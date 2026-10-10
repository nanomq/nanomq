#!/usr/bin/env python3
"""Raw-socket MQTT acceptance client for the Zephyr broker demo.

Stdlib only (no paho in the container image).  Speaks MQTT 3.1.1 and 5.0
at the packet level, which is enough to drive the acceptance scenarios in
PORTING_ZEPHYR.md §9: pub/sub forwarding, webhook triggers, persistent
sessions / offline messages and keepalive expiry, $SYS client_status.

Usage:
  mqtt_accept.py <host> <port> connect   [--cid X] [--proto 4|5] [--clean 0|1]
                                          [--keepalive N] [--hold S]
  mqtt_accept.py <host> <port> sub       [--cid X] [--proto 4|5] [--clean 0|1]
                                          [--topic T]... [--qos N] [--hold S]
  mqtt_accept.py <host> <port> pub       [--cid X] [--proto 4|5]
                                          --topic T --msg M [--qos N] [--count N]
                                          [--interval MS] [--hold S]
  mqtt_accept.py <host> <port> expect    like sub, but exits 0 as soon as every
                                          --expect MSG pattern matched at least
                                          once (default hold 30s)

Output lines are machine friendly:
  CONNACK <session_present> <reason>
  SUBACK <pktid> <rc...>
  MSG <topic> qos<N> <payload>           (payload printed raw)
  PUBACK <pktid>
  EXIT <rc>
"""

import argparse
import socket
import struct
import sys
import time


class Mqtt:
    def __init__(self, host, port, cid, proto=4, clean=True, keepalive=0,
                 user=None, password=None, expiry=None):
        self.proto = proto
        self.keepalive = keepalive
        self.pktid = 1
        self.rcvq = b""
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(1.0)
        vh = bytearray()
        vh += b"\x00\x04MQTT"
        vh += bytes([proto])
        flags = 0x02 if clean else 0x00
        if user:
            flags |= 0x80
            pwlen = len(password or b"")
            flags |= 0x40 if pwlen else 0
        vh += bytes([flags]) + struct.pack("!H", keepalive)
        if proto == 5:
            # MQTT 5: CONNECT properties sit in the variable header,
            # BEFORE the client id in the payload.
            props = bytearray()
            if not clean and (expiry is not None or keepalive == 0):
                # Session-Expiry-Interval (0x11, 4 bytes).  MQTT 5: clean=0
                # with no expiry means expiry 0 (=discard on disconnect);
                # pass --expiry N to request a persistent session.
                se = 0 if expiry is None else expiry
                props += b"\x11" + struct.pack("!I", se)
            vh += bytes([len(props)]) + props
        cidb = cid.encode()
        vh += struct.pack("!H", len(cidb)) + cidb
        if user:
            ub = user.encode()
            vh += struct.pack("!H", len(ub)) + ub
            if password:
                pb = password.encode()
                vh += struct.pack("!H", len(pb)) + pb
        self._send(b"\x10", vh)

    # -- packet plumbing -------------------------------------------------
    def _send(self, type_byte, vh_or_body=b""):
        if isinstance(vh_or_body, bytearray):
            vh_or_body = bytes(vh_or_body)
        rem = len(vh_or_body)
        varint = bytearray()
        while True:
            d = rem % 128
            rem //= 128
            if rem:
                varint.append(d | 0x80)
            else:
                varint.append(d)
                break
        self.sock.sendall(type_byte + bytes(varint) + vh_or_body)

    def _recvn(self, n):
        while len(self.rcvq) < n:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                return b""
            self.rcvq += chunk
        out, self.rcvq = self.rcvq[:n], self.rcvq[n:]
        return out

    def recv_pkt(self, timeout=5.0):
        """Return (type, body) or None on timeout / b'' on close."""
        deadline = time.time() + timeout
        while True:
            hdr = self._recvn(1)
            if hdr is None:
                if time.time() < deadline:
                    continue
                return None
            if hdr == b"":
                return b""
            rem = 0
            mult = 1
            for _ in range(4):
                b = self._recvn(1)
                if b in (None, b""):
                    return None
                rem += (b[0] & 0x7F) * mult
                if not b[0] & 0x80:
                    break
                mult *= 128
            body = self._recvn(rem)
            while body is None:
                if time.time() >= deadline:
                    return None
                body = self._recvn(rem)
            return hdr[0], body

    # -- operations ------------------------------------------------------
    def wait_connack(self):
        while True:
            pkt = self.recv_pkt()
            if pkt in (None, b""):
                return None
            t, body = pkt
            if t == 0x20:
                sp = body[0] & 1 if len(body) > 1 else 0
                rc = body[1] if len(body) > 1 else 0xFF
                if self.proto == 5 and len(body) > 2:
                    # reason at 1, property length at 2
                    rc = body[1]
                return sp, rc
            # ignore anything else (e.g. retransmitted garbage)

    def subscribe(self, topics, qos=0):
        body = struct.pack("!H", self.pktid)
        if self.proto == 5:
            body += b"\x00"  # subscription properties
        for t in topics:
            tb = t.encode()
            body += struct.pack("!H", len(tb)) + tb + bytes([qos])
        self._send(b"\x82", body)
        pid = self.pktid
        self.pktid += 1
        while True:
            pkt = self.recv_pkt()
            if pkt in (None, b""):
                return None, []
            t, b = pkt
            if t == 0x90 and len(b) >= 3 and struct.unpack("!H", b[:2])[0] == pid:
                rc = b[3:] if self.proto == 5 else b[2:]
                return pid, list(rc)
        return pid, []

    def publish(self, topic, payload, qos=0, retain=False):
        body = bytearray()
        tb = topic.encode()
        body += struct.pack("!H", len(tb)) + tb
        need_ack = qos > 0
        pid = self.pktid
        if qos == 1:
            body += struct.pack("!H", pid)
            self.pktid += 1
        elif qos == 2:
            body += struct.pack("!H", pid)
            self.pktid += 1
        if self.proto == 5:
            # MQTT 5: PUBLISH variable header order is topic name, packet
            # id (when qos > 0), THEN properties — unlike SUBSCRIBE where
            # properties precede the payload.  A properties byte before
            # the packet id makes the broker parse pid == 0 and drop the
            # connection with reason 130 (Malformed Packet).
            body += b"\x00"
        body += payload
        t = 0x30 | (qos << 1) | (1 if retain else 0)
        self._send(bytes([t]), bytes(body))
        return pid if need_ack else None

    def wait_puback(self, pid):
        while True:
            pkt = self.recv_pkt()
            if pkt in (None, b""):
                return False
            t, b = pkt
            if t == 0x40 and len(b) >= 2 and struct.unpack("!H", b[:2])[0] == pid:
                return True

    def handle_pkt(self, pkt, expect):
        """Handle one packet: report PUBLISH/MSG or match --expect patterns."""
        if pkt in (None, b""):
            return
        t, body = pkt
        if t in (0x30, 0x32, 0x34):  # PUBLISH qos0/1/2
            pos = 0
            (tlen,) = struct.unpack("!H", body[pos:pos + 2])
            pos += 2
            topic = body[pos:pos + tlen].decode("utf-8", "replace")
            pos += tlen
            qos = (t >> 1) & 3
            if qos:
                pos += 2
            if self.proto == 5 and pos < len(body) and False:
                pass  # properties handled below
            # v5 property length right after topic
            if self.proto == 5:
                plen = body[pos]
                pos += 1 + plen
            payload = body[pos:]
            print("MSG %s qos%d %s" % (topic, qos, payload.decode("utf-8", "replace")),
                  flush=True)
            if qos == 1:
                pid = struct.unpack("!H", body[2 + tlen:4 + tlen])[0]
                self._send(b"\x40", struct.pack("!H", pid) if self.proto == 4
                           else struct.pack("!HBB", pid, 0, 0))  # +reason+props
        for e in expect:
            if e.encode("utf-8") in body:
                print("MATCH %s" % e, flush=True)

    def disconnect(self):
        try:
            if self.proto == 5:
                self._send(b"\xe0", b"\x00")  # normal, no properties
            else:
                self._send(b"\xe0")
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("verb", choices=["connect", "sub", "pub", "expect"])
    ap.add_argument("--cid", default=None)
    ap.add_argument("--proto", type=int, choices=[4, 5], default=4)
    ap.add_argument("--clean", type=int, default=1)
    ap.add_argument("--keepalive", type=int, default=0)
    ap.add_argument("--expiry", type=int, default=None)
    ap.add_argument("--topic", action="append", default=[])
    ap.add_argument("--qos", type=int, choices=[0, 1], default=0)
    ap.add_argument("--msg", default=None)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval", type=float, default=0.0)
    ap.add_argument("--hold", type=float, default=5.0)
    ap.add_argument("--expect", action="append", default=[])
    return ap


def main():
    args = build_parser().parse_args()
    cid = args.cid or {"connect": "acc-conn", "sub": "acc-sub",
                       "pub": "acc-pub", "expect": "acc-exp"}[args.verb]
    c = Mqtt(args.host, args.port, cid, proto=args.proto,
             clean=bool(args.clean), keepalive=args.keepalive,
             expiry=args.expiry)
    sp, rc = c.wait_connack()
    if sp is None:
        print("EXIT 1 connack-timeout", flush=True)
        sys.exit(1)
    print("CONNACK %d %d" % (sp, rc), flush=True)
    if rc != 0:
        print("EXIT 2 connack-rejected", flush=True)
        sys.exit(2)

    expect = list(args.expect)
    if args.verb == "sub":
        subbed = False
        end = time.time() + args.hold
        while time.time() < end:
            if not subbed:
                pid, rcs = c.subscribe(args.topic or ["test/#"], args.qos)
                if pid is None:
                    print("SUBACK timeout, resubscribing", flush=True)
                    time.sleep(1)
                    continue
                print("SUBACK %d %s" % (pid, " ".join(map(str, rcs))), flush=True)
                if any(r >= 0x80 for r in rcs):
                    print("EXIT 4 sub-rejected", flush=True)
                    sys.exit(4)
                subbed = True
            pkt = c.recv_pkt(timeout=min(1.0, end - time.time()))
            if pkt == b"":
                break
            c.handle_pkt(pkt, expect)
    elif args.verb == "expect":
        end = time.time() + args.hold
        matched = set()
        subbed = False
        while time.time() < end and len(matched) < len(expect):
            if not subbed:
                pid, rcs = c.subscribe(args.topic or ["test/#"], args.qos)
                if pid is None:
                    time.sleep(1)
                    continue
                print("SUBACK %d %s" % (pid, " ".join(map(str, rcs))), flush=True)
                subbed = True
            pkt = c.recv_pkt(timeout=min(1.0, end - time.time()))
            if pkt == b"":
                break
            c.handle_pkt(pkt, expect)
            for e in expect:
                if e in str(pkt[1] if pkt else b""):
                    matched.add(e)
        if len(matched) >= len(expect) and expect:
            print("EXIT 0", flush=True)
            sys.exit(0)
        print("EXIT 5 expect-miss matched=%s" % sorted(matched), flush=True)
        sys.exit(5)
    elif args.verb == "pub":
        topic = (args.topic or ["test/zephyr"])[0]
        for i in range(args.count):
            pid = c.publish(topic,
                            (args.msg or "payload-%d" % i).encode(),
                            qos=args.qos)
            if pid is not None and not c.wait_puback(pid):
                print("EXIT 6 puback-miss", flush=True)
                sys.exit(6)
            if args.interval:
                time.sleep(args.interval / 1000.0)
        if args.hold:
            time.sleep(args.hold)
    # connect: just hold the line until told otherwise
    if args.verb == "connect":
        time.sleep(args.hold)
    c.disconnect()
    c.close()
    print("EXIT 0", flush=True)


if __name__ == "__main__":
    main()
