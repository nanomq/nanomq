import argparse
import itertools
import logging
import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional


def _setup_logger(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s.%(msecs)03d %(levelname)s [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _mqtt_encode_remaining_length(value: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value > 0:
            digit |= 0x80
        encoded.append(digit)
        if value == 0:
            break
    return bytes(encoded)


def _mqtt_enc_str(s: str) -> bytes:
    b = s.encode("utf-8", errors="strict")
    return struct.pack("!H", len(b)) + b


def _mqtt_connect_packet(client_id: str, keepalive: int, clean_session: bool) -> bytes:
    proto_name = _mqtt_enc_str("MQTT")
    proto_level = b"\x04"
    connect_flags = 0x02 if clean_session else 0x00
    payload = _mqtt_enc_str(client_id)
    variable_header = proto_name + proto_level + bytes([connect_flags]) + struct.pack("!H", keepalive)
    remaining_length = len(variable_header) + len(payload)
    fixed_header = b"\x10" + _mqtt_encode_remaining_length(remaining_length)
    return fixed_header + variable_header + payload


def _mqtt_subscribe_packet(packet_id: int, topics: Iterable[str], qos: int = 0) -> bytes:
    payload = bytearray()
    for t in topics:
        payload += _mqtt_enc_str(t)
        payload.append(qos & 0x03)
    variable_header = struct.pack("!H", packet_id & 0xFFFF)
    remaining_length = len(variable_header) + len(payload)
    fixed_header = bytes([0x82]) + _mqtt_encode_remaining_length(remaining_length)
    return fixed_header + variable_header + payload


def _mqtt_publish_packet(topic: str, payload: bytes) -> bytes:
    topic_encoded = _mqtt_enc_str(topic)
    variable_header = topic_encoded
    remaining_length = len(variable_header) + len(payload)
    fixed_header = bytes([0x30]) + _mqtt_encode_remaining_length(remaining_length)
    return fixed_header + variable_header + payload


def _set_linger_rst(s: socket.socket) -> None:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def _topic_filters_match_one_topic(topic: str, count: int) -> List[str]:
    parts = topic.split("/")
    combos = list(itertools.product([0, 1], repeat=len(parts)))
    filters: List[str] = []
    for mask in combos:
        flt_parts = [p if m == 0 else "+" for p, m in zip(parts, mask)]
        filters.append("/".join(flt_parts))
        if len(filters) >= count:
            break
    if not filters:
        filters.append(topic)
    return filters


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 1883
    client_id: str = "list34-final-session"
    topic: str = "hot/seg0/seg1/seg2/seg3/seg4/seg5/seg6/seg7/seg8"
    topic_count: int = 512
    publishers: int = 12
    churners: int = 8
    payload_size: int = 32768
    publish_burst: int = 128
    warmup_ms: int = 1500
    hold_ms: int = 40
    connect_burst: int = 8
    overlap_depth: int = 4
    overlap_close_delay_ms: int = 8
    close_mode: str = "shutdown"
    churn_close_mode: str = "rst"
    duration: int = 30
    log_level: str = "INFO"


class _StopFlag:
    def __init__(self) -> None:
        self._ev = threading.Event()

    def stop(self) -> None:
        self._ev.set()

    def is_set(self) -> bool:
        return self._ev.is_set()


def _connect_socket(cfg: Config, client_id: str, clean_session: bool) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect((cfg.host, cfg.port))
    s.sendall(_mqtt_connect_packet(client_id, keepalive=60, clean_session=clean_session))
    return s


def _close_socket(s: socket.socket, mode: str) -> None:
    try:
        if mode == "rst":
            _set_linger_rst(s)
            s.close()
            return
        if mode == "shutdown":
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
            return
        s.close()
    except OSError:
        pass


def _publisher_thread(cfg: Config, stop: _StopFlag, idx: int, stats: dict, log: logging.Logger) -> None:
    client_id = f"issue2246-pub-{idx}-{random.randint(0, 1_000_000)}"
    try:
        s = _connect_socket(cfg, client_id, clean_session=True)
    except OSError as e:
        log.warning("publisher connect failed: %s", e)
        return
    payload = os.urandom(cfg.payload_size)
    pkt = _mqtt_publish_packet(cfg.topic, payload)
    sent = 0
    try:
        while not stop.is_set():
            for _ in range(cfg.publish_burst):
                s.sendall(pkt)
                sent += 1
                stats["pub_sent"] = stats.get("pub_sent", 0) + 1
            time.sleep(0.001)
    except OSError as e:
        log.info("publisher stopped: %s (sent=%d)", e, sent)
    finally:
        _close_socket(s, "shutdown")


def _churn_thread(cfg: Config, stop: _StopFlag, idx: int, stats: dict, log: logging.Logger) -> None:
    live: List[socket.socket] = []
    opened = 0
    closed = 0
    while not stop.is_set():
        for _ in range(cfg.connect_burst):
            try:
                s = _connect_socket(cfg, cfg.client_id, clean_session=False)
                live.append(s)
                opened += 1
                stats["churn_open"] = stats.get("churn_open", 0) + 1
            except OSError as e:
                log.debug("churn connect failed: %s", e)
                break
            if len(live) > cfg.overlap_depth:
                old = live.pop(0)
                _close_socket(old, cfg.churn_close_mode)
                closed += 1
                stats["churn_close"] = stats.get("churn_close", 0) + 1
                time.sleep(cfg.overlap_close_delay_ms / 1000.0)
        time.sleep(0.001)
    for s in live:
        _close_socket(s, cfg.churn_close_mode)
    log.info("churner done (opened=%d closed=%d)", opened, closed)


def run(cfg: Optional[Config] = None) -> bool:
    cfg = cfg or Config()
    _setup_logger(cfg.log_level)
    log = logging.getLogger("issue2246")
    log.info(
        "start (host=%s port=%d client_id=%s publishers=%d churners=%d duration=%ds)",
        cfg.host,
        cfg.port,
        cfg.client_id,
        cfg.publishers,
        cfg.churners,
        cfg.duration,
    )
    filters = _topic_filters_match_one_topic(cfg.topic, cfg.topic_count)
    log.info("subscribe topic_count=%d example=%s", len(filters), filters[:3])
    try:
        target = _connect_socket(cfg, cfg.client_id, clean_session=False)
        target.sendall(_mqtt_subscribe_packet(packet_id=1, topics=filters, qos=0))
        log.info("target subscribed, warmup=%dms", cfg.warmup_ms)
    except OSError as e:
        log.error("target connect/subscribe failed: %s", e)
        return False
    stop = _StopFlag()
    stats: dict = {}
    pubs = [
        threading.Thread(
            target=_publisher_thread, name=f"pub-{i}", args=(cfg, stop, i, stats, log), daemon=True
        )
        for i in range(cfg.publishers)
    ]
    churners = [
        threading.Thread(
            target=_churn_thread, name=f"churn-{i}", args=(cfg, stop, i, stats, log), daemon=True
        )
        for i in range(cfg.churners)
    ]
    for t in pubs:
        t.start()
    time.sleep(cfg.warmup_ms / 1000.0)
    log.info("close original target (%s), hold=%dms", cfg.close_mode, cfg.hold_ms)
    _close_socket(target, cfg.close_mode)
    time.sleep(cfg.hold_ms / 1000.0)
    for t in churners:
        t.start()
    start = time.time()
    try:
        while time.time() - start < cfg.duration:
            time.sleep(1.0)
            log.info(
                "progress pub_sent=%d churn_open=%d churn_close=%d",
                stats.get("pub_sent", 0),
                stats.get("churn_open", 0),
                stats.get("churn_close", 0),
            )
    finally:
        stop.stop()
        time.sleep(0.2)
    log.info("done")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    ok = run(Config(host=args.host, port=args.port, duration=args.duration, log_level=args.log_level))
    raise SystemExit(0 if ok else 1)
