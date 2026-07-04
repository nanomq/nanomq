#!/usr/bin/env python3
"""Regression test for nanomq/nanomq#2355.

Offline QoS-1 messages published to a persistent session (clean_start=false)
must be redelivered promptly on reconnect:
  1. shared subscriptions ($share/<group>/<filter>) used to get 0 messages
     (dropped at the transport cache branch instead of stored);
  2. plain subscriptions used to drain one message per retry_interval.

The broker under test runs with --qos_duration 60, so the resend timer
cannot deliver anything within the assertion window (first timer fire is at
1.5 x 60 s): every message that arrives within seconds of reconnect proves
the resume-time drain, not the timer.

Runs its own broker instances on a dedicated port; safe to call from
test.py while the shared broker owns 1883.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

HOST = "127.0.0.1"
PORT = 1899
QOS_DURATION = 60          # far above the per-case assertion window
RECV_WINDOW = 15.0         # seconds to collect the drained backlog
MSG_COUNT = 5


def find_nanomq():
    if os.environ.get("NANOMQ_BIN"):
        return os.environ["NANOMQ_BIN"]
    found = shutil.which("nanomq")
    if found:
        return found
    repo_root = Path(__file__).resolve().parents[2]
    local = repo_root / "build" / "nanomq" / "nanomq"
    if local.exists():
        return str(local)
    raise FileNotFoundError("nanomq binary not found (PATH, NANOMQ_BIN, build/nanomq)")


def write_conf(workdir, sqlite_enabled):
    conf = f'listeners.tcp {{ bind = "0.0.0.0:{PORT}" }}\n'
    if sqlite_enabled:
        conf += (
            "sqlite {\n"
            "    disk_cache_size = 102400\n"
            f'    mounted_file_path = "{workdir}/"\n'
            "    flush_mem_threshold = 1\n"
            "    resend_interval = 5000\n"
            "}\n"
        )
    path = os.path.join(workdir, "nanomq_2355.conf")
    with open(path, "w") as f:
        f.write(conf)
    return path


def wait_for_port(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_port_free(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                time.sleep(0.2)
        except OSError:
            return True
    return False


def start_broker(conf_path, workdir, qos_duration=QOS_DURATION):
    log_path = os.path.join(workdir, "nanomq_2355.log")
    cmd = [
        find_nanomq(), "start",
        "--conf", conf_path,
        "--qos_duration", str(qos_duration),
        "--log_level", "warn",
        "--log_stdout", "false",
        "--log_file", log_path,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_port():
        stop_broker(proc)  # reap and free the port before raising
        raise RuntimeError("broker did not open port %d" % PORT)
    return proc


def stop_broker(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    wait_port_free()


def make_client(client_id):
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv5,
    )
    return client


def session_properties():
    props = Properties(PacketTypes.CONNECT)
    props.SessionExpiryInterval = 3600
    return props


def subscribe_then_disconnect(client_id, sub_filter, qos=1):
    client = make_client(client_id)
    subscribed = []

    def on_subscribe(cl, userdata, mid, reason_code_list, properties):
        # a SUBACK reason code >= 128 is a rejected subscription; fail
        # here with a clear message instead of a confusing 0/5 later
        subscribed.append(all(not rc.is_failure for rc in reason_code_list))

    client.on_subscribe = on_subscribe
    client.connect(HOST, PORT, keepalive=60, clean_start=False,
                   properties=session_properties())
    client.loop_start()
    client.subscribe(sub_filter, qos=qos)
    deadline = time.time() + 5
    while not subscribed and time.time() < deadline:
        time.sleep(0.05)
    client.loop_stop()
    client.disconnect()
    if not subscribed:
        print("issue_2355: SUBACK not received for %s" % sub_filter)
        return False
    if not subscribed[0]:
        print("issue_2355: subscription rejected for %s" % sub_filter)
        return False
    return True


def publish_messages(topic, qos, count=MSG_COUNT, prefix="msg-"):
    pub = make_client("issue2355-pub")
    pub.connect(HOST, PORT, keepalive=60, clean_start=True)
    pub.loop_start()
    for i in range(count):
        info = pub.publish(topic, payload="%s%d" % (prefix, i), qos=qos)
        info.wait_for_publish(timeout=5)
    pub.loop_stop()
    pub.disconnect()


def reconnect_and_collect(client_id, window=RECV_WINDOW, expected=MSG_COUNT,
                          resubscribe=None):
    received = {}
    order = []
    connected = []

    def on_message(cl, userdata, m):
        payload = m.payload.decode()
        if payload not in received:
            order.append(payload)
        received[payload] = received.get(payload, 0) + 1

    def on_connect(cl, userdata, flags, rc, props=None):
        connected.append(flags.session_present)
        # MQTT spec: session_present=false means the server holds no
        # session state (e.g., subscriptions are not persisted across a
        # broker restart) and the client must subscribe again
        if resubscribe and not flags.session_present:
            cl.subscribe(resubscribe, qos=1)

    client = make_client(client_id)
    client.on_message = on_message
    client.on_connect = on_connect
    start = time.time()
    client.connect(HOST, PORT, keepalive=60, clean_start=False,
                   properties=session_properties())
    client.loop_start()
    deadline = time.time() + window
    while time.time() < deadline and len(received) < expected:
        time.sleep(0.1)
    elapsed = time.time() - start
    # small grace period to catch unexpected extra deliveries
    time.sleep(1.0)
    client.loop_stop()
    client.disconnect()
    session_present = connected[0] if connected else None
    return received, order, elapsed, session_present


def run_case(name, client_id, sub_filter, pub_topic, expect_present=True,
             strict_order=False):
    print("issue_2355: case '%s' start" % name)
    if not subscribe_then_disconnect(client_id, sub_filter):
        return False
    time.sleep(0.5)
    publish_messages(pub_topic, qos=1)
    received, order, elapsed, session_present = reconnect_and_collect(client_id)

    expected_payloads = ["msg-%d" % i for i in range(MSG_COUNT)]
    ok = True
    if sorted(received.keys()) != sorted(expected_payloads):
        print("issue_2355: case '%s' FAILED: got %d/%d distinct msgs: %s"
              % (name, len(received), MSG_COUNT, sorted(received.keys())))
        ok = False
    dups = {k: v for k, v in received.items() if v > 1}
    if ok and dups:
        print("issue_2355: case '%s' FAILED: duplicate deliveries: %s"
              % (name, dups))
        ok = False
    if ok and elapsed > RECV_WINDOW:
        print("issue_2355: case '%s' FAILED: backlog took %.1fs (timer-paced?)"
              % (name, elapsed))
        ok = False
    if ok and order != expected_payloads:
        # FIFO is guaranteed for the SQLite backend (ORDER BY main.id);
        # the in-memory backend drains in packet-id order, so ordering
        # is informational there
        if strict_order:
            print("issue_2355: case '%s' FAILED: arrival order %s != %s"
                  % (name, order, expected_payloads))
            ok = False
        else:
            print("issue_2355: case '%s' note: arrival order %s"
                  % (name, order))
    if ok and expect_present and session_present is not True:
        print("issue_2355: case '%s' FAILED: session_present=%s"
              % (name, session_present))
        ok = False
    if ok:
        print("issue_2355: case '%s' ok (%d msgs in %.1fs, session_present=%s)"
              % (name, len(received), elapsed, session_present))
    return ok


def run_live_during_drain(client_id, sub_filter, pub_topic, live_count=2):
    """Publish live traffic while the backlog drain is stalled mid-flight.

    Uses manual acking to hold the first drained message unacked (the
    ACK-clocked drain cannot proceed), interleaves live publishes, then
    releases the acks. Every payload - backlog and live - must arrive
    exactly once: live in-flight rows must not be re-sent by the drain.
    """
    print("issue_2355: case 'live-during-drain' start")
    if not subscribe_then_disconnect(client_id, sub_filter):
        return False
    time.sleep(0.5)
    publish_messages(pub_topic, qos=1)

    received = {}
    to_ack = []
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv5,
        manual_ack=True,
    )

    def on_message(cl, userdata, m):
        payload = m.payload.decode()
        received[payload] = received.get(payload, 0) + 1
        to_ack.append(m)

    client.on_message = on_message
    client.connect(HOST, PORT, keepalive=60, clean_start=False,
                   properties=session_properties())
    client.loop_start()

    ok = True
    # wait for the first drained backlog msg; it stays unacked, so the
    # drain is stalled while we interleave live publishes
    deadline = time.time() + 5
    while not to_ack and time.time() < deadline:
        time.sleep(0.05)
    if not to_ack:
        print("issue_2355: case 'live-during-drain' FAILED: no backlog "
              "msg arrived while holding acks")
        ok = False
    else:
        publish_messages(pub_topic, qos=1, count=live_count,
                         prefix="live-")
        time.sleep(1.0)  # live msgs are delivered independently
        # release acks (including for msgs that keep arriving) until the
        # whole backlog + live set is in or the window closes
        expected = MSG_COUNT + live_count
        deadline = time.time() + RECV_WINDOW
        while time.time() < deadline:
            while to_ack:
                m = to_ack.pop(0)
                client.ack(m.mid, m.qos)
            if len(received) >= expected and not to_ack:
                break
            time.sleep(0.1)
        time.sleep(1.0)
        while to_ack:
            m = to_ack.pop(0)
            client.ack(m.mid, m.qos)

    client.loop_stop()
    client.disconnect()

    if ok:
        expected_payloads = sorted(
            ["msg-%d" % i for i in range(MSG_COUNT)]
            + ["live-%d" % i for i in range(live_count)])
        if sorted(received.keys()) != expected_payloads:
            print("issue_2355: case 'live-during-drain' FAILED: got %s "
                  "expected %s" % (sorted(received.keys()), expected_payloads))
            ok = False
        dups = {k: v for k, v in received.items() if v > 1}
        if ok and dups:
            print("issue_2355: case 'live-during-drain' FAILED: duplicate "
                  "deliveries: %s" % dups)
            ok = False
    if ok:
        print("issue_2355: case 'live-during-drain' ok (%d msgs, all "
              "exactly once)" % len(received))
    return ok


def run_qos0_control(client_id, sub_filter, pub_topic):
    print("issue_2355: case 'qos0-control' start")
    if not subscribe_then_disconnect(client_id, sub_filter):
        return False
    time.sleep(0.5)
    publish_messages(pub_topic, qos=0)
    received, _, _, _ = reconnect_and_collect(client_id, window=3.0, expected=1)
    if received:
        print("issue_2355: case 'qos0-control' FAILED: QoS0 offline msgs "
              "were delivered: %s" % sorted(received.keys()))
        return False
    print("issue_2355: case 'qos0-control' ok (0 msgs, as expected)")
    return True


def run_backend(sqlite_enabled):
    label = "sqlite" if sqlite_enabled else "memory"
    workdir = tempfile.mkdtemp(prefix="nanomq2355-%s-" % label)
    conf = write_conf(workdir, sqlite_enabled)
    broker = None
    ok = True
    try:
        broker = start_broker(conf, workdir)
        ok &= run_case("%s/plain" % label, "issue2355-%s-plain" % label,
                       "t2355/plain/x", "t2355/plain/x",
                       strict_order=sqlite_enabled)
        ok &= run_case("%s/shared" % label, "issue2355-%s-shared" % label,
                       "$share/g1/t2355/share/x", "t2355/share/x",
                       strict_order=sqlite_enabled)
        ok &= run_qos0_control("issue2355-%s-qos0" % label,
                               "t2355/qos0/x", "t2355/qos0/x")
        if sqlite_enabled:
            ok &= run_live_during_drain("issue2355-sqlite-livedrain",
                                        "t2355/live/x", "t2355/live/x")

        if sqlite_enabled and ok:
            # backlog must survive a broker restart (persisted in SQLite).
            # Across a restart the fast resume-drain does not apply (msg
            # timestamps are not comparable between processes); redelivery
            # runs on the resend timer, so the restarted broker uses a
            # short retry interval and the assertion is on completeness,
            # not burst timing.
            print("issue_2355: case 'sqlite/restart' start")
            cid = "issue2355-sqlite-restart"
            if not subscribe_then_disconnect(cid, "t2355/restart/x"):
                ok = False
            else:
                time.sleep(0.5)
                publish_messages("t2355/restart/x", qos=1)
                time.sleep(1.0)  # let rows land before terminating
                stop_broker(broker)
                broker = start_broker(conf, workdir, qos_duration=2)
                # subscriptions are in-memory only: the restarted broker
                # reports session_present=false and the client must
                # re-subscribe for the persisted backlog to be deliverable
                received, _, elapsed, _ = reconnect_and_collect(
                    cid, window=30.0, resubscribe="t2355/restart/x")
                if len(received) != MSG_COUNT:
                    print("issue_2355: case 'sqlite/restart' FAILED: "
                          "%d/%d msgs after restart: %s"
                          % (len(received), MSG_COUNT, sorted(received.keys())))
                    ok = False
                else:
                    print("issue_2355: case 'sqlite/restart' ok "
                          "(%d msgs in %.1fs, timer-paced)"
                          % (len(received), elapsed))
    finally:
        if broker is not None:
            stop_broker(broker)
        shutil.rmtree(workdir, ignore_errors=True)
    return ok


def issue_2355_test():
    ok = True
    for sqlite_enabled in (True, False):
        # return False instead of raising: test.py's harness expects the
        # return-False convention and has no try/except around test calls
        try:
            if not run_backend(sqlite_enabled):
                ok = False
        except Exception as exc:
            print("issue_2355: backend run crashed: %s" % exc)
            ok = False
    if ok:
        print("issue_2355: all cases passed")
    else:
        print("issue_2355: FAILED")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if issue_2355_test() else 1)
