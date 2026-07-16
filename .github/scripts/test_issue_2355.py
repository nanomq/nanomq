#!/usr/bin/env python3
"""Regression test for nanomq/nanomq#2355 (shared-subscription part).

QoS-1 messages published while a shared-subscription ($share/<group>/<filter>)
persistent session (clean_start=false) is offline used to be dropped at the
transport offline-cache branch: the topic was matched against the raw stored
filter including the $share/<group>/ prefix, so it never matched and the
message was freed instead of stored. A resumed session got nothing, ever.

This test asserts storage + eventual redelivery only. Redelivery pace is the
existing resend timer (the broker under test runs with a short retry
interval), so completeness is asserted within a generous window; burst-speed
assertions belong to the separate resume-pacing change. A plain subscription
runs as a control: after the fix, shared members must behave identically to
plain subscribers on resume. An overlap case ($share QoS-0 filter subscribed
before a plain QoS-1 filter for the same topic) guards the strongest-match
QoS resolution in the offline-cache branch.

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
QOS_DURATION = 2           # short retry interval: redelivery is timer-paced
RECV_WINDOW = 30.0         # generous window for the timer to drain the backlog
MSG_COUNT = 3


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
        # redelivery pace is --qos_duration for both backends; the broker-
        # level sqlite block has no resend_interval key (bridge-only)
        conf += (
            "sqlite {\n"
            "    disk_cache_size = 102400\n"
            f'    mounted_file_path = "{workdir}/"\n'
            "    flush_mem_threshold = 1\n"
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


def start_broker(conf_path, workdir):
    log_path = os.path.join(workdir, "nanomq_2355.log")
    cmd = [
        find_nanomq(), "start",
        "--conf", conf_path,
        "--qos_duration", str(QOS_DURATION),
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


def subscribe_then_disconnect(client_id, subs):
    # subs: list of (filter, qos); subscribed sequentially so subinfol
    # keeps the given order
    client = make_client(client_id)
    subscribed = []

    def on_subscribe(cl, userdata, mid, reason_code_list, properties):
        # a SUBACK reason code >= 128 is a rejected subscription; fail
        # here with a clear message instead of a confusing 0/3 later
        subscribed.append(all(not rc.is_failure for rc in reason_code_list))

    client.on_subscribe = on_subscribe
    client.connect(HOST, PORT, keepalive=60, clean_start=False,
                   properties=session_properties())
    client.loop_start()
    for sub_filter, qos in subs:
        client.subscribe(sub_filter, qos=qos)
    deadline = time.time() + 5
    while len(subscribed) < len(subs) and time.time() < deadline:
        time.sleep(0.05)
    client.disconnect()
    client.loop_stop()
    if len(subscribed) < len(subs):
        print("issue_2355: SUBACK not received for %s" % (subs,))
        return False
    if not all(subscribed):
        print("issue_2355: subscription rejected for %s" % (subs,))
        return False
    return True


def publish_messages(topic, qos, count=MSG_COUNT, prefix="msg-"):
    pub = make_client("issue2355-pub")
    pub.connect(HOST, PORT, keepalive=60, clean_start=True)
    pub.loop_start()
    for i in range(count):
        info = pub.publish(topic, payload="%s%d" % (prefix, i), qos=qos)
        info.wait_for_publish(timeout=5)
        # wait_for_publish returns silently on timeout; fail loudly here
        # instead of as a confusing 0/N assertion later
        if qos > 0 and not info.is_published():
            pub.loop_stop()
            raise RuntimeError("publish of %s%d never acked" % (prefix, i))
    pub.disconnect()
    pub.loop_stop()


def reconnect_and_collect(client_id, window=RECV_WINDOW, expected=MSG_COUNT):
    received = {}
    connected = []

    def on_message(cl, userdata, m):
        payload = m.payload.decode()
        received[payload] = received.get(payload, 0) + 1

    def on_connect(cl, userdata, flags, rc, props=None):
        connected.append(flags.session_present)

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
    client.disconnect()
    client.loop_stop()
    session_present = connected[0] if connected else None
    return received, elapsed, session_present


def run_case(name, client_id, subs, pub_topic):
    print("issue_2355: case '%s' start" % name)
    if not subscribe_then_disconnect(client_id, subs):
        return False
    time.sleep(0.5)
    publish_messages(pub_topic, qos=1)
    received, elapsed, session_present = reconnect_and_collect(client_id)

    expected_payloads = ["msg-%d" % i for i in range(MSG_COUNT)]
    ok = True
    if sorted(received.keys()) != sorted(expected_payloads):
        print("issue_2355: case '%s' FAILED: got %d/%d distinct msgs: %s"
              % (name, len(received), MSG_COUNT, sorted(received.keys())))
        ok = False
    # timer-paced redelivery may legitimately re-send with DUP if an ack
    # races the next timer fire; duplicates are informational only
    dups = {k: v for k, v in received.items() if v > 1}
    if ok and dups:
        print("issue_2355: case '%s' note: duplicate deliveries: %s"
              % (name, dups))
    if ok and session_present is not True:
        print("issue_2355: case '%s' FAILED: session_present=%s"
              % (name, session_present))
        ok = False
    if ok:
        print("issue_2355: case '%s' ok (%d msgs in %.1fs, session_present=%s)"
              % (name, len(received), elapsed, session_present))
    return ok


def run_qos0_control(client_id, sub_filter, pub_topic):
    # QoS-0 messages must not be stored for offline sessions, shared or not
    print("issue_2355: case 'qos0-control' start")
    if not subscribe_then_disconnect(client_id, [(sub_filter, 1)]):
        return False
    time.sleep(0.5)
    publish_messages(pub_topic, qos=0)
    # a regression that stored QoS-0 would redeliver on the resend timer:
    # first fire is qos_duration * 1.5 = 3s after resume, so listen across
    # two timer periods to actually catch it
    received, _, _ = reconnect_and_collect(client_id, window=7.0, expected=1)
    if received:
        print("issue_2355: case 'qos0-control' FAILED: QoS0 offline msgs "
              "were delivered: %s" % sorted(received.keys()))
        return False
    print("issue_2355: case 'qos0-control' ok (0 msgs, as expected)")
    return True


def dump_broker_log(workdir):
    # test.py's print_nanomq_log() shows the main 1883 broker; on failure
    # the log that matters is this test's own instance on port 1899
    log_path = os.path.join(workdir, "nanomq_2355.log")
    try:
        with open(log_path) as f:
            print("issue_2355: broker log %s:" % log_path)
            print(f.read())
    except OSError as exc:
        print("issue_2355: cannot read broker log %s: %s" % (log_path, exc))


def run_backend(sqlite_enabled):
    label = "sqlite" if sqlite_enabled else "memory"
    workdir = tempfile.mkdtemp(prefix="nanomq2355-%s-" % label)
    conf = write_conf(workdir, sqlite_enabled)
    broker = None
    ok = False
    try:
        broker = start_broker(conf, workdir)
        plain_ok = run_case("%s/plain-control" % label,
                            "issue2355-%s-plain" % label,
                            [("t2355/plain/x", 1)], "t2355/plain/x")
        shared_ok = run_case("%s/shared" % label,
                             "issue2355-%s-shared" % label,
                             [("$share/g1/t2355/share/x", 1)],
                             "t2355/share/x")
        # an overlapping shared QoS-0 filter subscribed first must not
        # shadow the plain QoS-1 filter in the offline-cache match: the
        # strongest matching subscription decides the stored QoS
        overlap_ok = run_case("%s/overlap" % label,
                              "issue2355-%s-ov" % label,
                              [("$share/g1/t2355/ov/x", 0),
                               ("t2355/ov/x", 1)], "t2355/ov/x")
        qos0_ok = run_qos0_control("issue2355-%s-qos0" % label,
                                   "$share/g1/t2355/qos0/x", "t2355/qos0/x")
        # assigned only after all cases ran: an exception mid-run leaves
        # ok False so the finally block still dumps the broker log
        ok = plain_ok and shared_ok and overlap_ok and qos0_ok
    finally:
        if broker is not None:
            stop_broker(broker)
        if not ok:
            dump_broker_log(workdir)
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
