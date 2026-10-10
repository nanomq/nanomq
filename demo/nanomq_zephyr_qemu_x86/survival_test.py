#!/usr/bin/env python3
"""Scaled-down survival test for the Zephyr broker (guest side load).

Reuses the upstream CI load harness `.github/scripts/attack.py` — the same
session-takeover / shared-subscription churn / flood-publish pattern — with
its knobs shrunk to what a qemu_x86 guest on SLIRP can absorb.  The point
is not throughput: it is that a sustained adversarial session mix (cached
session with a large subscription list, $share fan-out, client-id flapping,
QoS1 flood) does not wedge or crash the broker, and that the broker still
answers a normal QoS1 round trip afterwards.

Why the scale is what it is (upstream defaults in parentheses):
`FLOOD_PUBS` 8 → 2, `NOISE_N` 200 → 8, `SHARE_GROUP_N` 48 → 2,
`DURATION_SEC` 120 → 30.  A DEBUG-logging guest pushes ~150-250 msg/s
through the serial console, and every flooded message is fanned out to the
seeded session's subscription list; the upstream numbers are a crash
amplifier on real hardware, not a survival floor.  `attack_test()` itself
never raises and its workers tolerate a dead broker, so the pass/fail gate
is the QoS1 echo probe that follows the load phase (plus the runner's
per-group CONNACK probe).

Standalone:

    python3 survival_test.py [addr] [port]

Exit status 0 on success, 1 on failure.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
CI_SCRIPTS = REPO_ROOT / ".github" / "scripts"

ECHO_TOPIC = "zf/survival/alive"

# Post-import overrides; attack.py reads these at call time.
SCALE = {
    "DURATION_SEC": 30,
    "FLOOD_PUBS": 2,
    "NOISE_N": 8,
    "SHARE_GROUP_N": 2,
    "CHURN_BATCH": 2,
    "CHURN_UNSUB_EACH": 2,
    "CHURN_SUB_EACH": 2,
    "FLAP_ONLINE_HOLD": 0.05,
    "FLAP_OFFLINE_GAP": 0.10,
}


def _load_attack():
    if str(CI_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(CI_SCRIPTS))
    import attack
    return attack


def scale_attack(attack, addr: str, port: int, duration: float | None = None):
    """Point attack.py at the guest broker and shrink its load."""
    attack.BROKER_HOST = addr
    attack.BROKER_PORT = port
    for key, value in SCALE.items():
        setattr(attack, key, value)
    if duration is not None:
        attack.DURATION_SEC = duration
    # These two are derived at import time from SHARE_GROUP_N / NOISE_N, so
    # shrinking the counts alone would leave the original lists in place.
    attack.SHARED_FILTERS = [
        "$share/g%d/%s" % (i, attack.ANCHOR_FILTER)
        for i in range(attack.SHARE_GROUP_N)
    ]
    attack.NOISE_FILTERS = [
        "%s/grp/999/dev/999/telemetry/nope%d/+" % (attack.TOPIC_ROOT, i)
        for i in range(attack.NOISE_N)
    ]


def _echo_probe(addr: str, port: int, connect_timeout: float = 10.0,
                echo_timeout: float = 30.0) -> bool:
    """A plain MQTT 3.1.1 QoS1 pub/sub round trip — the broker's pulse."""
    import paho.mqtt.client as mqtt
    from paho.mqtt.client import CallbackAPIVersion

    got = threading.Event()
    c = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION1,
                    client_id="zf-survival-probe",
                    protocol=mqtt.MQTTv311)
    c.on_message = lambda cl, u, msg: got.set()
    c.connect(addr, port, 30)
    c.loop_start()
    deadline = time.time() + connect_timeout
    while not c.is_connected() and time.time() < deadline:
        time.sleep(0.05)
    if not c.is_connected():
        c.loop_stop()
        return False
    c.subscribe(ECHO_TOPIC, 1)
    time.sleep(0.5)
    c.publish(ECHO_TOPIC, "alive", 1)
    ok = got.wait(echo_timeout)
    c.loop_stop()
    c.disconnect()
    return ok


def survival_test(addr: str, port: int = 1883,
                  duration: float | None = None) -> None:
    """Run the scaled attack load, then require a healthy QoS1 echo."""
    attack = _load_attack()
    scale_attack(attack, addr, port, duration)
    print("[survival] load phase: %ss, %d publisher(s), %d shared group(s)"
          % (attack.DURATION_SEC, attack.FLOOD_PUBS, attack.SHARE_GROUP_N),
          flush=True)
    attack.attack_test()
    print("[survival] load phase done — probing QoS1 echo", flush=True)
    if not _echo_probe(addr, port):
        raise AssertionError(
            "broker did not answer a QoS1 echo after the load phase")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    mqtt_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1883
    try:
        survival_test(host, mqtt_port)
    except Exception as e:                            # noqa: BLE001
        print("survival_test FAIL: %s: %s" % (type(e).__name__, e))
        sys.exit(1)
    print("survival_test PASS")
    sys.exit(0)
