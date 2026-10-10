#!/bin/bash
# Acceptance suite for the NanoMQ-on-Zephyr broker demo.
#
# Drives host mosquitto clients against the broker's SLIRP-forwarded TCP
# port (host tcp:1883 -> guest 10.0.2.15:1883 by default).  Covers MQTT
# v3.1.1 QoS0/1/2 pub/sub, retained messages, will messages (abnormal
# disconnect) and MQTT v5 properties incl. the request/response helpers.
#
# Usage: ./accept.sh [host] [port]     (defaults: 127.0.0.1 1883)
# Requires: mosquitto-clients (mosquitto_sub / mosquitto_pub).
#
# Bring-up pitfalls encoded here (see README.md):
#   * mosquitto -k keepalive minimum is 5 — "-k 2" exits immediately.
#   * kill the client itself, not a `timeout` wrapper, or the will never
#     fires (the client keeps running and DISCONNECTs cleanly instead).

H=${1:-127.0.0.1}
P=${2:-1883}
T0=/tmp/accept_mqtt.$$
PASS=0; FAIL=0

note()  { echo "== $*"; }
ok()    { echo "   PASS: $*"; PASS=$((PASS+1)); }
bad()   { echo "   FAIL: $*"; FAIL=$((FAIL+1)); }

# wait_msg <file> <n>: wait until file has >= n lines (10s cap)
wait_msg() { local f=$1 n=$2 i; for i in $(seq 1 50); do
    [ "$(wc -l < "$f" 2>/dev/null)" -ge "$n" ] && return 0; sleep 0.2; done; return 1; }
wait_conn() { sleep 1.2; }   # slirp proxy + guest TCP handshake

cleanup() { jobs -p | while read -r j; do kill "$j" 2>/dev/null; done
            rm -f "$T0".*; }
trap cleanup EXIT

# ── QoS0 ────────────────────────────────────────────────────────
note "QoS0 pub/sub"
mosquitto_sub -h $H -p $P -t "z/q0" -q 0 -C 1 > "$T0.q0" 2>/dev/null &
wait_conn
mosquitto_pub -h $H -p $P -t "z/q0" -q 0 -m "hello-qos0"
wait_msg "$T0.q0" 1 && ok "QoS0 message delivered" || bad "QoS0 message lost"

# ── QoS1 ────────────────────────────────────────────────────────
note "QoS1 pub/sub"
mosquitto_sub -h $H -p $P -t "z/q1" -q 1 -C 1 > "$T0.q1" 2>/dev/null &
wait_conn
mosquitto_pub -h $H -p $P -t "z/q1" -q 1 -m "hello-qos1"
wait_msg "$T0.q1" 1 && ok "QoS1 message delivered" || bad "QoS1 message lost"

# ── QoS2 ────────────────────────────────────────────────────────
note "QoS2 pub/sub"
mosquitto_sub -h $H -p $P -t "z/q2" -q 2 -C 1 > "$T0.q2" 2>/dev/null &
wait_conn
mosquitto_pub -h $H -p $P -t "z/q2" -q 2 -m "hello-qos2"
wait_msg "$T0.q2" 1 && ok "QoS2 message delivered" || bad "QoS2 message lost"

# ── Retain ──────────────────────────────────────────────────────
note "Retain"
mosquitto_pub -h $H -p $P -t "z/ret" -q 1 -r -m "retained-payload"
sleep 0.5
mosquitto_sub -h $H -p $P -t "z/ret" -q 1 -C 1 --retained-only > "$T0.ret" 2>/dev/null &
if wait_msg "$T0.ret" 1; then ok "retained message received by late subscriber"
else bad "retained message not received"; fi

# ── Will ────────────────────────────────────────────────────────
note "Will (client SIGKILLed, keepalive 5)"
mosquitto_sub -h $H -p $P -t "z/will" -q 0 -C 1 > "$T0.will" 2>/dev/null &
wait_conn
# client that registers a will then dies abruptly (SIGKILL, no DISCONNECT)
mosquitto_sub -h $H -p $P -t "z/none" -q 0 -k 5 \
    --will-topic "z/will" --will-payload "client-died" --will-qos 0 \
    > "$T0.wc" 2>/dev/null &
WC=$!
sleep 2
kill -9 $WC 2>/dev/null
if wait_msg "$T0.will" 1; then ok "will published after abnormal disconnect"
else bad "will not published within ~10s"; fi

# ── MQTT v5 ─────────────────────────────────────────────────────
note "MQTT v5 pub/sub (properties)"
mosquitto_sub -h $H -p $P -V mqttv5 -t "z/v5" -q 1 -C 1 > "$T0.v5" 2>/dev/null &
wait_conn
mosquitto_pub -h $H -p $P -V mqttv5 -t "z/v5" -q 1 \
    -m "hello-v5" -D publish user-property k v
wait_msg "$T0.v5" 1 && ok "v5 message delivered" || bad "v5 message lost"

# ── v5 response-topic / correlation (request/response helper) ───
note "MQTT v5 response-topic + correlation-data roundtrip"
mosquitto_sub -h $H -p $P -V mqttv5 -t "z/v5resp" -q 1 -C 1 \
    > "$T0.v5r" 2>/dev/null &
wait_conn
timeout -s KILL 8 mosquitto_pub -h $H -p $P -V mqttv5 -t "z/v5resp" -q 1 -m "rpc-call" \
    -D publish response-topic "z/v5cb" -D publish correlation-data "abc123"
PRC=$?
wait_msg "$T0.v5r" 1 && ok "v5 response msg delivered (pub rc=$PRC)" \
                       || bad "v5 response msg lost (pub rc=$PRC)"

echo
echo "RESULT: pass=$PASS fail=$FAIL"
[ $FAIL -eq 0 ]
