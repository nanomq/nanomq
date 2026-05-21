#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

NANOMQ="${NANOMQ:-$REPO/build/nanomq/nanomq}"
CLI="${CLI:-$REPO/build/nanomq_cli/nanomq_cli}"
SO_PATH="${SO_PATH:-$SCRIPT_DIR/my_stream_plugin.so}"

IN_TOPIC="${IN_TOPIC:-canudp}"
OUT_TOPIC="${OUT_TOPIC:-metrics/example}"
METRICS_FILE="${METRICS_FILE:-/tmp/stream_plugin_metrics.jsonl}"
BATCH_FILE="${BATCH_FILE:-/tmp/stream_plugin.jsonl}"
PORT="${PORT:-$((18000 + RANDOM % 1000))}"

WORKDIR="${WORKDIR:-/tmp/nmq-self-verify-$$}"
CONF="$WORKDIR/nmq-sp.conf"
BROKER_LOG="$WORKDIR/nanomq.log"
SUB_OUT="$WORKDIR/sub.out"

BROKER_PID=""
SUB_PID=""

cleanup() {
	if [[ -n "${SUB_PID}" ]] && kill -0 "$SUB_PID" >/dev/null 2>&1; then
		kill "$SUB_PID" >/dev/null 2>&1 || true
	fi
	if [[ -n "${BROKER_PID}" ]] && kill -0 "$BROKER_PID" >/dev/null 2>&1; then
		kill "$BROKER_PID" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

require_file() {
	local path="$1"
	if [[ ! -f "$path" ]]; then
		echo "[FAIL] missing file: $path" >&2
		exit 1
	fi
}

require_exec() {
	local path="$1"
	if [[ ! -x "$path" ]]; then
		echo "[FAIL] missing executable: $path" >&2
		exit 1
	fi
}

mkdir -p "$WORKDIR"
rm -f "$METRICS_FILE" "$BATCH_FILE"

require_exec "$NANOMQ"
require_exec "$CLI"
require_file "$SO_PATH"

cat > "$CONF" <<EOF
listeners.tcp {
    bind = "0.0.0.0:$PORT"
}

log {
    to = [console]
    level = info
}

stream_plugin {
    sp0 {
        path  = "$SO_PATH"
        topic = "$IN_TOPIC"
        name  = "self-verify"
        mode  = "async"
        queue_cap = 10000
        full_op   = "drop"
    }
}

stream_inject {
    enable = true
    queue_cap = 4096
    worker_num = 1
    full_op = "drop"
}
EOF

echo "[INFO] starting NanoMQ on port $PORT ..."
"$NANOMQ" start --conf "$CONF" >"$BROKER_LOG" 2>&1 &
BROKER_PID=$!

sleep 2

echo "[INFO] waiting for output topic: $OUT_TOPIC"
timeout 12s "$CLI" sub -h 127.0.0.1 -p "$PORT" -t "$OUT_TOPIC" -V 4 >"$SUB_OUT" 2>&1 &
SUB_PID=$!
sleep 1

echo "[INFO] publishing input topic: $IN_TOPIC"
for v in 0 A B P 0 A; do
	"$CLI" pub -h 127.0.0.1 -p "$PORT" -t "$IN_TOPIC" -m "$v" -V 4 -i "self-$RANDOM" >/dev/null 2>&1 || true
	sleep 1
done

sleep 4
if kill -0 "$SUB_PID" >/dev/null 2>&1; then
	kill "$SUB_PID" >/dev/null 2>&1 || true
fi

echo "[INFO] checking results ..."
if ! grep -Eq "$OUT_TOPIC|count|avg" "$SUB_OUT"; then
	echo "[FAIL] no output-topic evidence found in subscriber output" >&2
	echo "----- sub output -----" >&2
	cat "$SUB_OUT" >&2
	exit 2
fi

if [[ ! -s "$BATCH_FILE" && ! -s "$METRICS_FILE" ]]; then
	echo "[FAIL] neither batch file nor metrics file has content" >&2
	echo "expected one of: $BATCH_FILE or $METRICS_FILE" >&2
	exit 3
fi

echo "[PASS] self verification passed"
echo "  - subscriber output: $SUB_OUT"
echo "  - broker log:        $BROKER_LOG"
if [[ -s "$BATCH_FILE" ]]; then
	echo "  - batch file:        $BATCH_FILE"
fi
if [[ -s "$METRICS_FILE" ]]; then
	echo "  - metrics file:      $METRICS_FILE"
fi
