#!/bin/bash
# Run the functional suite against an ART-Pi board on the LAN.
#
# Usage: tools/verify.sh <board-ip> [function_test.py args...]
#
# Default groups are the acceptance gates: mqtt_v311, mqtt_v5 and rest_get.
# Add the WebSocket and robustness groups with --full, or pass --group/--retry/
# --time-scale through to the suite.
#
# The REST API must be listening (local.conf sets CONFIG_BROKER_REST_USER/PASS
# and CONFIG_BROKER_REST_ALLOW_PUBLISHED), and the suite's default credentials
# are used unless --rest-user/--rest-pass are passed.
set -euo pipefail

if [ $# -lt 1 ]; then
    sed -n '2,10p' "$0"
    exit 2
fi

addr=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
suite=$repo/demo/nanomq_zephyr_qemu_x86/function_test.py

groups=(--group mqtt_v311 --group mqtt_v5 --group rest_get)
full=0
for arg in "$@"; do
    [ "$arg" = "--full" ] && full=1
done
if [ "$full" = 1 ]; then
    groups+=(--group capacity --group ws_abort --group ws_v311 --group ws_v5)
    # Drop --full before forwarding the rest to the suite.  A ${@/--full/}
    # substring substitution looks like it does that but leaves an empty
    # argument behind, which argparse rejects with
    # "unrecognized arguments: ".
    keep=()
    for arg in "$@"; do
        [ "$arg" = "--full" ] || keep+=("$arg")
    done
    if [ ${#keep[@]} -gt 0 ]; then
        set -- "${keep[@]}"
    else
        set --
    fi
fi

# --no-manage: the board is already running (the suite must not try to start
# a QEMU instance).  function_test.py's own local/remote heuristic sends any
# non-loopback address through --time-scale 4 --retry 2; the Wi-Fi-era
# threshold is bypassed for real hardware by that rule.
echo "+ python3 $suite --no-manage --addr $addr ${groups[*]} $*"
exec python3 "$suite" --no-manage --addr "$addr" "${groups[@]}" "$@"
