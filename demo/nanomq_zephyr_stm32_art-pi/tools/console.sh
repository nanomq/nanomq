#!/bin/bash
# Attach to the ART-Pi's console, or capture it to a file.
#
# The console is the ST-Link's virtual COM port at 115200 8N1 — no login, just
# the boot log and the broker's output.  After tools/flash.sh the board is
# already reset and running, so the boot log is on the wire right away.
#
# Usage:
#   tools/console.sh                      live view until Ctrl-C
#   tools/console.sh -o boot.log          capture to a file (and to the terminal)
#   tools/console.sh -o boot.log --drain 10
#                                        throw away 10 s of backlog first
#   tools/console.sh -d /dev/ttyACM1      different port
#
# Why --drain exists: the ST-Link VCP buffers, so a capture started right
# after a reset can begin with the *previous* boot (you will see two
# "Powered by RT-Thread." banners and a second "*** Booting Zephyr OS ... ***").
# Draining first — or simply splitting the log on the LAST banner — avoids
# mistaking that for a boot loop.
#
# Only one reader at a time: if the output looks truncated or interleaved,
# check that no other `cat`/`minicom`/`tio` still holds the port.
set -euo pipefail

dev=/dev/ttyACM0
out=
drain=0

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--device) dev=$2; shift 2 ;;
        -o|--output) out=$2; shift 2 ;;
        --drain)     drain=$2; shift 2 ;;
        -h|--help)   sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "console.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ ! -c "$dev" ]; then
    echo "console.sh: $dev is not a character device — is the board's ST-Link" \
         "plugged in, and is the udev rule in place? see the README" >&2
    exit 1
fi

if command -v fuser >/dev/null 2>&1 && fuser -s "$dev" 2>/dev/null; then
    echo "console.sh: warning: something else already has $dev open — two" \
         "readers split the output between them" >&2
fi

stty -F "$dev" 115200 raw -echo

if [ "$drain" -gt 0 ]; then
    echo "console.sh: discarding ${drain}s of buffered backlog" >&2
    timeout "$drain" cat "$dev" >/dev/null || true
fi

if [ -n "$out" ]; then
    echo "console.sh: capturing to $out (Ctrl-C to stop)" >&2
    : > "$out"
    cat "$dev" | tee "$out"
else
    echo "console.sh: $dev @115200 (Ctrl-C to stop)" >&2
    cat "$dev"
fi
