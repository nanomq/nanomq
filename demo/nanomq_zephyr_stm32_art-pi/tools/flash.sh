#!/bin/bash
# Build and program the ART-Pi demo image into the board's QSPI flash.
#
# Usage: tools/flash.sh [VARIANT] [--no-build] [--dry-run] [--build-dir DIR]
#
# --no-build programs the last build instead of rebuilding; --dry-run loads the
# flash algorithm and reports the plan without writing anything (it still
# builds first unless --no-build is given as well).
#
# VARIANT selects the network layer (default: --wifi, the configuration this
# demo is verified with):
#   --wifi   Wi-Fi STA on the on-board AP6212  (wifi.conf + art_pi_wifi.overlay)
#   --eth    on-board Ethernet PHY             (eth.conf, no extra overlay)
#   --usb    USB-ECM device port               (usb.conf + art_pi_usb.overlay)
#
# Picking the wrong one is the easiest way to get a board that looks broken:
# the Ethernet and USB variants need a cable to their far end (and the
# bring-up board has none), so they sit at "eth: still no link" /
# "usb: no carrier" forever, while only --wifi reaches the LAN on its own.
#
# Requires the Zephyr venv to be active (it provides west and pyocd), e.g.
#   source ~/zephyr-venv/bin/activate
#   export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
#
# local.conf (git-ignored: REST credentials, Wi-Fi SSID/PSK) is included when
# it exists.  The image is written over SWD with tools/artpi_flash.py; see
# that file and the README for why the QSPI (not the internal flash) is the
# target.
#
# NOTE: the first flash overwrites the factory RT-Thread application in QSPI
# slot0.  It is rebuildable from the ART-Pi SDK (projects/art_pi_factory).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
demo=$(dirname "$here")
repo=$(cd "$demo/../.." && pwd)
build_dir=${BUILD_DIR:-$repo/build/nanomq_zephyr_stm32_art-pi}

dry_run=0
do_build=1
variant=wifi
while [ $# -gt 0 ]; do
    case "$1" in
        --wifi|--eth|--usb) variant=${1#--} ;;
        --dry-run)   dry_run=1 ;;
        --no-build)  do_build=0 ;;
        --build-dir) build_dir=$2; shift ;;
        -h|--help)   sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "flash.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

confs=""
overlay=""
case "$variant" in
    wifi) confs="$demo/wifi.conf";  overlay="$demo/boards/art_pi_wifi.overlay" ;;
    eth)  confs="$demo/eth.conf" ;;
    usb)  confs="$demo/usb.conf";   overlay="$demo/boards/art_pi_usb.overlay" ;;
esac

if [ "$do_build" = 1 ]; then
    extra_conf=""
    [ -f "$demo/local.conf" ] && extra_conf="$demo/local.conf"
    [ -n "$confs" ] && extra_conf="${extra_conf:+$extra_conf;}$confs"

    build_args=(west build -b art_pi -d "$build_dir" "$demo")
    build_args+=(--)
    if [ -n "$extra_conf" ]; then
        build_args+=(-DEXTRA_CONF_FILE="$extra_conf")
    fi
    if [ -n "$overlay" ]; then
        build_args+=(-DEXTRA_DTC_OVERLAY_FILE="$overlay")
    fi
    echo "+ variant: $variant"
    echo "+ ${build_args[*]}"
    "${build_args[@]}"
fi

flash_args=("--elf" "$build_dir/zephyr/zephyr.elf")
[ "$dry_run" = 1 ] && flash_args+=("--dry-run")

echo "+ python3 $here/artpi_flash.py ${flash_args[*]}"
exec python3 "$here/artpi_flash.py" "${flash_args[@]}"
