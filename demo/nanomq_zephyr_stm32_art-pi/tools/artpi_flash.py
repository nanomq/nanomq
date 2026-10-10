#!/usr/bin/env python3
"""Program the ART-Pi's QSPI flash over SWD.

The broker image is ~0.5 MB while the STM32H750's internal flash is 128 KB and
holds the ART-Pi factory bootloader, so the demo is linked into the QSPI
memory-mapped window at 0x90000000 (docs/adr/0001).  pyocd's built-in
stm32h750xx target knows neither that flash region nor the W25Q64 programming
algorithm, so this script adds both: it loads the vendor's CMSIS flash
algorithm (the same one STM32CubeProgrammer consumes as
ART-Pi_W25Q64.stldr) and attaches it to a region covering the QSPI window.

The FLM is resolved from, in order: --flm, $ART_PI_FLM, or
<this_dir>/ART-Pi_W25Q64.FLM.  It is deliberately not vendored in this
repository — the RT-Thread SDK it comes from has no licence file at its root;
see the README for how to obtain a copy.

Usage:
    artpi_flash.py [--elf PATH] [--flm PATH] [--probe UID] [--dry-run]

Implementation notes:
  * The target is reset before the algorithm runs.  The vendor loader
    reconfigures the clock tree, caches and the QUADSPI peripheral itself and
    assumes a freshly reset MCU; running it over a live application makes
    Init() time out (verified on hardware).
  * The algorithm's code, two page buffers and stack live in SRAM4
    (0x38000000, 64 KB), which nothing else in this demo uses.
  * pyocd erases only the sectors it programs (chip_erase="sector"), so the
    rest of the QSPI — e.g. the remainder of the factory firmware — is left
    untouched.
"""

import argparse
import os
import struct
import sys
from pathlib import Path

# ── pyocd 0.45 + this ST-Link firmware ──────────────────────────────
# While connecting, pyocd 0.45 sends JTAG_GET_BOARD_IDENTIFIERS (0x56) and
# expects a 128-byte payload.  The ST-Link V2.1 on the ART-Pi answers with a
# 2-byte status instead, which pyocd turns into a fatal
# "received incomplete command response from STLink (got 2, expected 128)" —
# no SWD access at all, even though the probe is healthy (GET_VERSION,
# GET_TARGET_VOLTAGE and every target command work).  The board ID only feeds
# the probe's human-readable board name, so neutralise the query.
from pyocd.probe.stlink_probe import StlinkProbe

StlinkProbe._get_board_id = lambda self: None

from pyocd.core.helpers import ConnectHelper
from pyocd.core.memory_map import FlashRegion, RamRegion
from pyocd.flash.flash import Flash
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.target.pack.flash_algo import PackFlashAlgo

TARGET = "stm32h750xx"

# SRAM4: 64 KB at the top of the SRAM banks, unused by the demo.
ALGO_RAM_START = 0x38000000
ALGO_RAM_SIZE = 0x10000

PT_LOAD = 1


def find_flm(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("ART_PI_FLM")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent / "ART-Pi_W25Q64.FLM"


def elf_load_segments(path: Path):
    """Return [(paddr, filesz)] for the ELF's PT_LOAD program headers.

    Small enough to do by hand and avoids depending on pyocd internals.
    """
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1:  # 32-bit little-endian only
        raise SystemExit("%s: not a 32-bit little-endian ELF" % path)
    e_phoff, = struct.unpack_from("<I", data, 28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _, _, p_paddr, p_filesz = struct.unpack_from("<IIIII", data, off)
        if p_type == PT_LOAD and p_filesz:
            segments.append((p_paddr, p_filesz))
    return segments


def main() -> int:
    demo_dir = Path(__file__).resolve().parent.parent
    default_elf = demo_dir.parent.parent / "build" / "nanomq_zephyr_stm32_art-pi" / "zephyr" / "zephyr.elf"

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--elf", default=str(default_elf),
                    help="broker ELF (default: %(default)s)")
    ap.add_argument("--flm", help="vendor CMSIS flash algorithm for the W25Q64")
    ap.add_argument("--probe", help="pyocd probe unique id (default: pick the only one)")
    ap.add_argument("--dry-run", action="store_true",
                    help="load the algorithm and report the plan without writing")
    args = ap.parse_args()

    flm = find_flm(args.flm)
    if not flm.is_file():
        print(
            "flash algorithm not found: %s\n"
            "\n"
            "Fetch it once from the ART-Pi SDK (debug/flm/ART-Pi_W25Q64.FLM):\n"
            "  git clone --depth 1 --filter=blob:none --no-checkout \\\n"
            "      https://github.com/RT-Thread-Studio/sdk-bsp-stm32h750-realthread-artpi /tmp/artpi_sdk\n"
            "  git -C /tmp/artpi_sdk show HEAD:debug/flm/ART-Pi_W25Q64.FLM > %s\n"
            "or point --flm / $ART_PI_FLM at an existing copy." % (flm, flm),
            file=sys.stderr)
        return 2

    elf = Path(args.elf)
    if not elf.is_file():
        print("ELF not found: %s\nBuild first:\n"
              "  west build -b art_pi -d %s %s -- -DEXTRA_CONF_FILE=%s"
              % (elf, demo_dir.parent.parent / "build" / "nanomq_zephyr_stm32_art-pi",
                 demo_dir, demo_dir / "local.conf"), file=sys.stderr)
        return 2

    # The vendor FLM describes the whole 8 MB W25Q64 (4 KB sectors); pyocd
    # turns it into an algo dict placed at the end of the RAM region we hand
    # it (code + two page buffers + stack, ~28 KB).
    pack_algo = PackFlashAlgo(str(flm))
    info = pack_algo.flash_info
    algo_ram = RamRegion(start=ALGO_RAM_START, length=ALGO_RAM_SIZE, name="artpi_algo_ram")
    algo = pack_algo.get_pyocd_flash_algo(pack_algo.page_size, algo_ram)

    session = ConnectHelper.session_with_chosen_probe(
        unique_id=args.probe, target_override=TARGET,
        options={"auto_unlock": False, "reset_type": "hw"})
    if session is None:
        print("no debug probe found (is the ST-Link connected, and are the "
              "udev rules in place? see README)", file=sys.stderr)
        return 2

    with session:
        target = session.target
        region = FlashRegion(start=info.start, length=info.size,
                             blocksize=info.page_size, name="artpi_qspi",
                             is_default=False)
        region.algo = algo
        # 0x90000000 is only readable while the QUADSPI is in memory-mapped
        # mode, which the vendor algorithm takes over (indirect mode) as soon
        # as it runs.  Reading the region therefore faults ("Memory transfer
        # fault @ 0x90000000") unless pyocd is told not to: this flag forces
        # smart-flash, keep-unwritten and fast-verify off, so no read is
        # attempted and every affected sector is simply erased and rewritten.
        region.are_erased_sectors_readable = False
        target.memory_map.add_region(region)
        # The target's init sequence creates Flash instances for the flash
        # regions known at boot; a region added afterwards has to be bound by
        # hand, or FlashLoader refuses it with "has no flash instance".
        target.create_flash()

        segments = [(addr, size) for addr, size in elf_load_segments(elf)]
        out_of_range = [(a, s) for a, s in segments
                        if a < region.start or a + s > region.end]
        if out_of_range:
            print("ELF segments outside the QSPI region %#x-%#x: %s"
                  % (region.start, region.end,
                     ", ".join("%#x+%#x" % s for s in out_of_range)),
                  file=sys.stderr)
            return 1

        print("flash:  %s  %#x-%#x (%d MB, %d B sectors) via %s"
              % (region.name, region.start, region.start + region.length - 1,
                 region.length >> 20, region.page_size, flm.name))
        print("image:  %s  %d KB in %d segments"
              % (elf.name, sum(s for _, s in segments) >> 10, len(segments)))
        for addr, size in segments:
            print("          %#010x + %#08x" % (addr, size))

        if args.dry_run:
            # Still exercise the algorithm (load it into RAM, reset the MCU,
            # run Init/UnInit) so a dry run catches a broken FLM or RAM
            # choice without touching the flash contents.
            print("dry run: initialising the flash algorithm, not writing")
            flash = Flash(target, algo)
            flash.region = region
            flash.init(flash.Operation.ERASE, address=region.start, reset=True)
            flash.uninit()
            flash.cleanup()
            print("dry run: flash algorithm ran OK (no erase, no program)")
            return 0

        # The vendor algorithm brings the clock tree, caches and the QUADSPI
        # up from scratch and its Init() times out when it inherits a running
        # application's configuration, so hand it a freshly reset MCU.  pyocd
        # does not reset before the first FlashBuilder.init(); its own
        # post-program reset then starts the freshly written image.
        print("resetting target for a clean flash-algorithm bring-up")
        target.reset_and_halt()

        FileProgrammer(session, chip_erase="sector", trust_crc=False).program(
            str(elf), file_format="elf")

        # pyocd leaves the core halted once the programmer is done, so the
        # freshly written image would only start at the next power cycle: the
        # factory bootloader would run, jump to 0x90000000 and never be
        # reached again without an external reset.  Reset once more and let
        # it run, so the board is live by the time this script exits.
        target.reset_and_halt()
        target.resume()
        print("programmed; target reset and running")

    return 0


if __name__ == "__main__":
    sys.exit(main())
