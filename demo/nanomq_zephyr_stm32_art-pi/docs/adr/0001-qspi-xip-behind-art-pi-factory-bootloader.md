# Broker image runs from QSPI XIP behind the ART-Pi factory bootloader

The NanoMQ broker is ~0.6–0.9 MB of code (ESP32-S3 port: 830 KB text,
qemu_x86: 622 KB), while the ART-Pi's STM32H750XBH6 has only 128 KB of
internal flash — all of it occupied by the Ruiside/RT-Thread factory
bootloader. We therefore link the demo into the QSPI memory-mapped window at
0x90000000 (`chosen { zephyr,flash = &ext_memory; }`, 8 MB, 4 KB sectors) and
let the factory bootloader — which already maps the QUADSPI and jumps to the
vector table found at 0x90000000 — start it. Flashing is done over SWD with
pyocd driving the vendor CMSIS flash algorithm for the W25Q64
(`ART-Pi_W25Q64.FLM`), with a target reset before the algorithm runs because
the loader assumes fresh clocks, caches and peripherals.

## Considered Options

- **In-repo first-stage loader in internal flash** — reproducible and
  independent of the shipped firmware, but we would own the QSPI, MPU and
  vector-table hand-off. Kept as the fallback if the factory bootloader is
  ever erased.
- **MCUboot in internal flash, application in QSPI slot0** — the board
  devicetree already carves `boot_partition`/`slot0`/`slot1` for it, but the
  module is not in this west workspace, MCUboot would have to map the QSPI
  before jumping anyway, and the demo has no OTA requirement.
- **STM32CubeProgrammer CLI + `ART-Pi_W25Q64.stldr`** — the path Zephyr's
  `boards/ruiside/art_pi/board.cmake` already wires up, but it requires
  installing ST's proprietary CLI. Documented fallback.

## Consequences

- The application must not re-initialise the QUADSPI: `CONFIG_FLASH` and
  `FLASH_STM32_QSPI` stay off, so no driver init can reconfigure the
  peripheral while the CPU is fetching from it.
- A plain `west build -b art_pi` links into the 128 KB internal flash and
  cannot hold the broker; the demo overlay that sets `zephyr,flash` to
  `&ext_memory` is mandatory.
- The factory RT-Thread application in QSPI slot0 is overwritten the first
  time the demo is flashed. It is rebuildable from `projects/art_pi_factory`
  in the ART-Pi SDK.
