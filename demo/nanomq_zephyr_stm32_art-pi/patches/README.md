# Out-of-tree patches for the ART-Pi demo

The demo builds against stock Zephyr 4.4 plus three deltas that live outside
this repository — in the Zephyr tree itself and in one west module.  They are
kept here as patches because they cannot travel on this repository's branches.

Everything *inside* this repository travels on branches instead (see the end
of this file).

## Base revisions

| Patch | Repository | Base |
| --- | --- | --- |
| 0001, 0002 | the Zephyr tree (west manifest `zephyr`) | `11a87708d415` (`v4.4.0-4779-g11a87708d415`) |
| 0003 | west module `hal_infineon` (`modules/hal/infineon`) | `d9e6846` |

Both were verified to apply to a tree at those revisions, and to match the
working tree that passed the functional suite (`git apply --check --reverse`).

## Apply

```sh
ZEPHYR_WORKSPACE=~/Projects/EMQ/ZephyrProject      # your west workspace
PATCHES=$PWD/demo/nanomq_zephyr_stm32_art-pi/patches

git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0001-zephyr-sdhc-stm32-sdio-card-interrupt.patch
git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0002-zephyr-airoc-whd-sdio-bring-up.patch
git -C $ZEPHYR_WORKSPACE/modules/hal/infineon apply $PATCHES/0003-infineon-whd-43438-art-pi-resources.patch
```

Then fetch the Infineon blobs once (the 43438 firmware image is not in git):

```sh
west blobs fetch hal_infineon
```

## What each patch contains

### 0001 — `zephyr/drivers/sdhc/sdhc_stm32.c`

SDIO card-interrupt support for the STM32 SDMMC host, which the driver was
missing entirely (`sdhc_driver_api.enable_interrupt` / `disable_interrupt`
were unimplemented here; the imx, ambiq, infineon and numaker hosts have
them).  It stores the callback, unmasks `SDMMC_MASK.SDIOITIE`, and handles
`SDMMC_FLAG_SDIOIT` in the ISR (write-1-to-clear via `SDMMC_ICR_SDIOITC`)
before the data-path early-out that would otherwise swallow it.

On this board the interrupt is *armed* by this code but never *asserted* by
the chip; the porting record (`docs/*/port-to-art-pi.md`, "no in-band SDIO
card interrupt") has the measurements.

### 0002 — Zephyr tree, AIROC/WHD

* `drivers/wifi/infineon/airoc_whd_hal_sdio.c` — the WHD thread poke timer,
  the workaround for the never-asserted card interrupt, behind
  `CONFIG_AIROC_WIFI_WHD_POKE` (the demo's `wifi.conf` enables it).  Without
  it WHD's worker thread is never woken and every ioctl times out.  Also
  keeps the chip out of its KSO sleep (`CONFIG_AIROC_WIFI_DISABLE_POWERSAVE`):
  a sleeping device deliberately does not answer the write that wakes it,
  which a host controller reports as a command-response timeout — measured at
  ~300 a second, and the reason the console used to flood (ADR 0004).
* `modules/hal_infineon/whd-expansion/CMakeLists.txt` — wire CLM and NVRAM
  for the CYW43438 the way the 4343W/43439 entries already are (upstream
  publishes only firmware for this part), and add two options used while
  chasing the interrupt:
  * `CONFIG_AIROC_WIFI_NO_CLM` (build WHD without a CLM resource),
  * `CONFIG_AIROC_WIFI_WHD_DEBUG` (`WPRINT_ENABLE_WHD_DEBUG`, which also
    compiles in `whd_bus_sdio_verify_resource()` — the post-download readback
    of the firmware/CLM transfer).
  Both are app-level Kconfig symbols, defined in the demo's `Kconfig`.
`CONFIG_AIROC_WIFI_WHD_POKE` is defined there too, for the same reason.

### 0003 — west module `hal_infineon`

* The CYW43438 NVRAM now holds the ART-Pi module's own parameters, taken from
  the vendor's `wifi_nvram_image[]` (`libraries/drivers/drv_wlan.c` in the
  ART-Pi SDK): `prodid=boardtype=0x0726`, `boardrev=0x1101`, `xtalfreq=26000`.
  The AW-CU427-P data the manifest ships for this part makes the firmware
  abort its init.

The firmware blob itself is *not* part of any patch: fetching it is what
`west blobs fetch hal_infineon` is for.  The demo uses it unchanged.

## In-repo changes (branch `alvin/art-pi`)

* the demo directory itself (`demo/nanomq_zephyr_stm32_art-pi/`),
* `demo/nanomq_zephyr_qemu_x86/function_test.py` — the non-localhost heuristic
  (non-loopback address ⇒ `--time-scale 4 --retry 2`), so the suite is usable
  against a board on the LAN,
* the `nng` submodule's `SUCCESS` → `NNG_MQTT_SUCCESS` rename (CMSIS
  `ErrorStatus.SUCCESS` collides with nng's enum on STM32); that lives on the
  nng branch `alvin/art-pi`, which is based on `alvin/zephyr-port`.

## Status

Generated from the working tree that passed the acceptance gates
(`mqtt_v311`, `mqtt_v5`, `rest_get` — `RESULT: pass=3 fail=0`), after the
bring-up instrumentation was removed and the poke timer became a Kconfig
option.  No `nanomq-probe` diagnostics remain in the tree or in these
patches.
