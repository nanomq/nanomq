# Porting the Zephyr NanoMQ broker to the ART-Pi (STM32H750XBH6)

This is the record of adding `demo/nanomq_zephyr_stm32_art-pi` — the third
Zephyr broker demo, after qemu_x86 (simulation) and ESP32-S3 (Wi-Fi).  It
keeps the order in which the problems actually appeared, because the order is
the lesson: three separate faults look identical from the console
(`airoc_wifi_init_primary failed ret = -19`, no link, no DHCP).

Acceptance: buildable, **board-verified**, and at **functional parity** with
the other two demos — the suite's three hard gates pass against the board.

## 1. What differs from the ESP32-S3 sibling

| Dimension | ESP32-S3 | ART-Pi | Consequence |
| --- | --- | --- | --- |
| SoC | ESP32-S3 (xtensa) | STM32H750XBH6 (Cortex-M7) | 32-bit RISC-V-like atomics budget, `-mno-movbe` only for x86, CMSIS `SUCCESS` collision (see below) |
| Code storage | 16 MB flash (execute in place from the flash cache) | 128 KB internal flash, occupied by the factory bootloader | the image must be linked into the 8 MB **QSPI** window at 0x90000000 (ADR 0001) |
| Data plane | 16 MB octal PSRAM, 4 MB heap window | 32 MB FMC SDRAM, 4 MB `k_heap` (ADR 0002) | different allocator wiring, no PSRAM "shared multi heap" |
| Network | ESP32 Wi-Fi (ESP-IDF blob) | on-board **AP6212 = CYW43438**, SDIO on SDMMC2 | Infineon AIROC/WHD path, SDIO host glue on STM32 SDMMC |
| Display | LCD panel (unused) | LTDC would take SDRAM from the broker heap | `&ltdc` disabled in the overlay |
| Clock | Wi-Fi driver seeds SNTP | identical approach, optional (`CONFIG_BROKER_SNTP`) | none |

The application layer was not touched: `src/main.c` is the ESP32-S3 file with
the Wi-Fi bring-up kept as-is and an Ethernet path added beside it, and
`src/process_stub.c` is the same stand-in for nanomq's POSIX `process.c`.

## 2. Getting an image onto the board

The ART-Pi's internal flash holds the Ruiside/RT-Thread **factory bootloader**.
It maps the QUADSPI and jumps to the vector table at 0x90000000, so the demo
does not have to be a first-stage loader — it only has to *be there*:

```dts
/ { chosen { zephyr,flash = &ext_memory; }; };   /* 8 MB QSPI, 0x90000000 */
```

Two consequences worth stating explicitly:

* **The QSPI driver must stay off** (`CONFIG_FLASH` / `FLASH_STM32_QSPI`).
  Its init would reconfigure the peripheral the CPU is fetching instructions
  from.  This demo has no filesystem, so nothing is lost.
* A plain `west build -b art_pi` links into the 128 KB internal flash and
  cannot hold the broker — the overlay that sets `zephyr,flash` is mandatory.

The `Powered by RT-Thread.` logo on the console is **the bootloader's own
banner** (see `projects/art_pi_bootloader/applications/boot.c` in the ART-Pi
SDK, which prints it and then jumps).  Mistaking it for "the factory
application is still running, my image did not get flashed" cost real time
during the bring-up.

## 3. Tooling traps on the way to a running image

* **pyocd 0.45 + this ST-Link.**  While connecting, pyocd sends
  `JTAG_GET_BOARD_IDENTIFIERS` and expects 128 bytes; this probe answers with a
  2-byte status, which pyocd turns into a fatal
  `received incomplete command response from STLink (got 2, expected 128)` —
  no SWD access at all, although the probe itself is healthy.  The board ID
  only feeds a human-readable name, so `tools/artpi_flash.py` neutralises the
  query (`StlinkProbe._get_board_id = lambda self: None`) before importing the
  connect helper.
* **The vendor's CMSIS flash algorithm** (`ART-Pi_W25Q64.FLM`) is needed for
  the W25Q64 behind the QUADSPI; it is not redistributed here (see the
  README).  pyocd's own `stm32h750xx` target knows neither that region nor
  that algorithm.
* **Reset before, not around, the algorithm.**  The vendor loader brings up
  clocks, caches and the QUADSPI from scratch and *times out* when it inherits
  a running application's configuration.  Hence `reset_and_halt()` before
  programming.
* **Reading 0x90000000 over SWD faults while the QUADSPI is in indirect
  mode**, which is why the flash region is marked
  `are_erased_sectors_readable = False` and the tool always erases+rewrites
  whole sectors instead of read-verify.
* **Console backlog.**  The ST-Link's virtual COM port buffers; a capture
  started right after a reset can replay the previous boot first (two
  `Powered by RT-Thread.` banners in one log).  Split the log on the last
  bootloader banner before reading it, or discard the backlog first —
  `tools/console.sh --drain <s>`.  The commands for opening/capturing the
  console, and an annotated example of what a good boot prints, are in the
  README's "Console and boot log" section.
* **pyocd leaves the core halted** when the programmer finishes, so a board
  that was flashed and announced as "reset and running" looked dead: the
  bootloader banner appeared, then silence, and the image had in fact never
  started.  `tools/artpi_flash.py` now resets and resumes once more at the
  end.  The symptom to recognise is a console that stays silent *and* a board
  that never shows up on the LAN, with re-flashing changing nothing.
* **The default build has to be the one that works.**  `tools/flash.sh` builds
  the Wi-Fi variant unless told `--eth`/`--usb`; an earlier version built the
  plain `prj.conf` image, i.e. the Ethernet variant, which then sits at
  `eth: still no link` forever on a bench with no cable.  That mistake looks
  exactly like a dead board and cost one round of debugging.
* **A flooding console is a defect too.**  The STM32 SDHC driver logged one
  line per failed command, and once the chip stops answering (below) that is
  hundreds of failures a second — the console becomes a wall of
  `Command response timeout` and nothing else is readable.  Those messages are
  now rate-limited: one line per 5 s plus a `Skipped N messages` counter, so
  the console stays usable and the true volume is still visible.
* **The broker's startup log is printed once, and only if the broker starts.**
  nanolib announces it while `broker()` runs; anything attached to the console
  later sees only what the drivers are doing.  Two fixes came out of that: the
  Wi-Fi connect loop is now **bounded** (it used to retry forever, so a board
  that could not associate never started the broker and printed nothing about
  it — the "the board shows no broker log" report), and the demo prints a
  one-line status heartbeat every `CONFIG_BROKER_STATUS_INTERVAL_S` seconds
  (default 60) carrying the uptime, the listeners and the current IPv4
  address, so "is it up?" never depends on catching the boot.

## 4. Networking

### 4.1 Ethernet: the reset line was the red herring

The ART-Pi has an STM32 MAC + LAN8720A PHY, so the first attempt was the
simpler path (`eth.conf`).  It never came up: an SWD-driven MDIO scan of every
address 0–31 found nothing, `phy_mii: PHY (0) ID FFFF`, `HAL_ETH_Init failed`.
The obvious explanation was a PHY held in reset, so the overlay drove PA3 (the
vendor BSP's `ETH_RESET_PIN`) as `reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>`.
That did not help, which looked like a dead PHY — until the override was
removed again and the MAC initialised cleanly with no PHY error at all.  PA3
is evidently not this board's PHY reset, and driving it low is what kept the
PHY quiet; the override is gone from the overlay.

What is *not* proven is the part that needs hardware nobody has here: with no
Ethernet cable the interface stays dormant waiting for carrier, so link-up,
DHCP and traffic over Ethernet remain untested.  Wi-Fi is the verified path.

### 4.2 Wi-Fi: the SDIO side has to be built from scratch

Zephyr's ART-Pi devicetree says nothing about the Wi-Fi side of the AP6212, so
the overlay adds an SDIO host on SDMMC2 and the AIROC device node:

| Signal | Pin | Source |
| --- | --- | --- |
| SDMMC2 D0/D1/D2/D3 | PB14/PB15/PB3/PB4 (AF9) | vendor `projects/art_pi_wifi` CubeMX config |
| SDMMC2 CK/CMD | PD6/PD7 (AF11) | same |
| WL_REG_ON | PC13 | `libraries/drivers/drv_wlan.c`: `AP6212_WL_REG_ON` |

`WL_REG_ON` is worth calling out: an early guess based on the schematic text
(PI14) gave "no CMD5 response" at all, because the chip was never powered.
The vendor driver's own `GET_PIN(C, 13)` is the authority.  With PC13 driven
high, SDIO enumerates: CMD5, CCCR rev 2, CIS for functions 0/1/2, 4-bit bus,
25 MHz.

### 4.3 The trap that cost the most: no in-band SDIO card interrupt

Symptom: firmware download succeeded, the WLAN function became ready
(`SDIOD_CCCR_IORDY` reached `0x6`), the first ioctl was written to function 2
(768 + 36 bytes) — and then nothing.  No reply was ever read, every ioctl
timed out (`iovar "cap" -> 101580800`, 5 s each), and
`airoc_wifi_init_primary failed ret = -19`.

WHD's design makes this fatal: `whd_thread_func()` only enters its receive
path when `thread_info->bus_interrupt` is set (or when
`whd_bus_use_status_report_scheme()` is true), and for this transport that
function returns `WHD_FALSE`.  The flag is only set by the SDIO card interrupt
handler.  So no card interrupt = no received frame, forever.

The obvious suspects were ruled out with on-target instrumentation rather than
debugger reads (pyocd's halt/register access on this setup turned out to be
unreliable — it reports `LOCKUP` and returns garbage for registers while the
application is demonstrably running):

* `SDMMC_MASK.SDIOITIE` **is** set: `enable_interrupt -> MASK=0x00400000`.
* The SDMMC interrupt works: the ISR fires for data transfers.
* `SDMMC_STA.SDIOIT` is **never** set — not once in a whole boot, including
  while WHD sits in its 5 s ioctl timeout.  The chip simply never asserts
  DAT1.
* CCCR `INTEN` is programmed (`wr cccr[0x4] = 0x7`) and the WLAN function is
  ready, so the host side is fully armed.

Workaround (patch 0002, `CONFIG_AIROC_WIFI_WHD_POKE`): poke
`whd_thread_notify_irq()` from a 20 ms timer.  That hands the thread the
wake-up the interrupt would have delivered, its poll finds the queued reply,
and the init chain completes:

```
[4179] nanomq-probe: iovar "cap" -> 0            (was 101580800)
cmd53 rd func2 addr=0x0 size=39 -> 0             (the reply is read)
WLAN MAC Address : 70:4A:0E:51:77:9A
```

Every other way of getting a real interrupt was then tried and ruled out:

* **`DCTRL.SDIOEN`** (the STM32 SDMMC's "SD I/O enable", i.e. "treat DAT1 as
  the interrupt line").  With it set the host is undeniably armed
  (`MASK=0x00400000`, `DCTRL=0x00000800`, and the bit stays set through the
  transfers) yet `SDMMC_STA.SDIOIT` still never latched — and once traffic
  flows it makes 4-bit transfers fail with a `Command response timeout`
  flood, so it is deliberately not set.
* **A 1-bit bus**, where DAT1 is a dedicated interrupt line rather than a data
  line (`bus-width = <1>` plus WHD's `sdio_1bit_mode`).  Same result: no
  `SDIOIT`, no link.
* **Out-of-band host-wake.**  The vendor NVRAM sets `muxenab=0x11` (bit `0x10`
  = "HW OOB") and the schematic carries a `GPIO_WIFI_HOST_WAKE` net, so the
  chip may be signalling out-of-band instead.  Wired as
  `wifi-host-wake-gpios = <&gpioe 3 GPIO_ACTIVE_HIGH>` (PE3 being the only MCU
  pin the schematic text plausibly pairs with that net; the PI14/PI15 hits are
  the LCD's LTDC_CLK/LTDC_R0), it produced no wake-up either, and the CMD
  flood appeared once traffic flowed.  Left out, with the reasoning in the
  overlay.

Polling is also what this board's vendor stack does: the ART-Pi SDK's own Wi-Fi
host driver (`libraries/drivers/drv_sdio.c`) never enables
`SDMMC_MASK.SDIOITIE` and registers no card-interrupt callback, so its
WICED-based stack is fed by polling the chip's status registers.  The decision
and its consequences are recorded in
[ADR 0003](../../../../docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md).

Note for the next person: because the missing interrupt makes *every* ioctl
time out, it also produced two convincing but wrong earlier conclusions — that
the CLM blob "hangs the chip", and that the packed firmware blob from the
vendor's SPI flash is needed.  Both were symptoms, not causes.

### 4.4 NVRAM must be this module's

With the interrupt worked around, the firmware still aborted its init until
the NVRAM matched the module.  The ART-Pi's AP6212 is the
prodid/`boardtype=0x0726` variant; the AW-CU427-P NVRAM that the blob manifest
ships for the CYW43438 (`boardtype=0x0865`) does not work here.  The
authoritative text is the vendor's own `wifi_nvram_image[]` in
`libraries/drivers/drv_wlan.c` (`prodid=0x0726`, `boardrev=0x1101`,
`xtalfreq=26000`, `macaddr=…`), and patch 0003 installs exactly that as the
`COMPONENT_43438` NVRAM.

### 4.5 A CLM blob is not optional

`whd_wifi_on()` ends with a `country` iovar, and without regulatory data the
firmware refuses it:

```
[4079] Could not set Country code
airoc_wifi_init_primary failed ret = -19
```

Leaving CLM out (a `CONFIG_AIROC_WIFI_NO_CLM` option this port added while
chasing the interrupt trap) therefore cannot work.  With the 43438 CLM wired
in, the chip accepts it and reports:

```
[4399] WLAN CLM : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3
               Creation: 2021-03-28 22:47:33
```

It is the AW-CU427-P module's CLM — the only one Infineon publishes for this
part — so it is not this module's calibration data, but it is accepted and the
link works.

### 4.6 USB-ECM: a third path, and where it stopped

With Wi-Fi working, the board's USB-OTG port was tried as an alternative
network path (`usb.conf` + `boards/art_pi_usb.overlay`): the board becomes a
USB **device** exposing CDC-ECM, and — since a host attaching to it has no
reason to run a DHCP server — the board is also the DHCPv4 server for that
link, so the host's desktop configures the new interface with no manual
`ip(8)` and no host-side privileges.  Nothing in the west tree needed
changing: the ART-Pi's Zephyr board file already enables `zephyr_udc0`, the
ECM class is in `subsys/usb/device/class/netusb/`, and Zephyr has a DHCPv4
server.

Firmware-side evidence, read from the board itself (the debugger's register
reads are unreliable on this setup, so the app prints them):

* `usb_dc_attach` → `HAL_PCD_Init` → `HAL_PCD_Start`, then endpoints
  configured and enabled, and the ECM function registered.
* The OTG core reports `GCCFG=0x00010000` (PHY powered),
  `DCTL=0x00000000` (`SDIS=0`: soft-connected, D+ pull-up on),
  `GOTGCTL=0x030900c0` (the HAL's B-session-valid override, as expected with
  `vbus_sensing_enable` disabled for a board whose pin mux has no
  `usb_otg_fs_vbus_pa9`).
* PA11/PA12 are muxed to **AF10** (`pinmux = <0x16a>`, `<0x18a>` in the
  resolved devicetree) — the correct USB OTG FS alternate function.

What never happens is host activity: `GINTSTS` has neither `USBRST` (12) nor
`ENUMDNE` (13) set, and on the PC `journalctl -k` logs **nothing** — not even
when the firmware cycles the D+ pull-up, an event every xHCI host reports if
the port is electrically connected.  So the physical path is the blocker, not
the firmware.  Candidate causes and the checks are in the demo README (cable
type first: a Type-C receptacle wired for legacy devices needs CC pulldowns,
and a C-to-C cable into a port without them stays dark).

That is where this stopped: it is a hardware-side question (try another
cable/port) rather than anything left to implement.

## 5. Tuning the functional suite for a board on Wi-Fi

`function_test.py` was written for qemu/localhost: its CI scripts sleep as if
the broker were local.  Measured against this board the TCP round trip is
30–100 ms, so the suite's "not localhost" heuristic
(`function_test.py`, one-line change: non-loopback ⇒ `--time-scale 4 --retry
2`) is what makes the run reliable — the stretched scale covers the
localhost-tuned sleeps, and the retry covers two subtests that are racy by
construction (`retain-as-published` in `mqtt_v5` failed the first attempt on
this bench and passed on retry).  `tools/verify.sh <board-ip>` wraps that.

It is a heuristic, not a guarantee: one run on a congested link (RTT ~200 ms,
about 3× the usual 30–100 ms) exhausted both `mqtt_v5` retries, and an
immediate re-run passed.  A failure isolated to `mqtt_v5` is worth a re-run
before any investigation.

## 6. Acceptance result (hardware, 2026-09-27)

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

Runs of the same gates on the instrumented build passed too (`mqtt_v5` took
235.8 s, after one `retain-as-published` retry — that subtest is racy by
construction on this bench and the suite retries it).

One of the acceptance runs was made deliberately while the console was
flooding with `sdhc_stm32: Command response timeout` (§3), which is what
established that the state is non-fatal: the gates passed during it.

The full group set passes as well — the two WebSocket groups and the
robustness groups included (`verify.sh <ip> --full` → `pass=7 fail=0`:
`ws_v311` 260.5 s, `ws_v5` 7.7 s, `capacity` 7.5 s, `ws_abort` 11.5 s on top
of the three gates).  That run also found a bug in the demo's own helper:
`verify.sh --full` forwarded an empty argument to the suite (a `${@/--full/}`
substitution leaves one behind) and argparse rejected it; the flag is now
filtered out properly.

`webhook_smoke` is the exception.  It needs a build with
`CONFIG_BROKER_WEBHOOK=y` and the receiver's address baked in; such a build
joins Wi-Fi and leases an address, but the SDIO link then wedges almost
immediately (`Command response timeout` flood) — internal SRAM is at ~88 %
there and the forwarder needs more room, so the group could not be brought up
and `prj.conf` keeps webhook off.

Link state at the same time: `wifi: connected`, DHCPv4 `192.168.1.3`, MQTT
:1883 / REST :8081 / WebSocket :8083 listening, `NanoMQ Broker is started
successfully!`, REST `/api/v4/brokers` → `node_status: Running`.

## 7. Where the changes live

| Change | Where |
| --- | --- |
| The demo itself, `function_test.py`'s non-localhost tuning | repository branch `alvin/art-pi` (nanomq-upstream) |
| `nng`: `SUCCESS` → `NNG_MQTT_SUCCESS` (CMSIS `ErrorStatus.SUCCESS` collision) | nng branch `alvin/art-pi`, based on `alvin/zephyr-port` |
| STM32 SDHC SDIO card-interrupt support; AIROC/WHD SDIO bring-up (poke timer) | `patches/0001`, `patches/0002` (Zephyr tree) |
| 43438 CLM/NVRAM wiring in the WHD glue | `patches/0002` (Zephyr tree) |
| 43438 NVRAM contents | `patches/0003` (west module `hal_infineon`) |
| USB-ECM network path (`usb.conf`, `boards/art_pi_usb.overlay`, the app's bring-up) | demo only — no west-tree change was needed |

The bring-up instrumentation (`nanomq-probe` prints in the Zephyr tree and in
WHD, on-target flag probes) was removed once this configuration passed, and
the poke timer became the Kconfig option `CONFIG_AIROC_WIFI_WHD_POKE`
(enabled by the demo's `wifi.conf`).  The patches are generated from that
final tree.

## 8. Checklist for the next board of this family

1. Confirm which flash the image must live in before fighting the loader —
   here: QSPI XIP, internal flash belongs to the bootloader.
2. Find the module's power-up and clock pins in the *vendor's own* driver
   rather than in schematic text extraction.
3. When an SDIO Wi-Fi chip enumerates but never answers, check
   `SDMMC_STA.SDIOIT` (and whether the driver's card-interrupt path is even
   implemented) before suspecting firmware or NVRAM.
4. Instrument on-target; distrust a debugger that reports `LOCKUP` while the
   console keeps printing.
5. Match NVRAM to the module, and treat a missing CLM as fatal.
6. Re-tune the host test suite for the board's network before concluding the
   broker is broken.
