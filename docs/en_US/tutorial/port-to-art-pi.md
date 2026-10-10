# NanoMQ on Zephyr RTOS: Porting the Broker to the ART-Pi (STM32H750)

## Introduction

This article is the ART-Pi companion to [NanoMQ on Zephyr RTOS: Running an MQTT Broker Directly on an MCU](./port-to-zephyr.md). That article explains the port itself and covers the two targets it was first validated on, the ESP32-S3 (Wi-Fi hardware) and `qemu_x86` (simulation). This one is the record of a third target, `demo/nanomq_zephyr_stm32_art-pi`: an ARM Cortex-M7 board with an on-board Wi-Fi module and 32 MB of SDRAM.

It follows the order the problems appeared in, because three unrelated faults produced the same console output (`airoc_wifi_init_primary failed ret = -19`, no link, no DHCP) and each one first looked like the others.

Acceptance for this port: buildable, **board-verified**, and at **functional parity** with the other two demos. The functional suite's three hard gates pass against the board, and so does the full group set except the webhook group ([the reason is below](#functional-testing)).

## About the ART-Pi

The ART-Pi is a Ruiside (the RT-Thread team's hardware arm) development board built around the **STM32H750XBH6**: a 480 MHz Cortex-M7 with 1 MB of internal SRAM, 32 MB of FMC SDRAM, 8 MB of QSPI flash, and an **AP6212** module whose Wi-Fi side is an Infineon CYW43438 on SDIO. It is close to the ESP32-S3 in class, but everything around the broker is different: where the image lives, where the heap lives, how the radio is attached.

The application layer was not touched. `src/main.c` is the ESP32-S3 file with the Wi-Fi bring-up kept as-is and an Ethernet path added beside it, and `src/process_stub.c` is the same stand-in for NanoMQ's POSIX `process.c`. What had to change is board support and the network layer:

| Dimension | ESP32-S3 | ART-Pi | Consequence |
| --- | --- | --- | --- |
| SoC | ESP32-S3 (Xtensa) | STM32H750XBH6 (Cortex-M7) | 32-bit atomics budget, and a CMSIS `SUCCESS` collision (see Appendix A) |
| Code storage | 16 MB flash, executed in place through its cache | 128 KB internal flash, entirely occupied by the factory bootloader | the image must be linked into the 8 MB **QSPI** window at 0x90000000 |
| Data plane | 16 MB octal PSRAM, 4 MB heap window | 32 MB FMC SDRAM, 4 MB `k_heap` | different allocator wiring, and no PSRAM "shared multi heap" |
| Network | ESP32 Wi-Fi (ESP-IDF blob) | on-board **AP6212 = CYW43438**, SDIO on SDMMC2 | the Infineon AIROC/WHD path, with SDIO host glue on the STM32 SDMMC |
| Display | LCD panel (unused) | an LTDC would take SDRAM away from the broker heap | `&ltdc` is disabled in the overlay |
| Clock | the Wi-Fi driver seeds SNTP | same approach, optional (`CONFIG_BROKER_SNTP`) | none |

## Environment Setup

### Prerequisites

The environment is the one the [main article](./port-to-zephyr.md#environment-setup) sets up: a Zephyr ≥ 4.4 west workspace with the Python virtual environment that provides `west` and `pyocd`, and `ZEPHYR_SDK_INSTALL_DIR` exported. Two things are specific to this board:

* The ART-Pi's ST-Link provides both the serial console and the SWD probe, so one USB cable gives you `/dev/ttyACM0` for both. A udev rule for the probe is recommended.
* `pyocd 0.45` needs a board-ID workaround on this probe; `tools/artpi_flash.py` already contains it (see [The Porting Process](#the-porting-process), trap 2).

### Get the Source Code and the Out-of-Tree Patches

The ART-Pi demo lives under `demo/nanomq_zephyr_stm32_art-pi/` in the `zephyr-rtos` branch of the repository. It needs three deltas that live outside it, two in the Zephyr tree and one in a west module, because they cannot travel on this repository's branches:

| Patch | Repository | What it does |
| --- | --- | --- |
| `patches/0001-zephyr-sdhc-stm32-sdio-card-interrupt.patch` | Zephyr tree | SDIO card-interrupt support for the STM32 SDMMC host, which had no `enable_interrupt` / `disable_interrupt` implementation |
| `patches/0002-zephyr-airoc-whd-sdio-bring-up.patch` | Zephyr tree | the WHD thread poke timer and the power-save fix (both are Kconfig options), plus CLM/NVRAM wiring for the CYW43438 in the WHD glue |
| `patches/0003-infineon-whd-43438-art-pi-resources.patch` | west module `hal_infineon` | the 43438 NVRAM for this module, kept in its own file |

The patches are generated from the tree that passed acceptance, and the base revisions they apply to are recorded in `patches/README.md`. Apply them before building:

```sh
ZEPHYR_WORKSPACE=~/zephyrproject          # your west workspace
PATCHES=$PWD/demo/nanomq_zephyr_stm32_art-pi/patches

git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0001-zephyr-sdhc-stm32-sdio-card-interrupt.patch
git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0002-zephyr-airoc-whd-sdio-bring-up.patch
git -C $ZEPHYR_WORKSPACE/modules/hal/infineon apply $PATCHES/0003-infineon-whd-43438-art-pi-resources.patch
```

### Fetch the Infineon Blobs

The 43438 firmware image is not in git, and without it `CONFIG_WIFI_AIROC` has no blob to embed:

```sh
west blobs fetch hal_infineon
```

### The Vendor QSPI Flash Algorithm

Flashing the QSPI part needs the vendor's CMSIS flash algorithm (`ART-Pi_W25Q64.FLM`), which is fetched from the ART-Pi SDK rather than redistributed here:

```sh
git clone --depth 1 --filter=blob:none --no-checkout \
    https://github.com/RT-Thread-Studio/sdk-bsp-stm32h750-realthread-artpi /tmp/artpi_sdk
git -C /tmp/artpi_sdk show HEAD:debug/flm/ART-Pi_W25Q64.FLM \
    > demo/nanomq_zephyr_stm32_art-pi/tools/ART-Pi_W25Q64.FLM
```

## Build and Run: ART-Pi Hardware

### 1. Configure Local Credentials (Wi-Fi and REST)

Wi-Fi credentials and REST credentials are site-specific, so they live in a git-ignored `local.conf`, copied from `local.conf.example`:

```sh
cp demo/nanomq_zephyr_stm32_art-pi/local.conf.example \
   demo/nanomq_zephyr_stm32_art-pi/local.conf

# then edit:
#   CONFIG_BROKER_WIFI_SSID="<your AP>"
#   CONFIG_BROKER_WIFI_PSK="<your passphrase>"
#   CONFIG_BROKER_REST_USER="<user>"     # the REST listener stays off
#   CONFIG_BROKER_REST_PASS="<password>" # until both of these are set
```

REST is optional but is what the suite's `rest_get` group exercises; if you leave the credentials unset, that group is reported as SKIP rather than failing.

### 2. Build

The demo links into the QSPI window, not the internal flash, and that comes from an overlay the app sets for itself, so `west build -b art_pi` with no extra arguments does not produce a usable image. `tools/flash.sh` builds and programs in one step with the right arguments:

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --wifi
```

`--wifi` is the default and the only variant verified here; it passes `wifi.conf` and `boards/art_pi_wifi.overlay`, which also disables the Ethernet nodes so the image has a single network interface. If you want the build step on its own:

```sh
west build -b art_pi demo/nanomq_zephyr_stm32_art-pi -- \
    -DEXTRA_CONF_FILE="local.conf;wifi.conf" \
    -DEXTRA_DTC_OVERLAY_FILE=boards/art_pi_wifi.overlay
```

### 3. Flash the Firmware

`tools/flash.sh` builds, then runs `tools/artpi_flash.py`, which loads the vendor's CMSIS flash algorithm into SRAM4, resets the target (the loader brings up clocks, caches and the QUADSPI from scratch and times out when it inherits a running application's configuration), programs only the sectors the image covers into the QSPI window at 0x90000000 over SWD, and resets and resumes one more time at the end, because `pyocd` leaves the core halted after programming. Without that last reset the image would only start at the next power cycle.

Two things are worth knowing before the first flash:

* It overwrites the factory RT-Thread application in QSPI slot 0. The factory application is rebuildable from `projects/art_pi_factory` in the ART-Pi SDK; the factory **bootloader** in internal flash is untouched.
* `--dry-run` loads the flash algorithm and reports the plan without writing, but it does not reset the target afterwards; a board left there sits at the bootloader's `msh >` prompt until the next real flash or reset.

### 4. Monitor the Serial Console

There is no login, just the boot log and the broker's output at 115200 8N1:

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh            # live view, Ctrl-C to quit
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o boot.log # capture while showing it
```

The ST-Link's virtual COM port buffers, so a capture started right after a reset can replay the *previous* boot first: you will see two `Powered by RT-Thread.` banners and two `*** Booting Zephyr OS ***` lines. Split the log on the last bootloader banner, or discard the backlog first with `console.sh --drain <seconds>`. Only one reader at a time: if the output looks truncated or interleaved, check that no other `cat`/`minicom`/`tio` still holds the port.

### 5. Verify the Connection

`tools/verify.sh` wraps the functional suite for a board that is already running:

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/verify.sh <board-ip>
```

The broker's REST API is a quick manual check:

```sh
curl -u <user>:<password> http://<board-ip>:8081/api/v4/brokers
```

### What a Good Boot Looks Like

Captured straight after a re-flash:

```
Powered by RT-Thread.

msh >[00:00:00.000,000] <inf> sdhc_stm32: SDHC Init Passed Successfully
[00:00:02.767,000] <inf> sd: Card does not support CMD8, assuming legacy card

[4358] WLAN MAC Address : 70:4A:0E:51:77:9A

[4378] WLAN Firmware    : wl0: Mar 28 2021 22:55:55 version 7.45.98.117 (dc5d9c4 CY) FWID 01-d36e8386

[4398] WLAN CLM         : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3 Creation: 2021-03-28 22:47:33

[4408] WHD VERSION      : 3.3.3.26653
[4412]  : WIFI5-v3.3.3
[4414]  : GCC 14.3
[4415]  : 2025-04-14 03:18:50 +0000
*** Booting Zephyr OS build v4.4.0-4779-g11a87708d415 ***
wifi: connecting to "TP-LINK_A57B" (attempt 1)
1970-01-01 00:00:08 [0] INFO  WEST_TOPDIR/nanomq-upstream/nanomq/web_server.c:548 start_rest_server: http://0.0.0.0:8081/api/v4
1970-01-01 00:00:08 [0] WARN  WEST_TOPDIR/nanomq-upstream/nanomq/apps/broker.c:1400 broker: NanoMQ (ver 0.25.6) Serving HTTP Server on http://(null):8081
NanoMQ Broker is started successfully!
wifi: connected to "TP-LINK_A57B"
wifi: connected — starting DHCPv4 client
[00:00:07.758,000] <err> net_ipv6_nd: DAD failed, no ll IPv6 address!
[00:00:08.138,000] <inf> net_dhcpv4: Received: 192.168.1.3
wifi: IPv4 address assigned (DHCPv4)
net: iface 0x24002068 dev=airoc-wifi up=1
net: ipv4 192.168.1.3
```

Reading it, in order:

* `Powered by RT-Thread.` / `msh >`: the **ART-Pi factory bootloader**'s own banner, printed before it maps the QSPI and jumps to the demo. It is not the demo failing to start, and not RT-Thread running the broker.
* `sdhc_stm32: SDHC Init Passed Successfully`, then `sd: Card does not support CMD8`: the SDIO host is up and the Wi-Fi card is enumerated as a legacy (SDIO, not SD) card. `Card does not support CMD8` is normal here.
* `WLAN MAC Address`, `WLAN Firmware`, `WLAN CLM`, `WHD VERSION`: raw `printf` output from Infineon's WHD as it talks to the chip. The MAC is this board's AP6212; the firmware and CLM are the resources the demo loaded. These lines appear *before* the Zephyr banner because raw `printf` does not go through the log subsystem the banner uses, so that ordering is cosmetic.
* `*** Booting Zephyr OS ... ***`: the demo itself, i.e. the point where `main()` starts doing work.
* `wifi: connecting to "<SSID>"` → `wifi: connected` → `wifi: IPv4 address assigned (DHCPv4)`: the STA flow in `src/main.c`. These lines go through Zephyr's logging (here `printk` is routed into the deferred log thread) while nanolib's `printf` writes straight to the console, so `NanoMQ Broker is started successfully!` can appear *between* `wifi: connecting` and `wifi: connected` even though the broker starts afterwards. That reordering is cosmetic too.
* `net_ipv6_nd: DAD failed, no ll IPv6 address!` is an **error-severity log that is expected**: IPv6 is enabled in the net stack but this link has no IPv6, so duplicate-address detection has nothing to work on. The broker uses IPv4.
* `NanoMQ Broker is started successfully!` plus the two `broker:`/`web_server:` lines: the REST listener is on `:8081`, MQTT on `:1883`, WebSocket on `:8083/mqtt`.
* `net: ipv4 192.168.x.y`: the address `tools/verify.sh` wants.
* Afterwards, one line a minute: `broker: status running — uptime 64s, MQTT tcp://0.0.0.0:1883, REST http://0.0.0.0:8081, WS :8083/mqtt, ipv4 192.168.1.3`. The broker's startup banner is printed **once**, while `broker()` starts, so anything attached to the console later sees only the heartbeat, which exists so "is it up, and on which address?" never depends on catching the boot.

## Functional Testing

The functional suite is shared with the other demos; the [main article](./port-to-zephyr.md#functional-testing) covers installing it and running it. Two things are specific to a board on Wi-Fi:

`function_test.py` was written for qemu/localhost: its CI scripts sleep as if the broker were local. Measured against this board the TCP round trip is 30 to 100 ms, so the suite's "not localhost" heuristic (a one-line change in `function_test.py`: a non-loopback address implies `--time-scale 4 --retry 2`) is what makes a run reliable: the stretched scale covers the localhost-tuned sleeps, and the retry covers two subtests that are racy by construction (`retain-as-published` in `mqtt_v5` failed its first attempt on this bench and passed on retry). `tools/verify.sh <board-ip>` wraps that.

It is a heuristic, not a guarantee: one run on a congested link (RTT ~200 ms, about 3× the usual 30 to 100 ms) exhausted both `mqtt_v5` retries, and an immediate re-run passed. A failure isolated to `mqtt_v5` is worth a re-run before any investigation.

The acceptance run, on hardware, 2026-09-27:

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

An earlier run of the same gates on the instrumented build passed too (`mqtt_v5` took 235.8 s there, after one `retain-as-published` retry). One of the acceptance runs was made deliberately while the console was flooding with `sdhc_stm32: Command response timeout` (trap 8 in [The Porting Process](#the-porting-process)), which is what established that the state is non-fatal: the gates passed during it.

The full group set passes as well: the two WebSocket groups and the robustness groups included (`verify.sh <ip> --full` → `pass=7 fail=0`: `ws_v311` 260.5 s, `ws_v5` 7.7 s, `capacity` 7.5 s, `ws_abort` 11.5 s on top of the three gates). That run also found a bug in the demo's own helper: `verify.sh --full` forwarded an empty argument to the suite (a `${@/--full/}` substitution leaves one behind) and argparse rejected it; the flag is now filtered out properly.

`webhook_smoke` is the exception. It needs a build with `CONFIG_BROKER_WEBHOOK=y` and the receiver's address baked in; such a build joins Wi-Fi and leases an address, but the SDIO link then wedges almost immediately (the same `Command response timeout` flood). Internal SRAM is at ~88 % there and the forwarder needs more room, so the group could not come up, and the demo keeps webhook off by default.

Link state at the same time: `wifi: connected`, DHCPv4 `192.168.1.3`, MQTT :1883 / REST :8081 / WebSocket :8083 listening, `NanoMQ Broker is started successfully!`, REST `/api/v4/brokers` → `node_status: Running`.

Link recovery (trap 9 in [The Porting Process](#the-porting-process)) got its own bench run. A temporary build (the hook was not committed) issued `NET_REQUEST_WIFI_DISCONNECT` 180 s into the run *and* left `NET_EVENT_WIFI_DISCONNECT_RESULT` unregistered, so only the supervisor's status poll could notice the loss, i.e. an AP that disappears without raising an event:

```
selftest: NET_REQUEST_WIFI_DISCONNECT -> 0                (uptime 180 s)
[00:03:07.558] <err> sdhc_stm32: Command response timeout  <- the leave sequence
wifi: link down — reconnecting to "TP-LINK_A57B"          (uptime ~188 s)
wifi: connected to "TP-LINK_A57B"
[00:03:13.738] <inf> net_dhcpv4: Received: 192.168.1.8
wifi: IPv4 address assigned (DHCPv4)
broker: status running — uptime 244s, ... , ipv4 192.168.1.8
```

The poll caught it 7 s after the drop (inside the 10 s period), re-association and a fresh lease took another ~6 s, the same address came back, and the broker kept running throughout: its listeners never restarted. The single `Command response timeout` belongs to the leave sequence, not the KSO flood of trap 8: it appears once, at the transition, and not afterwards.

## The Porting Process

### 1. Getting an Image onto the Board: QSPI XIP Behind the Factory Bootloader

The ART-Pi's internal flash holds the Ruiside/RT-Thread **factory bootloader**. It maps the QUADSPI and jumps to the vector table at 0x90000000, so the demo does not have to be a first-stage loader; it only has to *be there*:

```dts
/ { chosen { zephyr,flash = &ext_memory; }; };   /* 8 MB QSPI, 0x90000000 */
```

Two consequences follow:

* **The QSPI driver must stay off** (`CONFIG_FLASH` / `FLASH_STM32_QSPI`). Its init would reconfigure the peripheral the CPU is fetching instructions from. This demo has no filesystem, so nothing is lost.
* A plain `west build -b art_pi` links into the 128 KB internal flash and cannot hold the broker, so the overlay that sets `zephyr,flash` is mandatory; that is why `tools/flash.sh` exists.

### 2. Tooling Traps on the Way to a Running Image

* **pyocd 0.45 + this ST-Link.** While connecting, pyocd sends `JTAG_GET_BOARD_IDENTIFIERS` and expects 128 bytes; this probe answers with a 2-byte status, which pyocd turns into a fatal `received incomplete command response from STLink (got 2, expected 128)`, and no SWD access at all, although the probe itself is healthy. The board ID only feeds a human-readable name, so `tools/artpi_flash.py` neutralises the query before importing the connect helper.
* **The vendor's flash algorithm is not optional.** `ART-Pi_W25Q64.FLM` is what knows the W25Q64 behind the QUADSPI; pyocd's own `stm32h750xx` target knows neither that region nor that algorithm. It is not redistributed with the demo; fetch it from the ART-Pi SDK as shown in [Environment Setup](#environment-setup).
* **Reset before the algorithm, not around it.** The vendor loader brings up clocks, caches and the QUADSPI from scratch and *times out* when it inherits a running application's configuration, so the tool resets and halts before programming.
* **Reading 0x90000000 over SWD faults while the QUADSPI is in indirect mode**, which is why the flash region is marked `are_erased_sectors_readable = False` and the tool erases and rewrites whole sectors instead of read-verifying.
* **Console backlog and halted cores.** The two symptoms that look like a dead board: a capture that starts with the *previous* boot because the ST-Link's virtual COM port buffered it (split on the last bootloader banner, or use `console.sh --drain`), and a board that prints only the bootloader banner and then goes silent because `pyocd` left the core halted after programming (the tool now resets and resumes once more at the end).
* **The default build has to be the one that works.** `tools/flash.sh` builds the Wi-Fi variant unless told `--eth`; an early version built the plain `prj.conf` image, i.e. the Ethernet variant, which then sits at `eth: still no link` forever on a bench with no cable. That mistake looks exactly like a dead board.
* **A flooding console is a defect too.** The STM32 SDHC driver logged one line per failed command, and the Wi-Fi chip's sleep (trap 8) produced hundreds of them a second, so the console became a wall of `Command response timeout` and nothing else was readable. They are now rate-limited (one line per 5 s plus a `Skipped N messages` counter) *and* the cause itself is fixed.
* **The broker's startup log is printed once, and only if the broker starts.** nanolib announces it while `broker()` runs; anything attached to the console later sees only what the drivers are doing. Two fixes came out of that: the boot-time Wi-Fi connect loop is **bounded** (it used to retry forever, so a board that could not associate never started the broker and printed nothing about it) with the link supervisor taking over afterwards (trap 9), and the demo prints a one-line status heartbeat every `CONFIG_BROKER_STATUS_INTERVAL_S` seconds (default 60) carrying the uptime, the listeners and the current IPv4 address.

### 3. Ethernet: the Reset Line Was the Red Herring

The ART-Pi has an STM32 MAC + LAN8720A PHY, so the first attempt was the simpler path (`eth.conf`). It never came up: an SWD-driven MDIO scan of every address 0 to 31 found nothing (`phy_mii: PHY (0) ID FFFF`, `HAL_ETH_Init failed`). The obvious explanation was a PHY held in reset, so the overlay drove PA3, the vendor BSP's `ETH_RESET_PIN`, as `reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>`. That did not help, which looked like a dead PHY, until the override was removed again and the MAC initialised cleanly with no PHY error at all. PA3 is evidently not this board's PHY reset, and driving it low is what kept the PHY quiet; the override is gone from the overlay.

What is *not* proven is the part that needs hardware nobody had on the bench: with no Ethernet cable the interface stays dormant waiting for carrier, so link-up, DHCP and traffic over Ethernet remain untested. Wi-Fi is the verified path.

### 4. Wi-Fi: the SDIO Side Has to Be Built from Scratch

Zephyr's ART-Pi devicetree says nothing about the Wi-Fi side of the AP6212, so the overlay adds an SDIO host on SDMMC2 and the AIROC device node:

| Signal | Pin | Source |
| --- | --- | --- |
| SDMMC2 D0/D1/D2/D3 | PB14/PB15/PB3/PB4 (AF9) | vendor `projects/art_pi_wifi` CubeMX config |
| SDMMC2 CK/CMD | PD6/PD7 (AF11) | same |
| WL_REG_ON | PC13 | `libraries/drivers/drv_wlan.c`: `AP6212_WL_REG_ON` |

`WL_REG_ON` is easy to get wrong: an early guess based on the schematic text (PI14) gave "no CMD5 response" at all, because the chip was never powered. The vendor driver's own `GET_PIN(C, 13)` is the authority. With PC13 driven high, SDIO enumerates: CMD5, CCCR rev 2, CIS for functions 0/1/2, 4-bit bus, 25 MHz.

### 5. The Trap That Cost the Most: No In-Band SDIO Card Interrupt

Symptom: firmware download succeeded, the WLAN function became ready (`SDIOD_CCCR_IORDY` reached `0x6`), the first ioctl was written to function 2 (768 + 36 bytes), and then nothing. No reply was ever read, every ioctl timed out (`iovar "cap" -> 101580800`, 5 s each), and `airoc_wifi_init_primary failed ret = -19`.

WHD's design makes this fatal: `whd_thread_func()` only enters its receive path when `thread_info->bus_interrupt` is set (or when `whd_bus_use_status_report_scheme()` is true), and for this transport that function returns `WHD_FALSE`. The flag is only set by the SDIO card interrupt handler, so no card interrupt means no received frame, forever.

The obvious suspects were ruled out with on-target instrumentation rather than debugger reads (pyocd's halt/register access on this setup turned out to be unreliable: it reports `LOCKUP` and returns garbage for registers while the application is demonstrably running):

* `SDMMC_MASK.SDIOITIE` **is** set: `enable_interrupt -> MASK=0x00400000`.
* The SDMMC interrupt works: the ISR fires for data transfers.
* `SDMMC_STA.SDIOIT` is **never** set, not once in a whole boot, including while WHD sits in its 5 s ioctl timeout. The chip never asserts DAT1.
* CCCR `INTEN` is programmed (`wr cccr[0x4] = 0x7`) and the WLAN function is ready, so the host side is fully armed.

The workaround is patch 0002, `CONFIG_AIROC_WIFI_WHD_POKE`: poke `whd_thread_notify_irq()` from a 20 ms timer. That hands the thread the wake-up the interrupt would have delivered, its poll finds the queued reply, and the init chain completes:

```
[4179] nanomq-probe: iovar "cap" -> 0            (was 101580800)
cmd53 rd func2 addr=0x0 size=39 -> 0             (the reply is read)
WLAN MAC Address : 70:4A:0E:51:77:9A
```

Every other way of getting a real interrupt was then tried and ruled out:

* **`DCTRL.SDIOEN`** (the STM32 SDMMC's "SD I/O enable", i.e. "treat DAT1 as the interrupt line"). With it set the host is fully armed (`MASK=0x00400000`, `DCTRL=0x00000800`, and the bit stays set through transfers) yet `SDMMC_STA.SDIOIT` still never latched. Once traffic flows it makes 4-bit transfers fail with a `Command response timeout` flood, so it is deliberately not set.
* **A 1-bit bus**, where DAT1 is a dedicated interrupt line rather than a data line (`bus-width = <1>` plus WHD's `sdio_1bit_mode`). Same result: no `SDIOIT`, no link.
* **Out-of-band host-wake.** The vendor NVRAM sets `muxenab=0x11` (bit `0x10` = "HW OOB") and the schematic carries a `GPIO_WIFI_HOST_WAKE` net, so the chip may be signalling out-of-band instead. Wired as `wifi-host-wake-gpios = <&gpioe 3 GPIO_ACTIVE_HIGH>` (PE3 being the only MCU pin the schematic text plausibly pairs with that net; the PI14/PI15 hits are the LCD's LTDC_CLK/LTDC_R0), it produced no wake-up either, and the CMD flood appeared once traffic flowed. Left out.

Polling is also what this board's vendor stack does: the ART-Pi SDK's own Wi-Fi host driver (`libraries/drivers/drv_sdio.c`) never enables `SDMMC_MASK.SDIOITIE` and registers no card-interrupt callback, so its WICED-based stack is fed by polling the chip's status registers.

Because the missing interrupt makes *every* ioctl time out, it also produced two convincing but wrong earlier conclusions: that the CLM blob "hangs the chip", and that the packed firmware blob from the vendor's SPI flash is needed. Both were symptoms, not causes.

### 6. NVRAM Must Be This Module's

With the interrupt worked around, the firmware still aborted its init until the NVRAM matched the module. The ART-Pi's AP6212 is the `boardtype=0x0726` variant; the AW-CU427-P NVRAM that the blob manifest ships for the CYW43438 (`boardtype=0x0865`) does not work here. The authoritative text is the vendor's own `wifi_nvram_image[]` in `libraries/drivers/drv_wlan.c` (`prodid=0x0726`, `boardrev=0x1101`, `xtalfreq=26000`), and patch 0003 installs exactly that as the `COMPONENT_43438` NVRAM, in its own file, leaving the other module's calibration data untouched.

### 7. A CLM Blob Is Not Optional

`whd_wifi_on()` ends with a `country` iovar, and without regulatory data the firmware refuses it:

```
[4079] Could not set Country code
airoc_wifi_init_primary failed ret = -19
```

Leaving CLM out (a `CONFIG_AIROC_WIFI_NO_CLM` option this port added while chasing the interrupt trap) therefore cannot work. With the 43438 CLM wired in, the chip accepts it and reports:

```
[4399] WLAN CLM : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3
               Creation: 2021-03-28 22:47:33
```

It is the AW-CU427-P module's CLM, the only one Infineon publishes for this part, so it is not this module's calibration data; it is accepted and the link works.

### 8. The Console Flood: the Chip Was Asleep, and That Is Allowed

From about 50 s after association the console filled with `sdhc_stm32: Command response timeout`, rate-limited to one line per 5 s but with a `Skipped ~1500 messages` counter beside it, i.e. ~300 failures a second, while the broker and its data path stayed healthy (the whole functional suite passed in that state).

Classifying the SDHC driver's commands (temporary probes, removed afterwards) gave the signature that identified it:

| Command class | Sent | Failed |
| --- | --- | --- |
| CMD52, any function (register access, no data phase) | ~215 000 | ~108 000 |
| CMD53, function 1, byte mode (the SDIO backplane) | ~20 000 | **0** |
| CMD53, function 1, block mode (the SDIO backplane) | 412 | **0** |
| CMD53, function 2 (WLAN data) | ~2 100 | **0** |

Only CMD52 failed, about half of them, and the first one to fail was always `CMD52 write, function 1, address 0x1001F, value 1`, which is `SBSDIO_SLPCSR_KEEP_WL_KSO` written to `SDIO_SLEEP_CSR`, the first write of WHD's device-wake sequence. WHD's own comment at that write reads "1st KSO write goes to AOS wake up core if device is asleep / Possibly device might not respond to this cmd. So, don't check return value here": with its power save enabled the chip enters that KSO sleep once the connection settles, and while asleep **it does not answer that write on purpose**.

A host controller cannot know that a card's silence is expected. The STM32 SDHC driver reports every command that gets no response as a command-response timeout, so the flood was the chip doing exactly what its firmware documents, rendered as ~300 error lines a second.

The fix is to keep the chip awake: `whd_wifi_disable_powersave()` once `whd_wifi_on()` succeeds, gated by `CONFIG_AIROC_WIFI_DISABLE_POWERSAVE`, on in the demo's `wifi.conf`. It is a mains-powered broker; the chip has no reason to sleep. Measured after the change: a boot that previously produced ~300 failures a second from ~50 s onward now runs with **zero** `Command response timeout` lines and zero CMD52 failures, with the rate limiter kept as a safety net for genuine timeouts.

A silent SDIO card is not necessarily a broken one: this chip stays silent on purpose while it sleeps, and the host can tell the difference only by knowing the protocol position of the command.

### 9. A Lost Link Has No Event, So the Demo Polls for It

An association on this board can end in three ways, and only one of them reaches the application as a Wi-Fi mgmt event:

| How the link ends | What the driver does | Event the app sees |
| --- | --- | --- |
| explicit `NET_REQUEST_WIFI_DISCONNECT` | `airoc_mgmt_disconnect()` raises the result | `NET_EVENT_WIFI_DISCONNECT_RESULT` |
| the AP sends deauth / disassoc | the event task calls `net_if_dormant_on()` | none |
| the AP disappears (beacon loss) | the event task passes `WLC_E_LINK` (link flag clear) through | none |

So the boot-time association was the application's only contact with the link: an AP that went away after that produced no event, and the broker, whose listeners are on `0.0.0.0` and never notice, stayed reachable only at an address the board no longer had. The symptom was the 60 s status heartbeat losing its `ipv4 ...` part, and the only recovery was a reset.

The one signal that covers all three rows already exists inside WHD: its `JOIN_LINK_READY` bit, which `whd_wifi_api.c` clears for `WLC_E_LINK` (link flag clear), `WLC_E_DEAUTH_IND` and `WLC_E_DISASSOC_IND`. `NET_REQUEST_WIFI_IFACE_STATUS` is the mgmt request that reaches `whd_wifi_is_ready_to_transceive()`, i.e. that bit, so the demo runs a supervisor thread that polls it every `CONFIG_BROKER_WIFI_MONITOR_PERIOD_S` seconds (default 10) and re-associates (wait for the connect result, then `net_dhcpv4_restart()`) whenever the answer is not `WIFI_STATE_COMPLETED`. While the AP stays away it backs off 5 s, doubling to 60 s. It also waits on `NET_EVENT_WIFI_DISCONNECT_RESULT`, so the one loss that *does* produce an event is handled immediately rather than at the next tick.

The broker itself needs no help: with the listeners on `0.0.0.0`, a reconnect that gets the same lease back is invisible to clients beyond their own reconnects, and a different lease only changes the address in the heartbeat. Boot is unchanged: the initial 3 × 30 s is still bounded, so a board that cannot associate still starts the broker and says so; the supervisor just keeps trying from then on.

## Conclusion

### Where This Approach Fits

The ART-Pi is the ARM board the main article listed as unvalidated: the Cortex-M7 path, the 32-bit atomic fallback and the external-RAM allocator all work, and the port reached functional parity with the other two demos. Its difficulty was board bring-up rather than application code, with a bootloader that owns the flash the image has to live in and an SDIO radio whose three independent faults (missing card interrupt, mismatched NVRAM, missing CLM) all present as "no link".

Two things generalize past this board. Polling a chip does not always mean the hardware is broken: this board's own vendor stack polls, and the interrupt the datasheet describes is not wired here. A link that can disappear also needs a supervisor, because a driver's disconnect event usually covers only an explicit disconnect; an AP that silently walks away has to be found by asking the driver for its own join state.

### Code and Demos

The demo lives under `demo/nanomq_zephyr_stm32_art-pi` in the `zephyr-rtos` branch of [nanomq/nanomq](https://github.com/nanomq/nanomq/tree/zephyr-rtos), next to the ESP32-S3 and `qemu_x86` demos, and its README carries the full build, flash and console procedure. The three out-of-tree patches are in the demo's `patches/` directory, with their base revisions in `patches/README.md`.

If you bring the port up on another board of this family, or hit a fault this article does not cover, join the discussion in the [NanoMQ community](https://github.com/nanomq/nanomq/discussions).

### Further Reading: The Port's Decision Records

Five decisions from this port are recorded in full, with the alternatives that were rejected, in the demo's own `docs/adr/` directory:

| Record | Decision |
| --- | --- |
| [ADR 0001](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0001-qspi-xip-behind-art-pi-factory-bootloader.md) | Run the image from QSPI XIP behind the ART-Pi factory bootloader |
| [ADR 0002](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0002-broker-heap-in-sdram-through-the-external-ram-allocator.md) | Put the broker heap in SDRAM, reached through the external-RAM allocator |
| [ADR 0003](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md) | Poll the WHD thread, because the board never asserts the SDIO card interrupt |
| [ADR 0004](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0004-keep-the-art-pi-wifi-chip-awake.md) | Keep the Wi-Fi chip awake instead of letting it KSO-sleep |
| [ADR 0005](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0005-poll-the-join-state-to-recover-a-lost-wi-fi-link.md) | Recover a lost Wi-Fi link by polling the join state |

## Appendix A: What the Port Needed Upstream

| Change | Where it lives |
| --- | --- |
| The demo itself, and the non-localhost tuning of `function_test.py` | this repository, `zephyr-rtos` branch |
| `nng`: `SUCCESS` → `NNG_MQTT_SUCCESS` (the CMSIS `ErrorStatus.SUCCESS` collision on STM32) | the `nng` submodule, on top of the Zephyr port work |
| STM32 SDHC SDIO card-interrupt support | `patches/0001` (Zephyr tree) |
| AIROC/WHD SDIO bring-up: the poke timer, the power-save fix, and the 43438 CLM/NVRAM wiring | `patches/0002` (Zephyr tree) |
| 43438 NVRAM contents for this module | `patches/0003` (west module `hal_infineon`) |

The bring-up instrumentation (`nanomq-probe` prints in the Zephyr tree and in WHD, plus on-target flag probes) was removed once this configuration passed, and the poke timer became the Kconfig option `CONFIG_AIROC_WIFI_WHD_POKE`. The patches are generated from that final tree.

## Appendix B: Checklist for the Next Board of This Family

1. Confirm which flash the image must live in before fighting the loader: here it is QSPI XIP, and the internal flash belongs to the bootloader.
2. Find the module's power-up and clock pins in the *vendor's own* driver rather than in schematic text extraction.
3. When an SDIO Wi-Fi chip enumerates but never answers, check `SDMMC_STA.SDIOIT` (and whether the driver's card-interrupt path is even implemented) before suspecting firmware or NVRAM.
4. Instrument on-target; distrust a debugger that reports `LOCKUP` while the console keeps printing.
5. Match NVRAM to the module, and treat a missing CLM as fatal.
6. Give the network link a supervisor (trap 9). A driver's disconnect event usually covers only an explicit disconnect, and an AP that disappears is silent, so poll the driver's own join state and re-associate from a thread that lives as long as the application does.
7. Re-tune the host test suite for the board's network before concluding the broker is broken.
