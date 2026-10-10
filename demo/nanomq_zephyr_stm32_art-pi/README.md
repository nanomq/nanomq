# NanoMQ broker on the ART-Pi (art_pi / STM32H750XBH6)

Runs the full NanoMQ broker core (`nanomq/nanomq/` application sources + the
NanoNNG submodule `nng/`) on the Ruiside/RT-Thread **ART-Pi**
(STM32H750XBH6) over **Wi-Fi (STA) + DHCPv4**, using the board's on-board
**AP6212** module (an Infineon **CYW43438** wired as an SDIO function on
SDMMC2).

Sibling of [demo/nanomq_zephyr_qemu_x86](../nanomq_zephyr_qemu_x86/)
(qemu_x86, simulation) and [demo/nanomq_zephyr_esp32s3](../nanomq_zephyr_esp32s3/)
(ESP32-S3, Wi-Fi): same app sources and NanoNNG ExternalProject build,
different board and network layer.  Feature surface matches the other two:
MQTT over TCP (:1883) + REST API (:8081, Basic auth) + MQTT over WebSocket
(:8083/mqtt), plus an optional webhook forwarder.  DEBUG log stays off.

Acceptance tier: **functional parity** — the suite's three hard gates
(`mqtt_v311`, `mqtt_v5`, `rest_get`) pass against the board (record below).

## Board target

Zephyr's own `art_pi` board: STM32H750XBH6 (Cortex-M7), 128 KB internal
flash, 1 MB SRAM, 32 MB FMC SDRAM, 8 MB QSPI NOR, AP6212 Wi-Fi/BT module,
microSD, RGB LCD connector, USB-OTG, ST-Link V2.1 on the same USB-C
connector (SWD + a 115200 virtual COM port on `/dev/ttyACM0`).

## Memory layout

Two decisions carry this demo; both have an ADR.

**The image runs from QSPI XIP at 0x90000000**
([docs/adr/0001](docs/adr/0001-qspi-xip-behind-art-pi-factory-bootloader.md)).
The broker is ~1 MB of code and the internal flash is 128 KB — all of it
occupied by the Ruiside factory bootloader, which already maps the QUADSPI
and jumps to the vector table it finds at 0x90000000.  The overlay points
`zephyr,flash` at the 8 MB QSPI window
([boards/art_pi.overlay](boards/art_pi.overlay)) and the QSPI *driver* stays
off so nothing reconfigures the peripheral the CPU fetches from.  Flashing
is SWD only ([tools/artpi_flash.py](tools/artpi_flash.py)).

**The broker data plane lives in SDRAM**
([docs/adr/0002](docs/adr/0002-broker-heap-in-sdram-through-the-external-ram-allocator.md)).
The devicetree's 6 MB `SDRAM1` region at 0xC0000000 feeds a plain `k_heap`
(4 MB of it) through NanoNNG's external-RAM allocator
(`NNG_ZEPHYR_ALLOC_SMH`), with the bounds in the linker fragment
[src/artpi_ext_ram.ld](src/artpi_ext_ram.ld).  The display controller is
disabled so its framebuffer does not compete for the same window.

Wi-Fi build footprint: FLASH ~977 KB (of 8 MB), RAM ~451 KB / 512 KB
(86 %) — the internal-SRAM budget is the tight one, not the flash.

## Networking

### Wi-Fi (default configuration)

The AP6212's Wi-Fi side is an SDIO function.  Zephyr's board devicetree wires
nothing for it, so the demo adds both the SDIO host and the AIROC/WHD device
node:

| Signal | Pin | Note |
| --- | --- | --- |
| SDMMC2 D0/D1 | PB14/PB15 | AF9 |
| SDMMC2 D2/D3 | PB3/PB4 | AF9 |
| SDMMC2 CK/CMD | PD6/PD7 | AF11 |
| WL_REG_ON | PC13 | active high, from the ART-Pi's own Wi-Fi driver |

Pin usage comes from the vendor's Wi-Fi project (`projects/art_pi_wifi/` in
the ART-Pi SDK); WL_REG_ON is `AP6212_WL_REG_ON == GET_PIN(C, 13)` in
`libraries/drivers/drv_wlan.c`.

Three things have to be right for the chip to join an AP.  All three were
found the hard way; see [docs/en_US/port-to-art-pi.md](docs/en_US/port-to-art-pi.md)
for the full record.

1. **Resources: firmware + NVRAM, and a CLM.**  The upstream airoc
   `43438A1.bin` firmware is used unchanged, but the NVRAM must be this
   module's: the vendor's `wifi_nvram_image[]` (`prodid=boardtype=0x0726`,
   `xtalfreq=26000`).  The AW-CU427-P NVRAM the blob manifest ships for this
   part makes the firmware abort its init.  A CLM blob must also be present:
   without one, WHD's first `country` ioctl fails and `whd_wifi_on()` never
   completes.  `zephyr/modules/hal_infineon/whd-expansion/CMakeLists.txt`
   learns to wire the 43438's CLM/NVRAM the same way it does for 4343W/43439
   (patch 0002; the mandatory firmware blob itself comes from
   `west blobs fetch hal_infineon`).

2. **The chip never asserts the in-band SDIO card interrupt.**  With the
   controller side fully armed (`SDMMC_MASK.SDIOITIE` set, CCCR
   `INTEN=0x7`, WLAN function ready, firmware downloaded, CLM accepted), the
   STM32 SDMMC's `SDMMC_STA.SDIOIT` stays clear — measured on hardware, with
   `SDIOITIE` confirmed set at the same moment.  WHD's thread only polls for
   received frames when it is woken *with the bus-interrupt flag set*
   (`whd_bus_sdio_use_status_report_scheme()` returns `WHD_FALSE` for this
   transport), so every ioctl was written to function 2 and then timed out
   without its reply ever being read (`iovar "cap" -> 101580800`, 5 s per
   ioctl, `airoc_wifi_init_primary failed ret = -19`).

   The workaround in [patches/0002](patches/0002-zephyr-airoc-whd-sdio-bring-up.patch)
   pokes `whd_thread_notify_irq()` from a 20 ms timer, which gives the thread
   the wake-up the interrupt would have delivered and lets it poll.  The
   thread is stopped again if `whd_wifi_on()` fails.

   Both ways of getting a real interrupt were tried on hardware and do not
   work here: the peripheral's `DCTRL.SDIOEN` ("SD I/O enable", the bit that
   makes DAT1 an interrupt line) still latches no `SDIOIT` **and** breaks
   4-bit transfers with a `Command response timeout` flood, and a 1-bit
   configuration behaves the same; an out-of-band host-wake on the
   schematic's `GPIO_WIFI_HOST_WAKE` net (PE3) produced no wake-up either.
   Polling is also what the board's vendor stack does — the ART-Pi SDK's
   `libraries/drivers/drv_sdio.c` never enables `SDMMC_MASK.SDIOITIE` at all.
   See [docs/adr/0003](docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md).

   The chip is also kept out of its low-power (KSO) sleep
   (`CONFIG_AIROC_WIFI_DISABLE_POWERSAVE`, on in `wifi.conf`): a sleeping
   device does not answer the first write that wakes it, and the host can only
   report that as a failed command.  Measurements:
   [docs/adr/0004](docs/adr/0004-keep-the-art-pi-wifi-chip-awake.md).

3. **The STA connect flow is the application's job**, exactly as in the
   ESP32-S3 sibling: `src/main.c` waits for the interface, issues
   `NET_REQUEST_WIFI_CONNECT` with the credentials from app Kconfig
   (`CONFIG_BROKER_WIFI_SSID` / `_PSK`, supplied through the git-ignored
   `local.conf`), retries every 30 s, then starts the DHCPv4 client and waits
   for `NET_EVENT_IPV4_DHCP_BOUND` before starting the broker.  The retries
   are **bounded** (3 attempts): a link that never associates must not keep
   the broker from starting, because then there is no broker log at all and
   the board looks dead — it starts anyway, prints
   `wifi: no association after 3 attempts ... starting the broker anyway`,
   starts the DHCP client too (so an address that turns up later is picked
   up), and leaves the association to a board reset — nothing retries it for
   you.  The Wi-Fi
   build passes [boards/art_pi_wifi.overlay](boards/art_pi_wifi.overlay) as
   an extra DTC overlay (`&mac`/`&mdio`/`&eth_phy` disabled) so the image has
   a single interface.

### Ethernet (optional; driver verified, link untested)

[eth.conf](eth.conf) builds the STM32 Ethernet MAC + LAN8720A PHY variant
instead of Wi-Fi (`CONFIG_ETH_STM32_HAL=y`, no Wi-Fi overlay).  Bring-up first
blamed the PHY for staying silent — MDIO scans found nothing and the driver
reported `PHY (0) ID FFFF` / `HAL_ETH_Init failed` — but that was with a
`reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>` override on `&eth_phy` (PA3 was
assumed to be the board's `ETH_RESET_PIN`).  With the override removed the MAC
initialises and no PHY error is logged; the interface comes up dormant,
waiting for carrier.

The bench has no Ethernet cable, so link-up, DHCP and traffic over Ethernet
have **not** been exercised.  Treat this variant as "the driver runs".

### USB-ECM (optional; firmware verified, blocked on the physical link)

[usb.conf](usb.conf) + [boards/art_pi_usb.overlay](boards/art_pi_usb.overlay)
build the board as a **USB device**: the USB-OTG port (PA11/PA12, the board's
already-enabled `zephyr_udc0`) presents a CDC-ECM Ethernet function, and
`src/main.c` makes the board the **DHCPv4 server** for that link (static
10.10.10.1/24, pool from .10) so the host's desktop configures the new
interface by itself — no `sudo`, no manual `ip(8)`.  The broker then listens
on that link exactly as it does over Wi-Fi.

The firmware side is verified: the controller initialises
(`HAL_PCD_Init`/`HAL_PCD_Start`), the ECM function registers, and the OTG core
reports itself powered and softly *connected* (`GCCFG.PWRDWN=1`,
`DCTL.SDIS=0`), with PA11/PA12 muxed to AF10 as Zephyr's own pinctrl defines.

What is missing is the link itself: **the host sees no USB device at all.**
On the bench PC, `journalctl -k` logs nothing — not even when the firmware
cycles the D+ pull-up, which every xHCI host reports if the port is
electrically connected.  So nothing is reaching the PC from this port; the
firmware is idle-waiting for a host that never appears.  Things worth trying
on the hardware side, in order:

* a different cable (charge-only cables carry no data), preferring a
  **USB-A → USB-C** cable over C-to-C: a Type-C receptacle wired for legacy
  devices needs 5.1 kΩ CC pulldowns, and a Type-C host port will not enable a
  port that does not present them;
* a different host port (directly on the machine, not through a hub/dock);
* confirming which ART-Pi connector is in use (`lsusb` should show a
  `2fe3:0100` device once it enumerates).

With the cable accepted, no further firmware work is needed: the host gets a
lease from the board and the broker is reachable at `10.10.10.1:1883` (MQTT),
`:8081` (REST, Basic auth) and `:8083/mqtt` (WebSocket) — the same
`tools/verify.sh 10.10.10.1` gates then apply.

## Environment / prerequisites

* A Zephyr ≥ 4.4 west workspace with its Python venv — `west` and `pyocd`
  live in that venv, not on the system `PATH`:
  ```sh
  source ~/zephyr-venv/bin/activate
  export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
  ```
  The Fedora setup guides are shared with the ESP32-S3 sibling:
  [English](../nanomq_zephyr_esp32s3/setup-fedora-en.md) /
  [简体中文](../nanomq_zephyr_esp32s3/setup-fedora-zh.md).

* **Apply the out-of-tree patches first.**  The demo needs three deltas
  outside this repository (the Zephyr tree and one west module); they are in
  [patches/](patches/), with the base revisions in
  [patches/README.md](patches/README.md).  In-repo work (the demo directory
  itself, the `nng` submodule's STM32 `SUCCESS` rename) travels on the
  branches instead.

* **Fetch the Infineon blobs once** — the 43438 firmware image is not in
  git, and without it `CONFIG_WIFI_AIROC` has no blob to embed:
  ```sh
  west blobs fetch hal_infineon     # accepts the Infineon licence
  ```

* **Vendor QSPI flash algorithm** — `tools/ART-Pi_W25Q64.FLM` is fetched from
  the ART-Pi SDK the same way (it is git-ignored, not redistributed):
  ```sh
  git clone --depth 1 --filter=blob:none --no-checkout \
      https://github.com/RT-Thread-Studio/sdk-bsp-stm32h750-realthread-artpi /tmp/artpi_sdk
  git -C /tmp/artpi_sdk show HEAD:debug/flm/ART-Pi_W25Q64.FLM \
      > demo/nanomq_zephyr_stm32_art-pi/tools/ART-Pi_W25Q64.FLM
  ```

* The board's ST-Link is `/dev/ttyACM0` for the console and the SWD probe; a
  udev rule for the probe is recommended.  `pyocd 0.45` needs the
  board-ID workaround described in
  [tools/artpi_flash.py](tools/artpi_flash.py) (already applied there).

## Build

```sh
west build -b art_pi demo/nanomq_zephyr_stm32_art-pi -- \
    -DEXTRA_CONF_FILE="local.conf;wifi.conf" \
    -DEXTRA_DTC_OVERLAY_FILE=boards/art_pi_wifi.overlay
```

`local.conf` is git-ignored; start from
[local.conf.example](local.conf.example).  Wi-Fi credentials live in
`CONFIG_BROKER_WIFI_SSID/PSK` (app Kconfig) and never land in the tree.
Without `-d`, `west build` uses `build/` **relative to the current
directory**; the helpers below default to
`build/nanomq_zephyr_stm32_art-pi` at the repository root.

## Flash

```sh
# build + program; Wi-Fi is the default variant (the one verified here)
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh

# ... or pick the network layer explicitly; --no-build programs the last build
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --wifi    # default
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --eth
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --usb
```

`--wifi` is the default on purpose: it is the only variant that reaches the
LAN without extra hardware.  `--eth` and `--usb` want a cable to a live far
end, so on a bench without one they come up and then sit at
`eth: still no link ...` / `usb: no carrier ...` forever — which looks like a
broken board but is just the wrong variant.

`tools/flash.sh` builds with `local.conf` plus the variant's conf file and
overlay, then runs
[tools/artpi_flash.py](tools/artpi_flash.py), which loads the vendor's CMSIS
flash algorithm (`ART-Pi_W25Q64.FLM`) into SRAM4, resets the target (the
loader assumes fresh clocks/caches/peripherals) and programs the ELF's load
segments into the QSPI window at 0x90000000 over SWD.  Only the sectors the
image covers are erased.  It resets and resumes the target once more at the
end, because pyocd leaves the core halted after programming — without that
the image would only start at the next power cycle.

The first flash overwrites the factory RT-Thread application in QSPI slot0
(rebuildable from `projects/art_pi_factory` in the ART-Pi SDK).  The factory
*bootloader* in internal flash is untouched, and it is what prints the
`Powered by RT-Thread.` logo before jumping to the image — that banner is the
bootloader's, not a sign that the demo did not start.

## Console and boot log

The console is the ST-Link's virtual COM port: 115200 8N1 on `/dev/ttyACM0`,
no login, just the boot log and everything the broker prints.  It is the
board's only window into a bring-up, so this is the first thing to open after
flashing.

### Open or capture it

```sh
# live view (Ctrl-C to quit)
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh

# capture to a file while still showing it
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o /tmp/boot.log

# ... throwing away the port's backlog first (see "Telling boots apart")
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o /tmp/boot.log --drain 10
```

Any 115200 8N1 terminal does the same — `tio /dev/ttyACM0`,
`picocom -b 115200 /dev/ttyACM0`, `minicom -D /dev/ttyACM0` — and a plain
capture is:

```sh
stty -F /dev/ttyACM0 115200 raw -echo      # 8N1, no flow control, no echo
cat /dev/ttyACM0 | tee /tmp/boot.log       # Ctrl-C to stop
```

`tools/flash.sh` leaves the board reset and running when it exits, so the
boot log is on the wire immediately — start the capture first if you want it
from the first line.  Only one reader at a time: a second `cat`/`minicom`
splits the stream between them and both look truncated.

### What a good boot looks like

Wi-Fi build (`local.conf;wifi.conf` + `boards/art_pi_wifi.overlay`), captured
straight after a re-flash:

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

* `Powered by RT-Thread.` / `msh >` — the **ART-Pi factory bootloader**'s own
  banner, printed before it maps the QSPI and jumps to the demo.  It is not
  the demo failing to start, and not RT-Thread running the broker.
* `sdhc_stm32: SDHC Init Passed Successfully`, then
  `sd: Card does not support CMD8` — the SDIO host is up and the Wi-Fi card is
  enumerated as a legacy (SDIO, not SD) card.  `Card does not support CMD8` is
  normal here.
* `WLAN MAC Address`, `WLAN Firmware`, `WLAN CLM`, `WHD VERSION` — raw
  `printf` output from Infineon's WHD as it talks to the chip.  The MAC is this
  board's AP6212; the firmware/CLM versions are the resources the demo loaded
  (hardware section above).  These lines appear *before* the Zephyr banner
  because raw `printf` does not go through the log subsystem the banner uses —
  that ordering is cosmetic.
* `*** Booting Zephyr OS build v4.4.0-4779-g11a87708d415 ***` — the demo
  itself, i.e. the point where `main()` starts doing work.
* `wifi: connecting to "<SSID>"` → `wifi: connected` →
  `wifi: IPv4 address assigned (DHCPv4)` — `src/main.c`'s STA flow.
* `net_ipv6_nd: DAD failed, no ll IPv6 address!` is an **error-severity log
  that is expected**: IPv6 is enabled in the net stack but this link has no
  IPv6, so duplicate-address detection has nothing to work on.  The broker uses
  IPv4.
* `NanoMQ Broker is started successfully!` plus the two `broker:`/`web_server:`
  lines — the REST listener is on `:8081`, MQTT on `:1883`, WebSocket on
  `:8083/mqtt`.
* `net: ipv4 192.168.x.y` — the address `tools/verify.sh` wants.
* Then, once a minute: `broker: status running — uptime 64s, MQTT
  tcp://0.0.0.0:1883, REST http://0.0.0.0:8081, WS :8083/mqtt, ipv4
  192.168.1.3`.  **The broker's startup block above is printed once**, so a
  console opened later never shows it — this heartbeat is the answer to "is it
  up, and on which address?" at any time
  (`CONFIG_BROKER_STATUS_INTERVAL_S`, default 60 s, `0` silences it).
  `curl -u <user>:<pass> http://<ip>:8081/api/v4/brokers` answers the same
  question without the console.

The same shape applies to the other variants: the Ethernet build shows
`eth: waiting for link` / `net_dhcpv4: Received: ...` instead of the `wifi:`
lines, and the USB-ECM build shows `usb: carrier up` / `usb: DHCPv4 server
started` (see the variant sections above).

Timestamps: the board has no battery-backed RTC, so nanolib's wall-clock
timestamps start at the 1970 epoch unless `CONFIG_BROKER_SNTP` is enabled
(`local.conf.example`), which seeds `CLOCK_REALTIME` from a public NTP server
once DHCP has bound.  Zephyr's own `<inf>`/`<err>` lines carry the kernel's
uptime instead.  Zephyr has no timezone database, so displayed times are UTC.

### Telling boots apart, and other console quirks

* **The port buffers, so a capture can replay the *previous* boot.** The
  ST-Link's VCP holds the last output in its buffer; a capture started just
  after a reset often begins with the tail of the boot before it, which is why
  you can see two `Powered by RT-Thread.` banners and two
  `*** Booting Zephyr OS ... ***` lines in one log.  That is not a reboot
  loop — split the log on the **last** banner, or use
  `tools/console.sh --drain <seconds>`.
* **`--- N messages dropped ---`** between lines means the Zephyr log buffer
  overflowed because the console (115200) cannot keep up — it happens when
  something is printing in a loop (see below).  Data is not affected.
* **A silent console right after flashing** usually means the core was left
  halted, not that the image is bad: pyocd leaves the target halted when its
  programmer finishes, which is why `tools/artpi_flash.py` resets *and resumes*
  once more at the end.  If you flash some other way, reset the board.
* **`sdhc_stm32: Command response timeout`, repeating**, used to start ~50 s
  after association and never stop.  It was the Wi-Fi chip's own low-power
  (KSO) sleep, and it is fixed: while asleep the device deliberately does not
  answer the first write that wakes it (WHD's source says so and ignores the
  error), and a host controller can only report that silence as a failed
  command — ~300 of them a second.  The demo now keeps the chip awake
  (`CONFIG_AIROC_WIFI_DISABLE_POWERSAVE`), so those messages do not appear at
  all; the driver also rate-limits them, so a *real* burst still looks like
  this rather than a wall of text:

  ```
  [00:04:11.518,000] <err> sdhc_stm32: Skipped 1621 messages
  [00:04:11.518,000] <err> sdhc_stm32: Command response timeout
  ```

  The measurements and the decision are in
  [docs/adr/0004](docs/adr/0004-keep-the-art-pi-wifi-chip-awake.md).  A side
  effect worth knowing from that episode: **`ping` can fail while TCP still
  works** in a degraded link state, so judge the broker with
  `tools/verify.sh <ip>` (or `curl` on `:8081`), not with `ping`.
* **Which variant is on the board?**  The log says so without ambiguity:
  `wifi: connecting to "<SSID>"` / `wifi: connected` is the Wi-Fi build,
  `eth: waiting for link` / `net: iface ... dev=ethernet@40028000` is the
  Ethernet one, `usb: starting the device stack (CDC-ECM)` is USB-ECM.
  Re-flash with `tools/flash.sh --wifi` if you are looking at the wrong one.

## Verify

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/verify.sh <board-ip>
```

That runs the three acceptance gates of
[demo/nanomq_zephyr_qemu_x86/function_test.py](../nanomq_zephyr_qemu_x86/function_test.py)
against the board (`--no-manage`, so the suite does not try to start qemu).
Add `--full` for the WebSocket and capacity/robustness groups.

The suite tunes itself to the hardware: it measures the TCP round trip and,
for any non-loopback address, defaults to `--time-scale 4 --retry 2` —
needed because the CI scripts' sleeps assume localhost and two of their
subtests are racy by construction.  On this bench the measured RTT is
~30–100 ms, so the stretched scale and the retry are what make `mqtt_v5`
stable.  It is not a guarantee: one run on a congested link (RTT ~200 ms,
roughly 3× the usual) exhausted both retries on `mqtt_v5`; an immediate
re-run passed.  Re-run before investigating a `mqtt_v5`-only failure.

### Verified on hardware (bring-up record, 2026-09-27)

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

Runs of the same gates on the earlier, instrumented build passed too
(`mqtt_v5` took 235.8 s there, after one `retain-as-published` retry — that
subtest is racy by construction on this bench and the suite retries it).

The **full** group set (adding the two WebSocket groups and the robustness
ones) passes as well:

```
broker connect RTT 19.3 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311 PASS 64.1s   mqtt_v5 PASS 118.2s   rest_get PASS 1.1s
ws_v311   PASS 260.5s  ws_v5   PASS 7.7s     capacity PASS 7.5s
ws_abort  PASS 11.5s
RESULT: pass=7 fail=0
```

`webhook_smoke` is the one group that has not been exercised: the demo builds
with the forwarder off by default, and a build with `CONFIG_BROKER_WEBHOOK=y`
wedges the SDIO link (see the limitations below).

Wi-Fi link: WPA2 AP on 2.4 GHz, MAC `70:4A:0E:51:77:9A`, firmware
`7.45.98.117`, WHD `3.3.3.26653`, DHCPv4 lease `192.168.1.3`; MQTT :1883,
REST :8081 and WebSocket :8083 all listening (REST
`/api/v4/brokers` → `node_status: Running`, `version 0.25.6-8`).

## Configuration files

| File | Purpose |
| --- | --- |
| [prj.conf](prj.conf) | The demo: POSIX API budget, net pools, SDRAM heap, REST + WebSocket listeners. |
| [wifi.conf](wifi.conf) | Wi-Fi build: AIROC/WHD + SDMMC2 host + Zephyr's Wi-Fi mgmt API, and the 43438 resource selection.  Pair with `boards/art_pi_wifi.overlay`. |
| [eth.conf](eth.conf) | Ethernet variant (no Wi-Fi overlay).  Unverified here; see above. |
| [usb.conf](usb.conf) | USB-ECM variant (board is the USB device and the DHCP server for that link).  Pair with `boards/art_pi_usb.overlay`; see above. |
| [boards/art_pi.overlay](boards/art_pi.overlay) | QSPI XIP, LTDC off, SDMMC2 + `airoc-wifi` node, PHY reset line. |
| [boards/art_pi_wifi.overlay](boards/art_pi_wifi.overlay) | Wi-Fi builds: drops `&mac`/`&mdio`/`&eth_phy` so the image has one interface. |
| [boards/art_pi_usb.overlay](boards/art_pi_usb.overlay) | USB-ECM builds: drops `&sdmmc2`, `&mac`, `&mdio` and `&eth_phy` so the ECM interface is the only one. |
| [local.conf.example](local.conf.example) | Copy to `local.conf`: REST credentials, Wi-Fi SSID/PSK, optional webhook/SNTP/DEBUG. |
| [wifi_dbg.conf](wifi_dbg.conf) | Diagnostic: Zephyr DEBUG logging + WHD tracing, for SDIO bring-up. |
| [wifi_whddbg.conf](wifi_whddbg.conf) | Diagnostic: WHD tracing only (`WPRINT_ENABLE_WHD_DEBUG`), including the post-download verification of the firmware/CLM transfer. |
| [wifi_crash.conf](wifi_crash.conf) | Diagnostic: immediate logging and no reset on fatal error, to inspect a faulted core. |

## Known limitations / next steps

* Wi-Fi interrupts are polled rather than delivered
  (`CONFIG_AIROC_WIFI_WHD_POKE`, enabled in `wifi.conf`).  Both the in-band
  controller path and the out-of-band host-wake pin were tried and do not
  work on this board; the vendor stack polls too.  See
  [docs/adr/0003](docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md).
* The Wi-Fi chip's low-power sleep used to flood the console with
  `sdhc_stm32: Command response timeout` from ~50 s after association; it is
  root-caused and fixed by keeping the chip awake
  ([docs/adr/0004](docs/adr/0004-keep-the-art-pi-wifi-chip-awake.md)), and the
  driver rate-limits the message in case a real one appears.  If it ever does
  reappear in bulk, `CONFIG_AIROC_WIFI_DISABLE_POWERSAVE` is the first thing
  to check.
* **Webhook is left off, and cannot simply be switched on**: a build with
  `CONFIG_BROKER_WEBHOOK=y` joins Wi-Fi and leases an address, but the SDIO
  link then wedges almost immediately (the same `Command response timeout`
  flood), so the `webhook_smoke` group could not be brought up on this
  build.  Internal SRAM is at ~88 % in that configuration and the forwarder
  needs more room; make room in the SRAM budget (or move a pool) before
  enabling it.  `prj.conf` therefore keeps it off.
* The CLM in use is the AW-CU427-P module's — the only one published for this
  part.  The link works and the chip accepts it, but it is not this module's
  calibration data.
* Internal SRAM is at 86 % in the Wi-Fi build; there is little headroom for
  more concurrent connections.
* The Ethernet variant is unverified (PHY silent on the bring-up unit).
* `CONFIG_BROKER_WEBHOOK` is off by default (see above), so the webhook group
  of the suite reports SKIP unless a build with room for it is made.  See the
  ESP32-S3 README for the trade-offs.

## References

* [docs/en_US/port-to-art-pi.md](docs/en_US/port-to-art-pi.md) /
  [docs/zh_CN/port-to-art-pi.md](docs/zh_CN/port-to-art-pi.md) — the porting
  record: what differs from the ESP32-S3 sibling, in what order the traps
  appeared, and the evidence for each.
* [docs/adr/](docs/adr/) — the decision records: QSPI XIP, the SDRAM heap, why
  Wi-Fi polls instead of being interrupted, and why the Wi-Fi chip is kept
  awake.
* [../nanomq_zephyr_esp32s3/README.md](../nanomq_zephyr_esp32s3/README.md) —
  the sibling this demo is derived from (PSRAM, ESP-IDF tooling, webhook).
* [../../docs/en_US/tutorial/port-to-zephyr.md](../../docs/en_US/tutorial/port-to-zephyr.md)
  — the general Zephyr port tutorial.
* [docs/CONTEXT.md](docs/CONTEXT.md) — the vocabulary used in these docs
  (Zephyr broker demo, ART-Pi factory bootloader, broker heap, …).
