# NanoMQ on Zephyr RTOS: Running an MQTT Broker Directly on an MCU

## Introduction

MQTT and Zephyr are most often used together on the client side: a Zephyr-based device acts as an MQTT client and connects to a remote broker. **But what if the broker itself could run directly on the MCU?**

This approach can be useful in edge scenarios where a dedicated Linux gateway adds unnecessary complexity. For example, dozens of field devices may communicate over Modbus, serial interfaces, or proprietary protocols and need to be consolidated into MQTT. In other cases, an unreliable network may require data to be buffered locally and uploaded after the connection is restored. The conventional solution is to deploy a Linux gateway alongside the devices, but the additional power, maintenance, and physical protection can be costly. Running the broker directly on an MCU can eliminate this extra layer.

[NanoMQ](https://nanomq.io/) is an open-source edge MQTT broker from EMQ, originally designed for Linux and other POSIX environments. This article explores what it takes to run the NanoMQ broker core on Zephyr RTOS. The application layer uses the same `nanomq/` source code and NanoNNG MQTT protocol stack without feature trimming. Peripheral capabilities are disabled or remain unverified where required by the constraints of the Zephyr platform; see [Appendix A](#appendix-a-differences-from-general-nanomq) for the complete list of differences and limitations.

The repository includes two demos: one running on real ESP32-S3 hardware and the other in a `qemu_x86` simulation environment. See [Appendix B](#appendix-b-comparing-the-two-demos) for a comparison of the two demos and guidance on choosing between them.

The rest of this article walks through the environment setup, build and deployment process, functional testing, and the porting process itself, including the framework-level issues encountered along the way.

## About Zephyr

Zephyr is an open-source real-time operating system (RTOS) hosted by the Linux Foundation and designed for resource-constrained embedded devices.

Four Zephyr features are particularly relevant to this port:

- **Configurable and scalable.** System features are enabled through Kconfig options, allowing a minimal configuration to fit into tens of kilobytes. This makes the same codebase suitable for devices ranging from simple sensor nodes to edge gateways.
- **Hardware described through devicetree.** Board-specific differences are defined through devicetree and board overlays, keeping application code independent of the underlying hardware. This is what allows the port to build the same application source for both `qemu_x86` and ESP32-S3.
- **Built-in networking stack.** Zephyr provides TCP/IP, a BSD-compatible socket layer, and TLS. The NanoNNG Zephyr platform adaptation layer is built on top of this socket API.
- **POSIX API subset.** Zephyr provides `CONFIG_POSIX_API` support for interfaces such as pthreads and file descriptors, making it possible to port middleware originally designed for POSIX environments.

This article is based on Zephyr 4.4 (`11a87708d41`).

## About NanoMQ

[NanoMQ](https://nanomq.io/) is an open-source MQTT broker from EMQ and a project under LF Edge. It is designed as an ultra-lightweight, high-performance MQTT broker for IoT edge environments. Unlike EMQX, which targets cloud deployments, NanoMQ is designed for embedded systems and industrial field sites.

### Architecture

NanoMQ uses a layered architecture:

- **Platform adaptation layer:** Detects the underlying hardware and operating system and provides a portable API to the layers above, avoiding platform-specific dependencies. This is the foundation for adding Zephyr support through a new platform adaptation layer.
- **Task layer:** Uses an Actor model and thread-level parallelism, with support for scaling across SMP systems.
- **Transport layer:** Manages TCP and UDP streams through pipes and clients, using zero-copy mechanisms to reduce memory usage.
- **Protocol layer:** Parses byte streams into MQTT packets, generates events, and manages the in-flight window.
- **Application layer:** Integrates the rule engine and global topic tree, exposing MQTT messages and events through a lock-free state machine.

### Implementation

NanoMQ is implemented entirely in C and has no external runtime dependencies, making it suitable for cross-compilation to a wide range of target boards.

Its asynchronous I/O and Actor architecture are built on the NNG fork ([NanoNNG](https://github.com/nanomq/NanoNNG)) maintained by the NanoMQ team, which is extended with MQTT protocol support and the `nanolib` utility library.

At the protocol level, NanoMQ fully supports MQTT 3.1.1, MQTT 3.1, and MQTT 5.0, including QoS 0/1/2, retained messages, Last Will messages, shared subscriptions, topic aliases, and other MQTT features.

## Environment Setup

### Prerequisites

You will need the following:

- A Zephyr 4.4+ west workspace, together with its Python virtual environment. **Both `west` itself and Zephyr's Python dependencies are installed in this venv.** Its location is up to you: the official Zephyr documentation uses `.venv/` at the workspace root, while the environment used for validation in this article uses `~/zephyr-venv`. Once activated, `west` is on `PATH`:

  ```sh
  source <venv>/bin/activate                   # ~/zephyr-venv in this article
  export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
  ```

- Zephyr SDK 1.0.x. Download and extract the SDK separately, then set `ZEPHYR_SDK_INSTALL_DIR` to its installation directory.
- For the ESP32-S3 hardware demo, an **ESP-IDF** environment (see the next section). This is not required if you only build `qemu_x86`.
- For functional testing, additional Python dependencies and the Mosquitto client, as described in the Functional Testing section.

The versions used for validation are fixed as follows. The e1000 patch is specific to the corresponding Zephyr source revision and must be revalidated if you upgrade Zephyr.

| Component | Version / Commit |
| --- | --- |
| Zephyr | 4.4, `11a87708d41` (the e1000 patch applies to this revision) |
| Zephyr SDK | 1.0.1 |
| NanoMQ | 0.25.6 (based on upstream `master`) |
| NanoNNG (`nng/` submodule) | Based on upstream `main`, plus the Zephyr platform adaptation layer. The `zephyr-rtos` branch commits the submodule gitlink, so `git clone --recursive` checks out the complete platform adaptation layer |

If you have not created a Zephyr workspace yet (the commands below put the venv at `~/zephyr-venv`, which is where the validation environment for this article keeps it; putting it elsewhere, or at `<workspace>/.venv` as the official documentation suggests, works just as well):

```sh
python3 -m venv ~/zephyr-venv
source ~/zephyr-venv/bin/activate
pip install west

west init ~/zephyrproject
cd ~/zephyrproject
west update
pip install -r zephyr/scripts/requirements.txt
```

### ESP32-S3 Development Environment

**This section applies only to the ESP32-S3 hardware demo. If you only build `qemu_x86`, skip it and use the standard Zephyr environment from the previous section.** The hardware demo needs Espressif's HAL blobs and the flashing and serial tools, but **the cross-compiler still comes from the Zephyr SDK**: 1.0.1 already includes the `xtensa-espressif_esp32s3_zephyr-elf` toolchain required by this target, and ESP-IDF plays no part in compilation.

**1. Get ESP-IDF** (it provides `west`, `esptool`, and `idf-monitor`). Either installation method works:

```sh
# a) Clone from git
git clone --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf
cd ~/esp/esp-idf && ./install.sh esp32s3
#    the activation script is ~/esp/esp-idf/export.sh

# b) Install with the ESP-IDF Installation Manager (eim)
#    the activation script is ~/.espressif/tools/activate_idf_v<version>.sh
```

**2. Activate the environment before each build** and point `ZEPHYR_SDK_INSTALL_DIR` to the Zephyr SDK.

The validation environment for this article turns this into an alias in `~/.bashrc`:

```sh
alias esp-zephyr='source ~/.espressif/tools/activate_idf_v6.1.sh \
    && export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1'
```

Run `esp-zephyr` before each build. Expanded, it is:

```sh
source ~/.espressif/tools/activate_idf_v6.1.sh   # ~/esp/esp-idf/export.sh if installed from git
export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
```

**Activating this environment replaces the Zephyr venv from the previous section**: ESP-IDF's Python environment ships its own `west` (and `python3`), and activating one of the two is enough — whichever is activated last wins. Use this one to build for ESP32 targets; use the Zephyr venv from the previous section to build for `qemu_x86` only, without installing ESP-IDF.

Activating ESP-IDF is independent of which compiler is used. It only puts `west`, `esptool` (which the ESP32 runner of `west flash` invokes), and `idf-monitor` on `PATH`. The compiler is selected by `ZEPHYR_SDK_INSTALL_DIR` and `ZEPHYR_TOOLCHAIN_VARIANT=zephyr`, the latter pointing to the matching Xtensa toolchain in the Zephyr SDK. **Do not** set it to `espressif`: that variant has been removed from the current Zephyr release and causes CMake to look for files that do not exist in the source tree. You can also omit `ZEPHYR_TOOLCHAIN_VARIANT` entirely, since Zephyr locates the Zephyr SDK on its own, but setting it explicitly is less error-prone.

**3. Fetch the Espressif HAL blobs** once from the workspace:

```sh
cd ~/zephyrproject
west blobs fetch hal_espressif
```

**Do not skip this step.** Without the blobs, `CONFIG_WIFI_ESP32` silently becomes unavailable. The build still succeeds and the firmware still boots, but Wi-Fi is not available, and the build system reports no warning. On the serial console, the expected `wifi: connected` message will never appear.

For distribution-specific setup instructions (including system dependencies, SDK installation, permissions, and common errors), see [setup-fedora-en.md](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_esp32s3/setup-fedora-en.md). The guide uses Fedora as an example; for other distributions, replace the package manager commands as needed.

### Get the Source Code

```sh
cd ~/zephyrproject
git clone --recursive -b zephyr-rtos https://github.com/nanomq/nanomq.git
cd nanomq
```

The `--recursive` option also fetches the `nng/` submodule, which contains the NanoNNG branch with the Zephyr platform adaptation layer. The `zephyr-rtos` branch commits the submodule's gitlink in the repository, so the checkout matches the commit listed in the table above. `git clone --recursive` always checks out the gitlink recorded by the repository; switching commits requires an explicit checkout.

If you cloned the repository without `--recursive`, initialize the submodules with:

```sh
git submodule update --init --recursive
```

After cloning, verify the submodule with `git submodule status nng`: if the output **does not start with `-` or `+`**, the submodule has been checked out at the gitlink recorded by the repository (`-` means it has not been initialized, `+` means the checked-out commit differs from the recorded one).

All subsequent commands in this article are run from the repository root (`~/zephyrproject/nanomq`).

### qemu_x86: Zephyr e1000 Driver Patch

The `qemu_x86` demo requires a two-line patch to the Zephyr e1000 driver. **This patch is required.** Without it, the broker starts normally and prints `NanoMQ Broker is started successfully!`. However, no client can establish a connection.

The issue is caused by the QEMU e1000 device model clearing the RCTL register during reset, including **RCTL_BAM** (Broadcast Accept Mode, bit 15) — real hardware sets this bit by default, but the device model does not.

Zephyr's `eth_e1000` driver writes only `RCTL_EN | RCTL_MPE` and never sets BAM. As a result, **all broadcast frames are silently dropped by the device model**. ARP resolution therefore fails, preventing SLIRP from delivering the initial TCP connection. This issue remains present in upstream Zephyr as of 4.4 (`11a87708d41`).

The patch must be applied to the **Zephyr source tree itself** (the `zephyr/` directory in the workspace, not this repository).

Save the following diff as `zephyr-e1000-bam.patch` and apply it with:

```sh
cd ~/zephyrproject/zephyr
git apply /path/to/zephyr-e1000-bam.patch
```

```diff
diff --git a/drivers/ethernet/eth_e1000.c b/drivers/ethernet/eth_e1000.c
--- a/drivers/ethernet/eth_e1000.c
+++ b/drivers/ethernet/eth_e1000.c
@@ -329,7 +329,7 @@ static const struct ethernet_api e1000_api = {
 									\
 		irq_enable(DT_INST_IRQN(inst));				\
 		iow32(dev, CTRL, CTRL_SLU); /* Set link up */		\
-		iow32(dev, RCTL, RCTL_EN | RCTL_MPE | DT_INST_PROP(inst, rdmts) << RDMTS_OFFSET); \
+		iow32(dev, RCTL, RCTL_EN | RCTL_MPE | RCTL_BAM | DT_INST_PROP(inst, rdmts) << RDMTS_OFFSET); \
 		iow32(dev, ITR, DT_INST_PROP(inst, itr) & (uint32_t)GENMASK(15, 0)); \
 	}								\
 									\
diff --git a/drivers/ethernet/eth_e1000_priv.h b/drivers/ethernet/eth_e1000_priv.h
--- a/drivers/ethernet/eth_e1000_priv.h
+++ b/drivers/ethernet/eth_e1000_priv.h
@@ -27,6 +27,7 @@ extern "C" {
 #define IMS_RXT0	(1 << 7) /* Receiver Timer */
 
 #define RCTL_MPE	(1 << 4) /* Multicast Promiscuous Enabled */
+#define RCTL_BAM	(1 << 15) /* Broadcast Accept Mode */
 
 #define TDESC_EOP	     (1) /* End Of Packet */
 #define TDESC_RS	(1 << 3) /* Report Status */
```

Note that `RCTL_MPE` means **Multicast** Promiscuous Enabled (bit 4) and only affects multicast reception. It does not enable broadcast reception, so the driver's existing setting cannot substitute for BAM. This distinction is why the issue went unnoticed for so long.

This patch only affects the emulated QEMU network adapter. **It is not required for the ESP32-S3 hardware demo.**

### Ports and Services

With the configurations validated in this article, both demos expose the same MQTT, REST, and WebSocket ports. For `qemu_x86`, actual reachability depends on the port-forwarding configuration described in the next section.

| Service | Port | ESP32-S3 | qemu_x86 | Authentication / Encryption |
| --- | --- | --- | --- | --- |
| MQTT over TCP | 1883 | Supported | Supported | No authentication, no TLS |
| REST API | 8081 | Supported | Supported | Basic authentication; credentials must be configured by you (there is no usable default), no TLS |
| MQTT over WebSocket | 8083 | Supported | Supported | No authentication, no TLS; path `/mqtt` |

The REST listener is enabled through the Kconfig option `CONFIG_BROKER_REST_API`: `main.c` uses it to set `http_server.enable` and `auth_type`, while the default value in `conf_init` is disabled. **This switch alone is not enough, however** — `CONFIG_BROKER_REST_USER` / `CONFIG_BROKER_REST_PASS` both default to the empty string, which is to say there are no usable default credentials, and the publicly known upstream credentials `admin` / `public` are rejected as well. Only when both are set to credentials of your own does anything listen on 8081; otherwise the broker prints an explanatory line at startup and leaves the port closed. If you remove this switch from the configuration yourself, nothing will listen on port 8081 either, and clients will receive an RST. That is expected behavior rather than a failure.

### Security Considerations

The default configuration of both demos assumes a **controlled experimental environment**. Deploying it unchanged introduces security risks.

| Item | Current Configuration |
| --- | --- |
| Listening addresses | MQTT `nmq-tcp://0.0.0.0:1883`, WebSocket `nmq-ws://0.0.0.0:8083/mqtt`, and REST `0.0.0.0:8081` all listen on all network interfaces |
| REST authentication | Basic authentication; credentials come from the Kconfig options `CONFIG_BROKER_REST_USER` / `_PASS`, both of which **default to the empty string (there are no usable default credentials)** — when they are unset, or still set to the publicly known upstream `admin` / `public`, nothing listens on 8081 |
| MQTT authentication | Disabled; any client can connect, publish, and subscribe |
| Transport encryption | None. TLS is not enabled in the NanoNNG Zephyr port, so MQTT, WebSocket, and REST traffic is sent in plaintext |

**Basic authentication over plaintext HTTP is only Base64 encoding, not encryption.** Credentials can therefore be recovered by an observer on the same network path. It can prevent accidental access, but not a deliberate attack. Real access control still depends on the network boundary.

Before using the demo outside an experimental network, at minimum: restrict the listening addresses to the specific network interfaces you need, set your own REST credentials (the published `admin` / `public` pair is now refused), and place the management interface behind a trusted network or an additional TLS proxy. As for MQTT authentication: if the authentication path of this port has been verified, it can be enabled directly; otherwise, enforce access control at the link layer or at a TLS proxy. **Do not assume that the authentication settings of the general NanoMQ distribution can be applied directly to the embedded configuration used by these demos** (the configuration sources differ; see [Appendix A](#appendix-a-differences-from-general-nanomq)). **Do not expose the demo's default configuration to the public Internet or an untrusted network.**

## Build and Run: ESP32-S3 Hardware Demo

### 1. Configure Local Credentials (Wi-Fi and REST)

Copy `local.conf.example` to `local.conf`. The file is already listed in `.gitignore`, so your credentials will not be committed to the repository.

```sh
cp demo/nanomq_zephyr_esp32s3/local.conf.example \
   demo/nanomq_zephyr_esp32s3/local.conf
```

Edit `demo/nanomq_zephyr_esp32s3/local.conf` and fill in the SSID and PSK:

```conf
CONFIG_BROKER_WIFI_SSID="your-ssid"
CONFIG_BROKER_WIFI_PSK="your-passphrase"

# prj.conf already enables CONFIG_BROKER_REST_API, but 8081 only starts
# listening once these two are set (and are not the public admin/public);
# leaving them unset means the port stays closed.
CONFIG_BROKER_REST_USER="your-rest-user"
CONFIG_BROKER_REST_PASS="your-rest-passphrase"
```

### 2. Build

`EXTRA_CONF_FILE` is resolved relative to the application directory:

```sh
west build -b esp32s3_devkitc/esp32s3/procpu -d build/esp32s3_nanomq \
    demo/nanomq_zephyr_esp32s3 -- -DEXTRA_CONF_FILE=local.conf
```

For the configuration validated in this article, with MQTT, REST, and WebSocket enabled, a successful build produces the following memory report:

```
Memory region         Used Size  Region Size  %age Used
           FLASH:      961204 B   16776960 B      5.73%
     iram0_0_seg:       54028 B     415492 B     13.00%
     dram0_0_seg:      379640 B     399108 B     95.12%
     irom0_0_seg:      686320 B        32 MB      2.05%
     drom0_0_seg:      830132 B        32 MB      2.47%
    ext_dram_seg:     5152752 B        32 MB     15.36%
...
Successfully created ESP32-S3 image.
```

Two figures are particularly important here:

- `dram0_0_seg`, which represents internal SRAM, is already **95.12% utilized**. This is the most constrained memory region and is why the broker heap and static pools are moved to PSRAM;
- `ext_dram_seg` reports **5,152,752 B (≈5.2 MB)**, which is the amount **placed in external PSRAM**, or 15.36% of that region. The relationship between this figure, the region's 32 MB size, and the module's 16 MB capacity is explained in [About the Development Board](#about-the-development-board) below.

### 3. Flash the Firmware

Connect the development board to the host computer over USB. Depending on whether the board uses an onboard USB-UART bridge or the ESP32-S3's native USB-JTAG/Serial interface, the device may appear as either:

- `/dev/ttyUSB*` — a separate USB-UART bridge such as CP2102 or CH34x
- `/dev/ttyACM*` — native USB CDC, including the ESP32-S3 USB-JTAG/Serial interface

This article uses `/dev/ttyUSB0` as an example. Check the actual device name on your system:

```sh
ls /dev/ttyUSB* /dev/ttyACM*
# Or check which device node appears when you connect the board
dmesg | tail -5
```

If flashing fails because of insufficient permissions, add the current user to the group that owns the device, then log in again for the change to take effect:

```sh
ls -l /dev/ttyUSB0                 # The fourth column shows the group
sudo usermod -aG <group> "$USER"
```

The group is typically `dialout` on Debian/Ubuntu and Fedora, and `uucp` on Arch. Always use the group reported by `ls -l` rather than assuming the distribution-specific default.

Then flash the firmware, replacing `/dev/ttyUSB0` with the actual device name:

```sh
west flash -d build/esp32s3_nanomq --runner esp32 --esp-device /dev/ttyUSB0
```

### 4. Monitor the Serial Console

The baud rate is 115200. You can use `idf-monitor` or `miniterm`. Passing the ELF file to `idf-monitor` enables binary log decoding:

```sh
idf-monitor --port /dev/ttyUSB0 build/esp32s3_nanomq/zephyr/zephyr.elf
```

A sample boot log from an actual run is shown below. Path prefixes are omitted, and the SSID is replaced with a placeholder:

```
I (octal_psram): vendor id    : 0x0d (AP)
I (octal_psram): density      : 0x05 (128 Mbit)
I (esp_psram): Found 16MB PSRAM device
I (esp_psram): Speed: 80MHz
I (esp_psram): SPI SRAM memory test OK
*** Booting Zephyr OS build v4.4.0-4779-g11a87708d415 ***
wifi: connecting to "<your-ssid>" (attempt 1)
wifi: connected to "<your-ssid>"
wifi: connected — starting DHCPv4 client
wifi: IPv4 address assigned (DHCPv4)
sntp: ntp.aliyun.com: epoch=1789468030, realtime seeded
net: iface 0x3fc96fd8 dev=wifi up=1
net: ipv4 <board-ip>
2026-09-15 10:27:10 [0] INFO  web_server.c:548 start_rest_server: http://0.0.0.0:8081/api/v4
2026-09-15 10:27:10 [0] WARN  broker.c:1400 broker: NanoMQ (ver 0.25.6) Serving HTTP Server on http://(null):8081
NanoMQ Broker is started successfully!
```

The `start_rest_server` and `Serving HTTP Server` lines appear only when REST credentials were configured at build time (the `local.conf` from step 1). Without them, this spot shows a single `rest: REST API stays off - ...` line instead, and nothing listens on 8081.

The startup sequence is: **PSRAM detection and memory test → Zephyr startup → Wi-Fi association → DHCP address assignment → SNTP time seeding → broker initialization.** The broker is ready when the final line appears: `NanoMQ Broker is started successfully!`.

### 5. Verify the Connection

Once the broker is ready, run the following checks from a host on the same network. Test the REST API (the credentials are the pair you set in `local.conf`; if you did not set them, nothing listens on 8081 and curl will simply fail to connect, which is expected):

```sh
curl -u <rest-user>:<rest-pass> http://<board-ip>:8081/api/v4/brokers/
```

To test MQTT messaging, subscribe with the Mosquitto client from any terminal:

```sh
mosquitto_sub -h <board-ip> -t 'test/#' -v
```

In another terminal, publish a message:

```sh
mosquitto_pub -h <board-ip> -t 'test/hello' -m 'hello from mosquitto' -q 1
```

The subscriber should receive: `test/hello hello from mosquitto`

### About the Development Board

The demo was validated on the [ESP32-S3-LCD-EV-Board](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-lcd-ev-board/user_guide.html#esp32-s3-lcd-ev-board-v1-5), using an ESP32-S3-WROOM-1-**N16R16V** module (16 MB flash and 16 MB **octal** PSRAM). The board configuration uses the same SoC definition as `esp32s3_devkitc/esp32s3/procpu`. Differences in the module configuration are expressed in two places: `boards/esp32s3_devkitc_procpu.overlay` (flash and PSRAM capacity) and `CONFIG_SPIRAM_MODE_OCT` in `prj.conf` (octal mode). **If your module is not N16R16V, both must be changed.** Octal and quad PSRAM configurations cannot be interchanged simply by changing a parameter: a quad-PSRAM module also requires replacing `CONFIG_SPIRAM_MODE_OCT` with `CONFIG_SPIRAM_MODE_QUAD`.

The link report shows: FLASH 961,204 B, internal SRAM 379,640 B / 399,108 B (95.12%), and 5,152,752 B placed in external PSRAM.

The last figure (approximately 5.2 MB) is easy to misread as the PSRAM capacity or the size of its address window, so it is worth spelling out how these three values relate. The module's physical PSRAM capacity is **16 MB** (`CONFIG_ESP_SPIRAM_SIZE`). The linker script declares `ext_dram_seg` as a **32 MB region** — a DCACHE0 address window it shares with `drom0_0_seg`, which is an address-space limit rather than usable capacity. The **5,152,752 B (≈5.2 MB)** shown in the link report is that region's **Used Size**, the amount actually placed in PSRAM. It includes the 4 MB broker heap specified by `CONFIG_ESP_SPIRAM_HEAP_SIZE`, as well as static pools moved out of internal SRAM, such as the Wi-Fi driver's `.noinit` section, the net_buf pools, and the Zephyr POSIX object pools. In other words, 5.2 MB is neither the PSRAM capacity nor the size of its mapped window.

**Clock.** The development board has no RTC. After DHCP completes, `main.c` performs a one-shot SNTP sync to seed `CLOCK_REALTIME` — up to two passes over two public SNTP servers, returning as soon as one answers — so the timestamps in the log are real UTC. This step is best-effort: if no server responds, the broker still starts normally, and only the timestamps remain at the Unix epoch (2 seconds per query and 1 second between the two passes, so the worst case adds roughly 9 seconds to startup).

## Build and Run: qemu_x86

### 1. Build

After applying the e1000 patch (activate the Zephyr workspace venv from "Environment Setup → Prerequisites" first so that `west` is available; ESP-IDF is not needed):

```sh
west build -b qemu_x86 -d build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86
```

A successful build ends with output similar to:

```
[289/290] Building C object zephyr/CMakeFiles/zephyr_final.dir/misc/empty_file.c.obj
[290/290] Linking C executable zephyr/zephyr.elf
Memory region         Used Size  Region Size  %age Used
             RAM:     2608020 B        31 MB      8.02%
        IDT_LIST:           0 B         2 KB      0.00%
Generating files from build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf for board: qemu_x86/atom
```

(This figure is sensitive to code layout: changing a few dozen bytes of code can push a section across a page boundary and shift the reported value by a whole 4 KB page. That is alignment padding, not real growth.)

The `qemu_x86/atom` shown at the end is the fully qualified board name. `atom` is the SoC qualifier for `qemu_x86`, using the same board/SoC qualification mechanism as `esp32s3_devkitc/esp32s3/procpu` on the ESP32-S3 side. It does not mean that `-b qemu_x86` selected the wrong board.

### 2. Run

Starting QEMU in the background and writing the serial console to a file is the recommended approach — it leaves the terminal free for the verification steps that follow:

```sh
qemu-system-i386 -m 32 -cpu qemu32,+nx,+pae,sse,sse2,pni -machine q35 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -machine acpi=off \
    -serial file:/tmp/qemu.log -display none \
    -netdev user,id=n1,hostfwd=tcp:127.0.0.1:1883-:1883,hostfwd=tcp:127.0.0.1:8081-:8081,hostfwd=tcp:127.0.0.1:8083-:8083 \
    -device e1000,netdev=n1 \
    -kernel build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf &
```

The port forwarding is configured through `CONFIG_NET_QEMU_USER_EXTRA_ARGS` in `prj.conf`, which binds 1883/8081/8083 to `127.0.0.1` and matches the manual command above. Both follow the same rule: **whoever runs QEMU owns the network interfaces its ports are bound to.**

You can also let west start it directly:

```sh
west build -d build/nanomq_zephyr_qemu_x86 -t run
```

This picks up the three port forwards from `prj.conf` automatically, **but it attaches the serial console to stdio and occupies the current terminal**, so it is only suitable for watching the boot process.

**Clear out old instances before restarting.** A leftover QEMU keeps the three ports occupied and the new instance fails immediately:

```
qemu-system-i386: ... Could not set up host forwarding rule 'tcp:127.0.0.1:8083-:8083'
```

`-t run` is especially prone to leaving such a process behind — stopping it does not necessarily take the QEMU instance it started with it. To clean up, look the PIDs up by port:

```sh
ss -ltnp | grep -E ':(1883|8081|8083)' | grep -oP 'pid=\K[0-9]+' | sort -u | xargs -r kill
```

`qemu-system-i386` can also be located by west itself (the host tools of the Zephyr SDK, or a distribution package on `PATH`, such as Fedora's `qemu-system-x86`). If running it manually reports `command not found`, add the directory containing QEMU to `PATH`.

The `-m 32` option allocates 32 MB of memory to QEMU. Zephyr's linker script reserves part of this memory, so the usable RAM shown in the link report is approximately 31 MB (the image used in this article occupies about 2.5 MB, of which approximately 1 MB is the malloc arena).

### 3. Startup Log

The following is an actual startup log (some DEBUG lines and path prefixes omitted):

```
*** Booting Zephyr OS build v4.4.0-4779-g11a87708d415 ***
rtc: CMOS clock 2026-09-15 10:27:23 UTC, realtime seeded
net: iface 0x19e94c dev=eth0 up=1
net: ipv4 10.0.2.15
2026-09-15 10:27:23 [0] DEBUG broker.c:1102 broker: db init finished
2026-09-15 10:27:23 [0] DEBUG broker.c:1111 broker: listener init finished
2026-09-15 10:27:23 [0] DEBUG broker.c:1128 broker: HTTP init finished
2026-09-15 10:27:23 [0] INFO  web_server.c:548 start_rest_server: http://0.0.0.0:8081/api/v4
2026-09-15 10:27:23 [0] WARN  broker.c:1400 broker: NanoMQ (ver 0.25.6) Serving HTTP Server on http://(null):8081
NanoMQ Broker is started successfully!
```

Those two REST lines appear only when credentials were configured at build time.

The broker is ready when the final line appears: `NanoMQ Broker is started successfully!`. You can then verify the REST API (provided that `CONFIG_BROKER_REST_USER` / `_PASS` were set through `local.conf` at build time; without them nothing listens on 8081):

```sh
curl -u <rest-user>:<rest-pass> http://127.0.0.1:8081/api/v4/brokers/
```

### About the malloc Arena

`qemu_x86` enables the MMU, and Zephyr's libc provides a default `malloc` arena of only 16 KB. The NNG Zephyr platform adaptation layer uses `malloc()` as its allocator, so the receive queue of a single pipe can exceed this limit as `msq_len * 8` bytes.

The `prj.conf` configuration therefore increases the arena to 1 MB. As a result, approximately 1 MB of the image's memory usage belongs to the `malloc` arena rather than to the broker itself.

## Functional Testing

The repository includes a functional test suite that runs the same set of tests against both demos. Before running the tests, install the required Python dependencies (the runner checks for them and exits with an error if they are missing):

```sh
python3 -m pip install paho-mqtt requests
```

The system must also have the Mosquitto command-line clients (`mosquitto_pub` and `mosquitto_sub`) installed. On Debian/Ubuntu, install the `mosquitto-clients` package; on Fedora, install `mosquitto`.

`--list` shows all test groups (this article covers 8 of them, listed in the table below):

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --list
```

For a running hardware demo, use `--no-manage` to tell the runner that the broker is already running and should not be managed by the runner:

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr <board-ip>
```

You can also run specific test groups:

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr <board-ip> \
    --group mqtt_v311 --group rest_get
```

The following results were obtained on the ESP32-S3 hardware demo, running the 8 groups in the table below one at a time with `--group`. Path prefixes are omitted for readability.

```
========================================================================
Zephyr broker functional test suite — broker <board-ip>:1883
groups: mqtt_v311, mqtt_v5, rest_get, ws_v311, ws_v5, capacity, ws_abort, survival
========================================================================
--no-manage: assuming a broker is already running; leftover mosquitto clients are NOT cleaned up
broker connect RTT 16.1 ms -> time-scale 4.0 (auto)
[1/8] mqtt_v311      PASS  (120.1s)
[2/8] mqtt_v5        PASS  (211.3s)
[3/8] rest_get       PASS  (2.9s)
[4/8] ws_v311        PASS  (279.0s)
[5/8] ws_v5          PASS  (15.9s)
[6/8] capacity       PASS  (13.1s)
[7/8] ws_abort       PASS  (31.9s)
[8/8] survival       PASS  (90.3s)
------------------------------------------------------------------------
RESULT: pass=8 fail=0
```

The `rest_get` group additionally requires that the broker under test was built with REST credentials configured (see each demo's `local.conf.example`). When they are not configured, this group does not fail but is reported as **SKIP**:

```
| [worker rest_get] SKIP: no REST API on <addr>:8081 — the demos leave it off
| until CONFIG_BROKER_REST_USER/PASS are set (local.conf); pass
| --rest-user/--rest-pass for a broker that has them
```

In other words, the suite distinguishes "REST is not enabled" from "REST is broken": the former is skipped with an explanation, and only the latter fails. Once the broker has credentials configured, pass the same pair to the suite with `--rest-user` / `--rest-pass` and the group runs normally.

The coverage and execution time for each test group on the hardware demo are shown below:

| Test group | Coverage | Hardware runtime |
| --- | --- | --- |
| `mqtt_v311` | Sessions, retained messages, and v4/v5 interoperability | 120.1s |
| `mqtt_v5` | Session expiry, user properties, `$share`, and topic aliases | 211.3s |
| `rest_get` | All REST GET routes | 2.9s |
| `ws_v311` | MQTT 3.1.1 over WebSocket | 279.0s |
| `ws_v5` | MQTT 5 over WebSocket | 15.9s |
| `capacity` | 12 concurrent CONNECTs + QoS 1 loopback | 13.1s |
| `ws_abort` | Connection-pool stability when WebSocket connections are aborted abnormally | 31.9s |
| `survival` | Scaled-down load/session churn based on the upstream `attack.py` | 90.3s |

The runner adjusts its parameters automatically: it first measures the TCP round-trip time to the broker (below 1 ms on the local loopback, tens to hundreds of milliseconds over Wi-Fi on real hardware; 16.1 ms in this run), and on determining that it is not local, it switches to `--time-scale 4` by default, which extends the sleep intervals that the CI scripts calibrate for local-network latency.

## The Porting Process

NanoMQ's layering already includes a platform adaptation layer (nng's `nni_plat_*`), so most of the porting work is **filling in that layer for Zephyr**. The real hard blockers, on the other hand, are in the application layer: a few places in `nanomq/` call POSIX directly and cannot be worked around. The sections below go layer by layer.

### 1. Application Layer: Trimming POSIX Dependencies

The application layer's POSIX dependencies are concentrated in four places, all handled with `__ZEPHYR__` conditional compilation rather than a new abstraction layer:

| File | Original POSIX dependency | Handling |
| --- | --- | --- |
| `apps/broker.c` | `signal()` / `sigaction` for installing signal handlers | The whole block is skipped. Zephyr has no POSIX signal semantics; an embedded broker's main loop terminates on its own conditions rather than on `^C` |
| `nanomq.c` | `#include <sys/ptrace.h>` | Conditional compilation. `check_trace()` is only called on the CLI path, which an embedded broker never takes |
| `mqtt_api.c` | `nng_access(dir, W_OK)` (writability check of the file-log directory) | Conditional compilation. picolibc has no `W_OK`; the file-log backend is always off on embedded, so skipping the check has no side effect |
| `process.c` (the whole translation unit) | `fork` / `kill` / `chdir`, `<paths.h>` | Not built; the demo provides `process_stub.c` supplying its public symbols (all returning -1) |

`process_stub.c` can "pretend" like this because the five symbols either have no call sites at all or are only reached from paths that never execute: both calls to `process_daemonize()` are guarded by `daemon == true`, `process_send_signal()` is called only by `check_trace()` on the CLI path, and `process_is_alive()` / `pidgrp_send_signal()` / `process_create_child()` have **no call sites anywhere in the application**. An embedded broker calls `broker()` and `conf_init()` with `daemon` defaulting to false, so none of those paths is reached — **the stub's actual job is simply to let the link succeed**.

### 2. Platform Adaptation Layer: Interface Inventory and POSIX Differences

This layer is nng's Zephyr implementation (`src/platform/zephyr/`, 22 files, 18 of them `.c`: 16 implementing the interface families below, plus 2 stubs — `zephyr_peerid.c` and `zephyr_socketpair.c`, corresponding to the two unsupported facilities in the table). It is organized by nng's interface families, each mapped onto a Zephyr facility:

**Interface inventory**

| Interface family | Implementation file | Corresponding POSIX facility | Zephyr implementation |
| --- | --- | --- | --- |
| Memory | `zephyr_alloc.c` | `malloc` / `free` | A `k_heap` on PSRAM, or the libc `malloc()` (per target) |
| Clock and sleep | `zephyr_clock.c` | `clock_gettime` / `nanosleep` | `k_uptime_get()`, plus Zephyr's POSIX `nanosleep()` |
| Threads and synchronization | `zephyr_thread.c` | `pthread_*` (mutexes / rwlocks / condition variables / threads) | Zephyr's pthread implementation (`CONFIG_POSIX_API`) |
| Atomic operations | `zephyr_atomic.c` | C11 `<stdatomic.h>` | Native 64-bit atomics, or an embedded-mutex fallback |
| Debugging and error codes | `zephyr_debug.c` | `abort` / `printf` / `strerror` / `errno` | `printk`, libc, and the errno ↔ nng error-code mapping |
| TCP (client) | `zephyr_tcpdial.c`, `zephyr_tcpconn.c` | `socket` / `connect` / `setsockopt` | The BSD-compatible sockets of Zephyr's network stack |
| TCP (server) | `zephyr_tcplisten.c` | `socket` / `bind` / `listen` / `accept` | Same as above |
| UDP | `zephyr_udp.c` | `socket` / `sendmsg` / `recvmsg` | Same as above |
| Descriptors and the poll queue | `zephyr_pollq_poll.c`, `zephyr_sockfd.c` | `poll()` (POSIX additionally layers epoll / kqueue / eventfd on top) | Zephyr's `poll()` |
| Socket address conversion | `zephyr_sockaddr.c` | Conversion between `sockaddr` and nng structures | Zephyr's `sockaddr` (AF_UNIX removed) |
| DNS resolution | `zephyr_resolv_gai.c` | `getaddrinfo()` | Zephyr has the interface, but with different semantics (see the table below) |
| Random numbers | `zephyr_rand_urandom.c` | `/dev/urandom`, `getrandom()` | Branches on whether a hardware entropy source exists (see the table below) |
| Files | `zephyr_file.c` | `stdio`, `stat`, file locking | `stdio` and `stat` are real implementations; the temp directory and file locking are fallbacks (see the table below) |
| Wakeup pipe | `zephyr_pipe.c` | `pipe()` / `eventfd()` | Zephyr has no corresponding facility (see the table below) |

**Where POSIX assumptions do not hold**

| POSIX assumption | Zephyr today | Handling |
| --- | --- | --- |
| `readv()` / `writev()` | Not available, and there is no `<sys/uio.h>` | Emulated with `read()` / `write()` loops, with short-transfer semantics explicitly preserved (Detail 1) |
| `pipe()` / `eventfd()` | Not available | The poll queue registers no wakeup descriptor and advances on its own timeout instead |
| `flock()` / `lockf()` | No file locking | Follows `posix_file.c`'s own embedded fallback: succeeds, but does not lock |
| Temp directory / working directory | Neither concept exists | `nni_plat_temp_dir()` returns `"/tmp"` (whether a filesystem is really mounted there is reported by the caller's own file operations); `nni_plat_getcwd()` returns NULL |
| Peer credentials such as `SO_PEERCRED` | Unavailable | Returns `NNG_ENOTSUP`. Peer credentials only serve the AF_UNIX IPC transport, which does not exist on Zephyr |
| `socketpair()` (AF_UNIX domain socket pairs) | No AF_UNIX | Returns `NNG_ENOTSUP`; the IPC transport that depends on it is therefore unavailable on Zephyr (see Appendix A) |
| `/dev/urandom` | No such device | Targets with a hardware entropy source (the ESP32-S3 TRNG) use `sys_csrand_get()`; targets without one fall back to a software generator, annotated in the code as unsuitable for secret material |
| 64-bit atomic operations | 32-bit non-x86 targets have no native support | Falls back to "atomics built on an embedded mutex" (Detail 2) |
| `SO_BINDTODEVICE` | No interface binding | Returns `NNG_ENOTSUP` at the option-setting point, rather than accepting the option and silently using the default interface |
| `getaddrinfo()` | Present, but synchronous | Synchronous semantics are accepted: resolution happens on the caller's thread, with no worker thread introduced |
| `pthread_condattr_setclock()` | Depends on `CONFIG_POSIX_CLOCK_SELECTION` | Validated at startup; if the monotonic clock is unavailable, the process terminates — otherwise every timed wait would silently time out immediately |

**Detail 1: Short-transfer semantics of `readv` / `writev`.** Simply "looping until all iovecs are written" is wrong. POSIX `readv` / `writev` return at the **first short transfer** and report the bytes transferred, leaving the caller to resubmit the rest. An emulation that carries on past an iovec creates holes in the byte stream; one that returns -1 after a successful transfer but a subsequent `EAGAIN` makes the caller believe nothing was sent and resend it. The correct approach is to stop at the first short transfer and return the accumulated value — the comment in `posix_sockfd.c` ("we didn't send all the data, the caller will resubmit") is the contract the caller relies on.

**Detail 2: Why atomic operations do not use pthread mutexes.** The intuitive approach is to embed a `pthread_mutex_t` in every atomic variable, but Zephyr's `pthread_mutex_init()` **allocates from a fixed pool** (`posix_mutex_pool`, bitmap allocation, returning `ENOMEM` once the pool is exhausted). Of the 26 places where nng initializes an atomic variable, only 5 have a matching `nni_atomic_fini*()` call to hand the slot back (three on the pipe, the message refcount, and the inproc pair); the rest have no corresponding release call. Using the kernel's own `struct k_mutex` avoids the problem: it is embedded, takes nothing from the pool, and needs no release.

**Detail 3: `ENABLE_LOG` must reach both sides.** Whether nanolib's `conf.c` initializes the log backend and whether `log_*()` is compiled into an entity is decided by `-DENABLE_LOG`, and it must be passed to **both** the application and libnng. The reason lies in the build system: nng's CMake only recognizes cache variables of the form `NNG_*`, so plain macros must be routed in through `CMAKE_C_FLAGS`. The consequence of passing it to only one side is silent — the link succeeds and the broker runs, but not a single log line appears (`conf->log.type` is left uninitialized). The same applies to `ACL_SUPP`, where an unsatisfied condition is more dangerous still: mismatched definitions on the two sides misalign the layout of `struct conf`.

### 3. Compile-Time Macro Contract

| Macro | Purpose | If unsatisfied |
| --- | --- | --- |
| `ENABLE_LOG` | Makes nanolib initialize the log backend and compile `log_*()` into an entity | Logging silently stops working |
| `ACL_SUPP` | Makes `struct conf` carry the ACL fields (on by default) | Mismatched definitions on the two sides → struct layout is misaligned |
| `SUPP_NANO_LIB` | Hides `nanomq.c`'s `main()` while keeping `get_cache_argc/argv` | Conflicts with the demo's own entry point |
| `SUPP_SYSLOG` | **Deliberately left unset** | Would look for `syslog()`, which Zephyr does not have |

### 4. Two Framework-Level Traps

Both issues described below come from the same type of problem: Zephyr's API behavior differs from what might be expected, and failures produce no error messages, making them expensive to diagnose.

#### 1. PSRAM Heap Corruption on the First Client Connection

The ESP32-S3 has about 512 KB of internal SRAM, of which around 416 KB is available. The broker's data plane requires several megabytes, so PSRAM is necessary.

Zephyr provides `shared_multi_heap` for managing multiple heap regions, which initially seems like a good fit. However, **it is not thread-safe** because its underlying `sys_heap` is accessed without locking.

NanoNNG allocates memory from multiple threads, including the poller, the taskq workers, and the aio associated with each connection. As a result, **the heap is corrupted when the first client connection is established**.

The solution is to avoid `shared_multi_heap_alloc()` and instead use a regular `struct k_heap` with locking on the PSRAM window. Static pools that do not need to reside in SRAM, including the Wi-Fi driver's `.noinit` section, the net_buf pools, and the Zephyr POSIX object pools (about 60 KB), are also moved to PSRAM. This leaves the internal SRAM available for the parts that actually require it.

#### 2. `net_mgmt` Callback Masks Are Not Matched Bitwise

The Wi-Fi connection process needs to listen for multiple events. It is intuitive to combine them into a single mask and register one callback:

```c
/* Incorrect: the two events use different layer codes */
net_mgmt_init_event_callback(&cb, handler,
    NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_IPV4_DHCP_BOUND);
net_mgmt_add_event_callback(&cb);
```

With this configuration, the callback **is never triggered**, and no log or error code is generated.

The reason is in `mgmt_run_slist_callbacks()` (`subsys/net/ip/net_mgmt.c`). When checking whether a callback matches an event, it uses **full layer-code equality**, rather than a bitwise AND:

```c
if (!(NET_MGMT_GET_LAYER(mgmt_event->event) ==
      NET_MGMT_GET_LAYER(cb->event_mask)) ||
    !(NET_MGMT_GET_LAYER_CODE(mgmt_event->event) ==
      NET_MGMT_GET_LAYER_CODE(cb->event_mask)) || ...
```

When events with different layer codes are combined into one mask, the layer code in `cb->event_mask` becomes the bitwise OR of the two codes, and so matches neither event. For these two events, the Wi-Fi event has a layer code of `0x0D` while IPv4 uses `0x03`. Their bitwise OR is `0x0F`, which is not equal to either value.

The correct approach is to **register one callback for each event**. The same handler can be reused:

```c
/* Correct: one callback structure per event */
net_mgmt_init_event_callback(&wifi_cb, handler, NET_EVENT_WIFI_CONNECT_RESULT);
net_mgmt_add_event_callback(&wifi_cb);

net_mgmt_init_event_callback(&dhcp_cb, handler, NET_EVENT_IPV4_DHCP_BOUND);
net_mgmt_add_event_callback(&dhcp_cb);
```

## Conclusion

The value of running the broker on an MCU lies in eliminating one edge gateway: the same development board already deployed in the field can run a broker on the side, consolidating heterogeneous devices into MQTT and buffering locally when the link goes down.

### Where This Approach Fits

Taken together with the list in [Appendix A](#appendix-a-differences-from-general-nanomq), the current implementation suits small-scale edge aggregation and protocol conversion inside a controlled network. The following points should be settled before making a selection:

- TLS, disk persistence, and MQTT-side authentication are not included (all three are marked as planned in the "Future plan" column of Appendix A), so **at this stage it is not suitable as a broker on the public Internet or an untrusted network**; the demos in this article listen on all interfaces by default, and although REST provides Basic authentication, it is unencrypted and its credentials must be configured by you (there are no usable default credentials). See "Security Considerations".
- There is no filesystem, so cached messages and persistent sessions do not survive a power loss.
- Concurrency is constrained by the Zephyr thread quota. This article does not publish formal throughput or concurrency benchmarks; the official performance figures cited in Appendix A come from multicore POSIX environments and do not represent the performance of this demo.
- Apart from `qemu_x86` and ESP32-S3, no other boards have been validated.

### Code and Demos

The code is available in the `zephyr-rtos` branch of [nanomq/nanomq](https://github.com/nanomq/nanomq/tree/zephyr-rtos), with both demos under the `demo/` directory. The respective READMEs document the complete bring-up process.

If you validate the port on another board or encounter new issues, you are welcome to join the discussion in the [NanoMQ community](https://github.com/nanomq/nanomq/discussions).

## Appendix A: Differences from General NanoMQ

This Zephyr port is **not an equivalent replacement for general NanoMQ**. It differs from the general version in several areas, and these differences should be considered when evaluating the port for a specific use case.

**Baseline version.** The port is based on upstream `master`, that is, NanoMQ **0.25.6**.

**Configuration source.** The general NanoMQ version reads its configuration from `nanomq.conf`. The Zephyr version instead uses an **embedded minimal configuration**: built-in defaults from `conf_init()` are combined with startup code that directly sets key fields such as listener addresses, bypassing the configuration file parser. The `conf` structure and its semantics remain unchanged; only the configuration source changes from a file to in-memory construction.

**Feature Availability.** Peripheral features (REST, the rule engine, bridging, and so on) are **fully compiled and controlled at runtime**, rather than being removed at compile time, which keeps the behavior of the same source code consistent across platforms. The following table lists the capabilities that are unavailable or unverified in this version, distinguishing **work not yet finished (planned)** from **limited by the platform or its dependencies (not planned)**:

| Capability | Status | Future plan |
| --- | --- | --- |
| Filesystem-related | Configuration, logs, and persistent sessions are not written to disk; `$SYS` only reflects runtime state | **Supported**: mounting Zephyr's fs subsystem (fat / ext2 / fcb, etc.) is all that is needed |
| SQLite persistence | Not included (`NNG_ENABLE_SQLITE=OFF`) | **Supported**: enabled together with the filesystem |
| Parquet | Not included. Controlled by the `SUPP_PARQUET` macro (not a CMake option); undefined means it is not compiled in | **Supported**: as above; depends on the filesystem |
| TLS | Not included (`NNG_ENABLE_TLS=OFF`). Zephyr provides mbedTLS (enabled in this build) and the `tls_credentials` subsystem | **Supported**: once enabled, MQTTS / WSS / HTTPS become available |
| MQTT-side authentication (password / ACL) | Neither wired up nor verified; any client can connect today | **Supported**: a matter of wiring up the configuration and validating it |
| Rule engine | The embedded configuration has no corresponding switch path; unverified | **Supported**: a pure software module, with only the configuration wiring missing |
| IPC transport | Turned off in the demos (`main.c` sets `ipc_internal = false`; a runtime assignment, not a build option), so the `nanomq ctl` management channel is unavailable | **Pending platform support**: requires named AF_UNIX, while Zephyr currently offers only anonymous `socketpair` |
| QUIC | Not included (`NNG_ENABLE_QUIC=OFF`). nng's QUIC implementation depends on msquic | **Not planned**: the dependency footprint does not fit an embedded target |

**Thread model.** The Linux version relies on a full POSIX dynamic thread pool. On Zephyr, the number of NanoNNG threads is fixed (taskq = 2 / poller = 1 / expire = 1), and together with the Zephyr POSIX thread pool limit of `CONFIG_POSIX_THREAD_THREADS_MAX=16` — with each pthread's stack fixed at 16 KB by `CONFIG_DYNAMIC_THREAD_STACK_SIZE` — broker concurrency is constrained accordingly.

**Performance data.** The figures published by [NanoMQ](https://nanomq.io/) include: a startup footprint of under 200 KB with a minimal feature set; throughput of up to millions of TPS; and performance up to 10 times faster than Mosquitto on multicore CPUs. It is important to stress the scope of these figures: they come from benchmarks in **multicore POSIX environments**, the official page does not give the hardware and configuration details of the corresponding tests, and they **do not represent the performance of the demos in this article** — the thread quota on the Zephyr side is far smaller than that of a multicore Linux system (see the previous point), so the actual concurrency characteristics differ. No formal performance testing was conducted on the demos in this article.

**Memory allocation.** The allocator differs by target: `qemu_x86` uses the libc `malloc()`, whose arena is the broker heap (see the qemu section); the ESP32-S3 cannot fit the data plane in internal SRAM, so `NNG_ZEPHYR_ALLOC_SMH` is defined to switch nng's allocation to a `k_heap` on PSRAM (see "The Porting Process → 4. Two Framework-Level Traps").

**Time source.** Both demos use real UTC, but obtain it differently: `qemu_x86` seeds it from the QEMU CMOS RTC, while the ESP32-S3 has no RTC and seeds it through SNTP. Zephyr does not include a timezone database, so displayed time is always UTC.

**Removed module.** The broker's `process.c` depends on `fork` / `kill` / `chdir` and cannot be compiled on Zephyr; it is replaced by a stub in the demo that provides the same symbols. Those symbols are called either from daemon and CLI paths or not at all, so the embedded broker does not reach them (see the corresponding table entry in "The Porting Process → 1. Application Layer").

**Validated platforms.** `qemu_x86` (32-bit) and ESP32-S3. The build system enables the atomic-operation fallback (`NNG_ZEPHYR_NO_STDATOMIC`, see Detail 2 in "The Porting Process → 2. Platform Adaptation Layer") for **every 32-bit non-x86 target** (ARM, RISC-V, Xtensa, and so on) — **the ESP32-S3 is itself using it**, so that path is covered by the hardware validation. What remains unvalidated is the ARM / RISC-V **board** itself (future plans: validating on ARM / RISC-V and other boards, where the network driver, interrupts, and memory budget would all need to be revalidated).

## Appendix B: Comparing the Two Demos

|  | `demo/nanomq_zephyr_esp32s3` | `demo/nanomq_zephyr_qemu_x86` |
| --- | --- | --- |
| **Target platform** | ESP32-S3 hardware | `qemu_x86` |
| **Hardware requirement** | ESP32-S3 development board | None |
| **Network** | Wi-Fi STA + DHCP | QEMU SLIRP user-mode networking |
| **Memory / storage** | 16 MB flash + octal PSRAM (data plane in PSRAM) | 31 MB simulated RAM, no persistent storage |
| **Additional prerequisite** | Wi-Fi credentials | Zephyr e1000 driver patch |
| **Typical use** | Real-world evaluation and hardware testing | Quick verification during development |

Both demos share the same application source and the same NanoNNG ExternalProject build; they differ only in board support and the network layer.

For development, `qemu_x86` is recommended. A complete build-and-run cycle takes only a few seconds, making it significantly faster than flashing and resetting the hardware.

For real-world evaluation and hardware testing, use the ESP32-S3 demo.

The complete build and run procedures for both demos are provided in the corresponding sections of this article.
