# ART-Pi (art_pi / STM32H750XBH6) 上的 NanoMQ broker

在睿赛德/RT-Thread 的 **ART-Pi**（STM32H750XBH6）上，通过**板载 AP6212 模块
（Infineon CYW43438，挂在 SDMMC2 上的一个 SDIO function）以 Wi-Fi STA +
DHCPv4 的方式**运行完整的 NanoMQ broker 核心（`nanomq/nanomq/` 应用源码 +
NanoNNG 子模块 `nng/`）。

它是 [demo/nanomq_zephyr_qemu_x86](../nanomq_zephyr_qemu_x86/)（qemu_x86 仿真）
和 [demo/nanomq_zephyr_esp32s3](../nanomq_zephyr_esp32s3/)（ESP32-S3，Wi-Fi）
的同类 demo：应用源码与 NanoNNG 的 ExternalProject 构建方式相同，差在目标板
与网络层。功能面与前两个一致：MQTT over TCP（:1883）+ REST API（:8081，
Basic 认证）+ MQTT over WebSocket（:8083/mqtt），以及可选的 webhook 转发。
DEBUG 日志默认关闭。

验收等级：**功能对等** —— 功能测试套件的三个硬性门禁（`mqtt_v311`、
`mqtt_v5`、`rest_get`）已在实机上通过（记录见下）。

## 目标板

Zephyr 原生 `art_pi` 板：STM32H750XBH6（Cortex-M7），128 KB 内部 Flash、
1 MB SRAM、32 MB FMC SDRAM、8 MB QSPI NOR、AP6212 Wi-Fi/BT 模块、microSD、
RGB LCD 排线、USB-OTG，ST-Link V2.1 与串口在同一个 USB-C 口上（SWD + 115200
虚拟串口，`/dev/ttyACM0`）。

## 内存布局

这个 demo 有两个关键决策，各自有一份 ADR。

**镜像从 QSPI 以 XIP 方式运行在 0x90000000**
（[../../docs/adr/0001](../../docs/adr/0001-qspi-xip-behind-art-pi-factory-bootloader.md)）。
broker 约 1 MB 代码，而内部 Flash 只有 128 KB，且已被睿赛德的出厂 bootloader
占满；该 bootloader 会把 QUADSPI 映射好并跳到 0x90000000 处的向量表。overlay
把 `zephyr,flash` 指向 8 MB 的 QSPI 窗口
（[boards/art_pi.overlay](boards/art_pi.overlay)），同时**不**打开 QSPI 驱动，
避免有驱动去重配 CPU 正在取指的外设。烧写只用 SWD
（[tools/artpi_flash.py](tools/artpi_flash.py)）。

**broker 数据面放在 SDRAM**
（[../../docs/adr/0002](../../docs/adr/0002-broker-heap-in-sdram-through-the-external-ram-allocator.md)）。
设备树中 0xC0000000 处 6 MB 的 `SDRAM1` 区域，通过 NanoNNG 的外部 RAM 分配器
（`NNG_ZEPHYR_ALLOC_SMH`）交给一个普通 `k_heap`（用其中 4 MB），边界定义在链接
脚本片段 [src/artpi_ext_ram.ld](src/artpi_ext_ram.ld)。显示控制器被关闭，避免
它的 framebuffer 争抢同一窗口。

Wi-Fi 构建的占用：FLASH 约 977 KB（共 8 MB），RAM 约 451 KB / 512 KB（86 %）
—— 紧张的是内部 SRAM，不是 Flash。

## 网络

### Wi-Fi（默认配置）

AP6212 的 Wi-Fi 侧是一个 SDIO function。Zephyr 的板级设备树没有描述它，因此本
demo 自己补上 SDIO 主机与 AIROC/WHD 设备节点：

| 信号 | 引脚 | 说明 |
| --- | --- | --- |
| SDMMC2 D0/D1 | PB14/PB15 | AF9 |
| SDMMC2 D2/D3 | PB3/PB4 | AF9 |
| SDMMC2 CK/CMD | PD6/PD7 | AF11 |
| WL_REG_ON | PC13 | 高有效，取自 ART-Pi 自己的 Wi-Fi 驱动 |

引脚定义来自厂商的 Wi-Fi 工程（ART-Pi SDK 的 `projects/art_pi_wifi/`）；
WL_REG_ON 即 `libraries/drivers/drv_wlan.c` 中的
`AP6212_WL_REG_ON == GET_PIN(C, 13)`。

要让芯片成功入网，有三件事必须正确。这三条都是踩坑踩出来的，完整记录见
[docs/zh_CN/port-to-art-pi.md](docs/zh_CN/port-to-art-pi.md)。

1. **资源：固件 + NVRAM，以及 CLM。** 固件直接用上游 airoc 的
   `43438A1.bin`，但 NVRAM 必须是本模块的：厂商
   `wifi_nvram_image[]` 里那套（`prodid=boardtype=0x0726`、
   `xtalfreq=26000`）。blob 清单里给这颗芯片配的 AW-CU427-P NVRAM 会让固件
   在初始化中途放弃。同时还必须有 CLM blob：没有它，WHD 的第一条 `country`
   ioctl 就会失败，`whd_wifi_on()` 永远走不完。
   `zephyr/modules/hal_infineon/whd-expansion/CMakeLists.txt` 因此学会了像
   4343W/43439 那样给 43438 接上 CLM/NVRAM（补丁 0002；固件 blob 本身来自
   `west blobs fetch hal_infineon`）。

2. **芯片从不断言 SDIO in-band 卡中断。** 在控制器侧完全就绪的情况下
   （`SDMMC_MASK.SDIOITIE` 已置位、CCCR `INTEN=0x7`、WLAN function ready、
   固件已下载、CLM 已被接受），STM32 SDMMC 的 `SDMMC_STA.SDIOIT` 始终为 0
   —— 这是在实机上量出来的，并且同一时刻确认了 `SDIOITIE` 已置位。而 WHD 的
   线程**只有在被"带 bus-interrupt 标志"地唤醒时**才会去轮询收到的帧
   （该传输层上 `whd_bus_sdio_use_status_report_scheme()` 返回 `WHD_FALSE`），
   于是每条 ioctl 都只是写进 function 2，然后超时、回包从未被读取
   （`iovar "cap" -> 101580800`，每条 ioctl 5 秒，
   `airoc_wifi_init_primary failed ret = -19`）。

   规避办法见 [patches/0002](patches/0002-zephyr-airoc-whd-sdio-bring-up.patch)：
   用一个 20 ms 定时器去戳 `whd_thread_notify_irq()`，把本该由中断送达的唤醒
   补给线程，让它改走轮询。若 `whd_wifi_on()` 失败则停掉该定时器。

   让中断真正到来的两条路都在实机上试过，都不可行：外设的 `DCTRL.SDIOEN`
   （"SD I/O enable"，让 DAT1 成为中断线的那个位）置位后 `SDIOIT` 依旧不锁存，
   **而且**一旦有数据流量就出现 `Command response timeout` 刷屏、4 位传输直接
   失败；改成 1 位总线也是同样结果。按原理图 `GPIO_WIFI_HOST_WAKE` 网络把
   out-of-band host-wake 接成 PE3 同样没有唤醒。轮询也正是这块板子**厂商栈的
   做法** —— ART-Pi SDK 的 `libraries/drivers/drv_sdio.c` 根本没有打开
   `SDMMC_MASK.SDIOITIE`。详见
   [../../docs/adr/0003](../../docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md)。

3. **STA 连接流程由应用负责**，与 ESP32-S3 同类 demo 一致：`src/main.c`
   等接口就绪，用应用 Kconfig 里的凭据（`CONFIG_BROKER_WIFI_SSID` / `_PSK`，
   通过 git-ignored 的 `local.conf` 提供）发出 `NET_REQUEST_WIFI_CONNECT`，
   每 30 秒重试，然后启动 DHCPv4 客户端并等待 `NET_EVENT_IPV4_DHCP_BOUND`，
   之后才启动 broker。重试是**有限次**（3 次）：连不上的链路绝不该连带让 broker
   起不来 —— 那样控制台上就一条 broker 日志都没有，板子看起来像死的。现在它会照常
   启动并打印 `wifi: no association after 3 attempts ... starting the broker
   anyway`，一旦后来拿到租约就能被访问。Wi-Fi 构建额外传入
   [boards/art_pi_wifi.overlay](boards/art_pi_wifi.overlay)
   （关掉 `&mac`/`&mdio`/`&eth_phy`），让镜像里只有一个网络接口。

### 以太网（可选；驱动已验证，链路未测）

[eth.conf](eth.conf) 用来构建 STM32 以太网 MAC + LAN8720A PHY 的版本以替代
Wi-Fi（`CONFIG_ETH_STM32_HAL=y`，不带 Wi-Fi overlay）。bring-up 时最初把 PHY
"完全不回应"归咎于硬件：MDIO 扫描无响应，驱动报 `PHY (0) ID FFFF` /
`HAL_ETH_Init failed`；但那是**带着** `&eth_phy` 上
`reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>` 这条覆盖的情况下测的（当时以为 PA3
是板级 `ETH_RESET_PIN`）。去掉这条覆盖后，MAC 能正常初始化、也不再报 PHY 错误，
接口以 dormant 状态等待 carrier。

调试台上没有网线，因此以太网的**链路建立、DHCP 与数据通路都没有验证过**。这份
配置只能算"驱动能跑"。

### USB-ECM（可选；固件已验证，卡在物理链路上）

[usb.conf](usb.conf) + [boards/art_pi_usb.overlay](boards/art_pi_usb.overlay)
把板子当 **USB 设备**：USB-OTG 口（PA11/PA12，板级 `zephyr_udc0` 本来就已使能）
呈现一个 CDC-ECM 以太网功能，`src/main.c` 让板子做这条链路的 **DHCPv4 服务器**
（静态 10.10.10.1/24，地址池从 .10 起），于是主机端的桌面环境会自己把新接口配好
——不需要 sudo，也不需要手工 `ip(8)`。broker 在这条链路上与 Wi-Fi 时完全一样地
监听。

固件侧是验证过的：控制器初始化成功（`HAL_PCD_Init`/`HAL_PCD_Start`）、ECM 功能
注册完成，OTG 核心自己报告已上电且处于"软连接"状态（`GCCFG.PWRDWN=1`、
`DCTL.SDIS=0`），PA11/PA12 也按 Zephyr 自带 pinctrl 定义复用为 AF10。

缺的是链路本身：**主机完全看不到这个 USB 设备**。在这台调试机上 `journalctl -k`
没有任何记录 —— 即使固件把 D+ 上拉电阻做了断开/接通循环，任何 xHCI 主机都会
报告该事件；也就是说这个口到 PC 之间什么都没有传过去，固件只能一直等一个不会
出现的主机。硬件侧建议按顺序排查：

* 换一根线（充电线没有数据线芯），优先 **USB-A → USB-C** 而不是 C-to-C：按旧式
  设备接法布线的 Type-C 母座需要 5.1 kΩ 的 CC 下拉，没有的话 Type-C 主机口根本
  不会启用该端口；
* 换一个主机口（直连机器，不要经过 hub/dock）；
* 确认插的是 ART-Pi 的哪个接口（枚举成功后 `lsusb` 会显示 `2fe3:0100`）。

线一旦被主机接受，固件不需要再改：主机会从板子拿到租约，broker 就在
`10.10.10.1:1883`（MQTT）、`:8081`（REST，Basic 认证）、`:8083/mqtt`（WebSocket）
上可达，之后 `tools/verify.sh 10.10.10.1` 那套门禁同样适用。

## 环境与前置条件

* 一个 Zephyr ≥ 4.4 的 west 工作区及其 Python venv —— `west` 和 `pyocd` 都在
  这个 venv 里，不在系统 `PATH`：
  ```sh
  source ~/zephyr-venv/bin/activate
  export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
  ```
  Fedora 环境搭建指南与 ESP32-S3 同类 demo 共用：
  [English](../nanomq_zephyr_esp32s3/setup-fedora-en.md) /
  [简体中文](../nanomq_zephyr_esp32s3/setup-fedora-zh.md)。

* **先应用仓库外的补丁。** 本 demo 需要三处本仓库之外的改动（Zephyr 树与一个
  west 模块），都在 [patches/](patches/) 里，基线版本见
  [patches/README.md](patches/README.md)。仓库内的改动（本 demo 目录本身、
  `nng` 子模块里 STM32 的 `SUCCESS` 重命名）走分支，不放在补丁里。

* **先抓一次 Infineon blob**：43438 固件镜像不在 git 里，没有它
  `CONFIG_WIFI_AIROC` 就没有 blob 可嵌入：
  ```sh
  west blobs fetch hal_infineon     # 需要接受 Infineon 许可
  ```

* **厂商 QSPI 烧写算法**：`tools/ART-Pi_W25Q64.FLM` 同样从 ART-Pi SDK 取
  （它被 git-ignore，不随仓库分发）：
  ```sh
  git clone --depth 1 --filter=blob:none --no-checkout \
      https://github.com/RT-Thread-Studio/sdk-bsp-stm32h750-realthread-artpi /tmp/artpi_sdk
  git -C /tmp/artpi_sdk show HEAD:debug/flm/ART-Pi_W25Q64.FLM \
      > demo/nanomq_zephyr_stm32_art-pi/tools/ART-Pi_W25Q64.FLM
  ```

* 板载 ST-Link 对应 `/dev/ttyACM0`（串口控制台 + SWD 探针）；建议为探针加一条
  udev 规则。`pyocd 0.45` 需要
  [tools/artpi_flash.py](tools/artpi_flash.py) 里说明的 board-ID 规避（该文件
  已内置）。

## 构建

```sh
west build -b art_pi demo/nanomq_zephyr_stm32_art-pi -- \
    -DEXTRA_CONF_FILE="local.conf;wifi.conf" \
    -DEXTRA_DTC_OVERLAY_FILE=boards/art_pi_wifi.overlay
```

`local.conf` 被 git-ignore，请从 [local.conf.example](local.conf.example) 复制。
Wi-Fi 凭据放在 `CONFIG_BROKER_WIFI_SSID/PSK`（应用 Kconfig），不会进入代码树。
不加 `-d` 时 `west build` 使用的是**相对于当前目录**的 `build/`；下面的辅助
脚本默认使用仓库根下的 `build/nanomq_zephyr_stm32_art-pi`。

## 烧写

```sh
# 构建 + 烧写；默认就是 Wi-Fi 变体（也是本 demo 验证过的那套）
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh

# 也可以显式指定网络层；--no-build 表示只烧上一次的构建产物
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --wifi    # 默认
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --eth
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --usb
```

默认选 `--wifi` 是有意的：它是唯一不需要额外硬件就能连上局域网的变体。`--eth` 和
`--usb` 都需要对端有一根活线；在调试台上没有线时它们会起来之后一直停在
`eth: still no link ...` / `usb: no carrier ...` —— 看起来像板子坏了，其实只是选错
了变体。

`tools/flash.sh` 先构建，然后调用
[tools/artpi_flash.py](tools/artpi_flash.py)：它把厂商的 CMSIS 烧写算法
（`ART-Pi_W25Q64.FLM`）加载到 SRAM4，复位目标（该 loader 假定时钟/缓存/外设
都是初始状态），再通过 SWD 把 ELF 的 load 段写进 0x90000000 的 QSPI 窗口；
只擦除镜像覆盖到的扇区。最后它会再复位并 resume 一次目标：pyocd 在烧写结束后会
把内核留在 halted 状态，不做这一步，镜像就要等到下次上电才会启动。

第一次烧写会覆盖 QSPI slot0 里的出厂 RT-Thread 应用（可用 ART-Pi SDK 的
`projects/art_pi_factory` 重新构建）。内部 Flash 里的出厂 **bootloader** 不受
影响，控制台上那句 `Powered by RT-Thread.` logo 正是它打印的 —— 那是
bootloader 的横幅，不代表 demo 没跑起来。

## 控制台与启动日志

控制台就是 ST-Link 的虚拟串口：`/dev/ttyACM0`、115200 8N1，没有登录，只有启动
日志和 broker 打印的一切。它是观察板子状态唯一的窗口，烧写之后第一件事就该看它。

### 打开 / 抓取

```sh
# 实时查看（Ctrl-C 退出）
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh

# 同时写文件
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o boot.log

# 先丢掉串口缓冲里的旧数据（原因见下文"区分两次启动"）
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o boot.log --drain 10
```

任何 115200 8N1 的终端都一样：`tio /dev/ttyACM0`、
`picocom -b 115200 /dev/ttyACM0`、`minicom -D /dev/ttyACM0`；纯抓取就是：

```sh
stty -F /dev/ttyACM0 115200 raw -echo      # 8N1、无流控、不回显
cat /dev/ttyACM0 | tee boot.log            # Ctrl-C 结束
```

`tools/flash.sh` 退出时板子已经复位并在运行，所以启动日志立刻就在线上了 —— 想从
第一行看起就先开抓取。**同一时刻只能有一个读端**：第二个 `cat`/`minicom` 会把数据
流分走，两边看起来都像被截断。

### 一次正常启动应该长什么样

Wi-Fi 构建（`local.conf;wifi.conf` + `boards/art_pi_wifi.overlay`），烧写后立即抓取：

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

逐行解读：

* `Powered by RT-Thread.` / `msh >` —— 这是 **ART-Pi 出厂 bootloader** 自己的
  横幅，它在映射好 QSPI 之后才跳到 demo。它既不表示 demo 没起来，也不表示
  RT-Thread 在跑 broker。
* `sdhc_stm32: SDHC Init Passed Successfully`，随后
  `sd: Card does not support CMD8` —— SDIO 主机起来了、Wi-Fi 卡被按 legacy
  （SDIO 而非 SD）卡枚举。这里 `Card does not support CMD8` 是正常现象。
* `WLAN MAC Address`、`WLAN Firmware`、`WLAN CLM`、`WHD VERSION` —— Infineon
  WHD 与芯片通信时的原始 `printf` 输出。MAC 就是本板 AP6212 的；固件/CLM 版本
  正是 demo 加载的资源（见上文硬件部分）。这几行出现在 Zephyr 横幅**之前**，
  是因为原始 `printf` 不走日志子系统，纯属观感问题。
* `*** Booting Zephyr OS build v4.4.0-4779-g11a87708d415 ***` —— demo 本体，
  也就是 `main()` 开始干活的时刻。
* `wifi: connecting to "<SSID>"` → `wifi: connected` →
  `wifi: IPv4 address assigned (DHCPv4)` —— `src/main.c` 的 STA 流程。
* `net_ipv6_nd: DAD failed, no ll IPv6 address!` 是**预期内的错误级别日志**：
  网络栈开了 IPv6，但这条链路没有 IPv6，重复地址检测无事可做。broker 用 IPv4。
* `NanoMQ Broker is started successfully!` 以及上面两行 `broker:`/`web_server:`
  —— REST 监听在 `:8081`，MQTT 在 `:1883`，WebSocket 在 `:8083/mqtt`。
* `net: ipv4 192.168.x.y` —— `tools/verify.sh` 需要的就是这个地址。
* 之后每分钟一行：`broker: status running — uptime 64s, MQTT
  tcp://0.0.0.0:1883, REST http://0.0.0.0:8081, WS :8083/mqtt, ipv4
  192.168.1.3`。**上面那段 broker 启动日志只在启动瞬间打印一次**，晚接上控制台
  就再也看不到了 —— 这行心跳就是"它还在跑吗、地址是多少"的随时答案
  （`CONFIG_BROKER_STATUS_INTERVAL_S`，默认 60 秒，设 0 关闭）。不想看控制台的话，
  `curl -u <user>:<pass> http://<ip>:8081/api/v4/brokers` 也能回答同一个问题。

其他变体形状相同：以太网构建里是 `eth: waiting for link` /
`net_dhcpv4: Received: ...` 取代 `wifi:` 那几行；USB-ECM 构建里是
`usb: carrier up` / `usb: DHCPv4 server started`（见上文各变体一节）。

时间戳：板子没有带电池的 RTC，所以 nanolib 的墙钟时间戳默认是 1970 epoch；启用
`CONFIG_BROKER_SNTP`（见 `local.conf.example`）后，main.c 会在 DHCP 绑定后从
公共 NTP 服务器给 `CLOCK_REALTIME` 播种。Zephyr 自己的 `<inf>`/`<err>` 行携带的
是内核 uptime。Zephyr 没有时区数据库，显示的时间一律是 UTC。

### 区分两次启动，以及其他控制台“怪现象”

* **串口有缓冲，抓取时可能先把上一次启动重放出来。** ST-Link 的 VCP 会把最后的
  输出留在缓冲区里；复位后立刻开始的抓取，常常先出现上一次启动的尾巴 —— 所以一份
  日志里可能出现两个 `Powered by RT-Thread.` 横幅、两行
  `*** Booting Zephyr OS ... ***`。这不是重启循环，**按最后一个横幅切分**，或者用
  `tools/console.sh --drain <秒数>`。
* **行间的 `--- N messages dropped ---`** 表示 Zephyr 日志缓冲区溢出，因为
  115200 的控制台跟不上（有东西在循环打印时就会出现，见下条）。与数据面无关。
* **烧完串口却是静默的**，通常是内核被留在 halted，而不是镜像有问题：pyocd 在
  烧写结束时会把目标停在 halted，所以 `tools/artpi_flash.py` 结尾会再复位并
  resume 一次。用别的方式烧写时，记得自己复位一下。
* **`sdhc_stm32: Command response timeout` 反复出现**（大约在启动 4 分钟后开始）是
  已知且**非致命**的状态：WHD 的后台状态轮询（替代芯片 SDIO 中断的那套，见
  ADR 0003）开始失败，而 WLAN 数据面仍在正常工作 —— **它出现期间整套功能测试依然
  全绿**，复位板子即恢复。驱动对这条消息做了限流，所以你看到的是每 5 秒一行，旁边
  带着真实速率：

  ```
  [00:04:11.518,000] <err> sdhc_stm32: Skipped 1621 messages
  [00:04:11.518,000] <err> sdhc_stm32: Command response timeout
  ```

  （约 324 次/秒，压成一行；限流之前这里每分钟是上千行。）有个副作用值得记住：
  **`ping` 可能失败但 TCP 仍然可用**，所以判断 broker 是否在线请用
  `tools/verify.sh <ip>`（或 `curl` 打 `:8081`），不要用 `ping`。
* **板子上现在是哪个变体？** 日志写得很明白：`wifi: connecting to "<SSID>"` /
  `wifi: connected` 是 Wi-Fi 构建，`eth: waiting for link` /
  `net: iface ... dev=ethernet@40028000` 是以太网构建，
  `usb: starting the device stack (CDC-ECM)` 是 USB-ECM。看错变体就
  `tools/flash.sh --wifi` 重新烧一次。

## 验证

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/verify.sh <board-ip>
```

它会对板子运行
[demo/nanomq_zephyr_qemu_x86/function_test.py](../nanomq_zephyr_qemu_x86/function_test.py)
的三个验收门禁（带 `--no-manage`，套件不会去拉 qemu）。加 `--full` 可再加
WebSocket 与容量/健壮性分组。

套件会自适应硬件：它先测 TCP 往返，只要地址不是 loopback 就默认
`--time-scale 4 --retry 2` —— 因为 CI 脚本里的 sleep 按 localhost 调的，
其中两个子用例本身也有竞态。本调试台上实测 RTT 约 30–100 ms，正是这两项让
`mqtt_v5` 稳定通过。但它不是保证：有一次链路拥塞（RTT 约 200 ms，平时约 3 倍）
时 `mqtt_v5` 两次重试都没过，紧接着重跑就通过了。遇到只有 `mqtt_v5` 失败，先
重跑再排查。

### 实机验证记录（2026-09-27）

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

更早那次（还带着 bring-up 探针的构建）同样过了这三道门禁，那次
`mqtt_v5` 跑了 235.8s —— 因为 `retain-as-published` 在这个调试台上本身有竞态，
重试一次后才通过。

**全部**分组（再加两个 WebSocket 分组与健壮性分组）也是全绿：

```
broker connect RTT 19.3 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311 PASS 64.1s   mqtt_v5 PASS 118.2s   rest_get PASS 1.1s
ws_v311   PASS 260.5s  ws_v5   PASS 7.7s     capacity PASS 7.5s
ws_abort  PASS 11.5s
RESULT: pass=7 fail=0
```

唯一没跑过的是 `webhook_smoke`：demo 默认不编 webhook 转发器，而打开
`CONFIG_BROKER_WEBHOOK=y` 的构建会让 SDIO 链路很快卡死（见下方已知限制）。

Wi-Fi 链路：2.4 GHz WPA2 AP，MAC `70:4A:0E:51:77:9A`，固件
`7.45.98.117`，WHD `3.3.3.26653`，DHCPv4 租约 `192.168.1.3`；MQTT :1883、
REST :8081、WebSocket :8083 均在监听（REST `/api/v4/brokers` 返回
`node_status: Running`、`version 0.25.6-8`）。

## 配置文件

| 文件 | 用途 |
| --- | --- |
| [prj.conf](prj.conf) | demo 本体：POSIX API 预算、网络池、SDRAM 堆、REST + WebSocket 监听。 |
| [wifi.conf](wifi.conf) | Wi-Fi 构建：AIROC/WHD + SDMMC2 主机 + Zephyr Wi-Fi mgmt API，以及 43438 资源选择。需与 `boards/art_pi_wifi.overlay` 搭配。 |
| [eth.conf](eth.conf) | 以太网变体（不带 Wi-Fi overlay）。本机未验证，见上文。 |
| [usb.conf](usb.conf) | USB-ECM 变体（板子是 USB 设备，也是这条链路的 DHCP 服务器）。需与 `boards/art_pi_usb.overlay` 搭配，见上文。 |
| [boards/art_pi.overlay](boards/art_pi.overlay) | QSPI XIP、关 LTDC、SDMMC2 + `airoc-wifi` 节点、PHY 复位线。 |
| [boards/art_pi_wifi.overlay](boards/art_pi_wifi.overlay) | Wi-Fi 构建：关掉 `&mac`/`&mdio`/`&eth_phy`，保证只有一个网络接口。 |
| [boards/art_pi_usb.overlay](boards/art_pi_usb.overlay) | USB-ECM 构建：关掉 `&sdmmc2`、`&mac`、`&mdio`、`&eth_phy`，只留 ECM 这一个接口。 |
| [local.conf.example](local.conf.example) | 复制为 `local.conf`：REST 凭据、Wi-Fi SSID/PSK，以及可选的 webhook/SNTP/DEBUG。 |
| [wifi_dbg.conf](wifi_dbg.conf) | 诊断：Zephyr DEBUG 日志 + WHD 追踪，用于 SDIO bring-up。 |
| [wifi_whddbg.conf](wifi_whddbg.conf) | 诊断：只开 WHD 追踪（`WPRINT_ENABLE_WHD_DEBUG`），包含固件/CLM 下载后的回读校验。 |
| [wifi_crash.conf](wifi_crash.conf) | 诊断：立即日志 + 致命错误不自动复位，便于调试器查看 faulting core。 |

## 已知限制 / 后续工作

* Wi-Fi 中断走的是轮询而不是中断（`CONFIG_AIROC_WIFI_WHD_POKE`，在 `wifi.conf`
  里打开）。in-band 控制器路径和 out-of-band host-wake 引脚都试过且在这块板子
  上不可行，厂商栈同样靠轮询。详见
  [../../docs/adr/0003](../../docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md)。
* 链路起来几分钟后，这套 backplane 轮询会开始失败，控制台被
  `sdhc_stm32: Command response timeout` 刷屏。它**不致命** —— 刷屏期间
  MQTT/REST/WebSocket 各分组依然全绿，复位板子即恢复 —— 但这种状态下 ICMP 可能
  失败，所以判断 broker 在线与否请用 TCP（`tools/verify.sh <ip>`、`curl`），不要
  用 `ping`。
* **webhook 不是"打开开关"就能用的**：编了 `CONFIG_BROKER_WEBHOOK=y` 的构建能连上
  Wi-Fi 并拿到地址，但随后 SDIO 链路几乎立刻卡死（同样是
  `Command response timeout` 刷屏），因此 `webhook_smoke` 分组在这个构建上没能
  跑起来。该配置下内部 SRAM 已到约 88 %，转发器需要更多空间；先给 SRAM 预算腾出
  余量（或搬走某个内存池）再启用它。`prj.conf` 因此保持关闭。
* 现在用的 CLM 是 AW-CU427-P 模块的 —— 这颗芯片公开发布的只有这一份。链路可用
  且芯片接受它，但它并不是本模块的校准数据。
* Wi-Fi 构建下内部 SRAM 已用 86 %，余量不多，不适合更高的并发连接数。
* 以太网变体未验证（本机 PHY 无响应）。
* `CONFIG_BROKER_WEBHOOK` 默认关闭（见上），所以套件的 webhook 分组会报告 SKIP，
  除非专门做一个有余量的构建。权衡见 ESP32-S3 的 README。

## 参考

* [docs/zh_CN/port-to-art-pi.md](docs/zh_CN/port-to-art-pi.md) /
  [docs/en_US/port-to-art-pi.md](docs/en_US/port-to-art-pi.md) —— 移植记录：
  与 ESP32-S3 同类 demo 的差异、各环节踩坑顺序与证据。
* [../../docs/adr/](../../docs/adr/) —— QSPI XIP 与 SDRAM 堆两个决策，以及记录
  "为什么 Wi-Fi 用轮询而不是中断"的 ADR 0003。
* [../nanomq_zephyr_esp32s3/README.md](../nanomq_zephyr_esp32s3/README.md) ——
  本 demo 的蓝本（PSRAM、ESP-IDF 工具链、webhook）。
* [../../docs/zh_CN/tutorial/port-to-zephyr.md](../../docs/zh_CN/tutorial/port-to-zephyr.md)
  —— 通用的 Zephyr 移植教程。
* [../../CONTEXT.md](../../CONTEXT.md) —— 这些文档使用的术语（Zephyr broker
  demo、ART-Pi factory bootloader、broker heap 等）。
