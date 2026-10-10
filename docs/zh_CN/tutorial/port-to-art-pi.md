# NanoMQ 移植到 Zephyr RTOS：把 broker 搬到 ART-Pi（STM32H750）

## 引言

本文是 [NanoMQ 移植到 Zephyr RTOS：把 MQTT Broker 跑在 MCU 上](./port-to-zephyr.md)的 ART-Pi 篇。那篇文章讲清楚了为什么要把 broker 核心搬到 Zephyr，以及最早验证的两个目标：ESP32-S3（Wi-Fi 实机）和 `qemu_x86`（仿真）。这一篇记录的是第三个目标 `demo/nanomq_zephyr_stm32_art-pi`：一块带板载 Wi-Fi 模块和 32 MB SDRAM 的 ARM Cortex-M7 板子。

本文按问题**实际出现的顺序**来写：有三个互不相同的故障，从控制台看却完全一样（`airoc_wifi_init_primary failed ret = -19`、没有链路、没有 DHCP），每一个第一眼都像是另外两个。

本移植的验收标准：可构建、**实机验证**、与另外两个 demo **功能对等**。功能套件的三个硬性门禁在实机上全部通过，除 webhook 分组外的全部分组也全绿（原因见"运行功能测试"一节）。

## 关于 ART-Pi

ART-Pi 是睿赛德（RT-Thread 团队的硬件分支）围绕 **STM32H750XBH6** 设计的开发板：480 MHz Cortex-M7，1 MB 内部 SRAM，32 MB FMC SDRAM，8 MB QSPI flash，外加一颗 **AP6212** 模块，其 Wi-Fi 侧是挂在 SDIO 上的 Infineon CYW43438。它正好各踩了本移植关心的两类约束：MCU 本身与 ESP32-S3 同一量级，但 broker 周围的一切都不一样：镜像放在哪、堆放在哪、射频怎么接。

应用层没有被改动：`src/main.c` 就是 ESP32-S3 那份，Wi-Fi bring-up 原样保留，旁边补了一条以太网路径；`src/process_stub.c` 也还是 NanoMQ POSIX `process.c` 的替身。真正要改的是板级支持与网络层：

| 维度 | ESP32-S3 | ART-Pi | 后果 |
| --- | --- | --- | --- |
| SoC | ESP32-S3（Xtensa） | STM32H750XBH6（Cortex-M7） | 32 位原子操作预算，以及 CMSIS `SUCCESS` 重名（见附录 A） |
| 代码存储 | 16 MB flash，借助其缓存原地执行 | 128 KB 内部 flash，已被出厂 bootloader 占满 | 镜像必须链接进 0x90000000 的 8 MB **QSPI** 窗口 |
| 数据面 | 16 MB 八线 PSRAM，4 MB 堆窗口 | 32 MB FMC SDRAM，4 MB `k_heap` | 分配器接法不同，且没有 PSRAM 的 shared multi heap |
| 网络 | ESP32 Wi-Fi（ESP-IDF blob） | 板载 **AP6212 = CYW43438**，SDMMC2 上的 SDIO | 走 Infineon AIROC/WHD，SDIO 主机胶水是 STM32 SDMMC |
| 显示 | LCD（未用） | LTDC 会从 broker 堆里抢 SDRAM | overlay 里关掉 `&ltdc` |
| 时钟 | Wi-Fi 驱动给 SNTP 播种 | 同样做法，可选（`CONFIG_BROKER_SNTP`） | 无 |

## 环境搭建

### 前置条件

环境就是[主篇](./port-to-zephyr.md)搭好的那套：一个 Zephyr ≥ 4.4 的 west 工作区，以及其中提供 `west` 和 `pyocd` 的 Python 虚拟环境，并已导出 `ZEPHYR_SDK_INSTALL_DIR`。这块板子有两处特殊：

* ART-Pi 的 ST-Link 同时提供串口控制台和 SWD 探针，一根 USB 线就够，通常是 `/dev/ttyACM0`；建议为探针配一条 udev 规则。
* `pyocd 0.45` 在这颗探针上需要一个 board-ID 规避，`tools/artpi_flash.py` 里已经内置（见"移植过程"第 2 条）。

### 获取源码与树外补丁

ART-Pi demo 位于仓库 `zephyr-rtos` 分支的 `demo/nanomq_zephyr_stm32_art-pi/` 下。它还需要三处落在这个目录**之外**的改动，两处在 Zephyr 树、一处在 west 模块，因为它们无法随本仓库的分支一起走：

| 补丁 | 所在仓库 | 作用 |
| --- | --- | --- |
| `patches/0001-zephyr-sdhc-stm32-sdio-card-interrupt.patch` | Zephyr 树 | 给 STM32 SDMMC 主机补上 SDIO 卡中断支持（此前 `enable_interrupt` / `disable_interrupt` 根本没有实现） |
| `patches/0002-zephyr-airoc-whd-sdio-bring-up.patch` | Zephyr 树 | WHD 线程的 poke 定时器与省电修复（两者都是 Kconfig 选项），以及 WHD 胶水里 CYW43438 的 CLM/NVRAM 接线 |
| `patches/0003-infineon-whd-43438-art-pi-resources.patch` | west 模块 `hal_infineon` | 本模块的 43438 NVRAM，单独放一个文件 |

补丁是从通过验收的那份代码生成的，适配的基线版本记录在 `patches/README.md` 里。构建前先应用：

```sh
ZEPHYR_WORKSPACE=~/zephyrproject          # 你的 west 工作区
PATCHES=$PWD/demo/nanomq_zephyr_stm32_art-pi/patches

git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0001-zephyr-sdhc-stm32-sdio-card-interrupt.patch
git -C $ZEPHYR_WORKSPACE/zephyr apply $PATCHES/0002-zephyr-airoc-whd-sdio-bring-up.patch
git -C $ZEPHYR_WORKSPACE/modules/hal/infineon apply $PATCHES/0003-infineon-whd-43438-art-pi-resources.patch
```

### 拉取 Infineon blobs

43438 的固件镜像不在 git 里，缺了它 `CONFIG_WIFI_AIROC` 就没有可内嵌的 blob：

```sh
west blobs fetch hal_infineon
```

### 厂商的 QSPI 烧写算法

烧写 QSPI 那颗芯片需要厂商的 CMSIS 烧写算法（`ART-Pi_W25Q64.FLM`），它从 ART-Pi SDK 取，不随本仓库分发：

```sh
git clone --depth 1 --filter=blob:none --no-checkout \
    https://github.com/RT-Thread-Studio/sdk-bsp-stm32h750-realthread-artpi /tmp/artpi_sdk
git -C /tmp/artpi_sdk show HEAD:debug/flm/ART-Pi_W25Q64.FLM \
    > demo/nanomq_zephyr_stm32_art-pi/tools/ART-Pi_W25Q64.FLM
```

## 编译与运行：ART-Pi 实机

### 1. 配置本地凭据（Wi-Fi 与 REST）

Wi-Fi 凭据和 REST 凭据都是站点相关的，所以放在 git-ignored 的 `local.conf` 里，从 `local.conf.example` 复制：

```sh
cp demo/nanomq_zephyr_stm32_art-pi/local.conf.example \
   demo/nanomq_zephyr_stm32_art-pi/local.conf

# 然后编辑：
#   CONFIG_BROKER_WIFI_SSID="<你的 AP>"
#   CONFIG_BROKER_WIFI_PSK="<口令>"
#   CONFIG_BROKER_REST_USER="<用户名>"   # 这两个不设，
#   CONFIG_BROKER_REST_PASS="<密码>"     # REST 监听就不启动
```

REST 是可选的，但它正是套件里 `rest_get` 分组要测的东西；不设凭据时该分组会报 SKIP，而不是失败。

### 2. 编译

本 demo 链接进 QSPI 窗口而不是内部 flash，而这来自应用自己带的 overlay，所以光敲 `west build -b art_pi` 得到的镜像装不进 broker。`tools/flash.sh` 会用正确的参数一次完成编译与烧写：

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh --wifi
```

`--wifi` 是默认值，也是本文验证过的唯一变体；它会带上 `wifi.conf` 与 `boards/art_pi_wifi.overlay`，后者同时关掉以太网相关节点，让镜像里只有一个网络接口。只想编译的话：

```sh
west build -b art_pi demo/nanomq_zephyr_stm32_art-pi -- \
    -DEXTRA_CONF_FILE="local.conf;wifi.conf" \
    -DEXTRA_DTC_OVERLAY_FILE=boards/art_pi_wifi.overlay
```

### 3. 烧录

`tools/flash.sh` 先构建，再调用 `tools/artpi_flash.py`：它把厂商的 CMSIS 烧写算法加载到 SRAM4，复位目标（该 loader 会从头重配时钟、缓存和 QUADSPI，若继承一个正在运行的应用的配置就会超时），然后只擦写镜像覆盖到的扇区，通过 SWD 写进 0x90000000 的 QSPI 窗口，最后再复位并 resume 一次，因为 pyocd 在烧写结束后会把内核留在 halted 状态，少了这次复位，镜像要等下次上电才会启动。

第一次烧写前有两点值得知道：

* 它会覆盖 QSPI slot0 里的出厂 RT-Thread 应用。该应用可以用 ART-Pi SDK 的 `projects/art_pi_factory` 重建；内部 flash 里的出厂 **bootloader** 不受影响。
* `--dry-run` 只加载烧写算法并报告计划、不写入，但之后不会复位目标；停在那里的板子会一直待在 bootloader 的 `msh >` 提示符，直到下一次真正烧写或复位。

### 4. 查看串口

没有登录，115200 8N1 上就是启动日志和 broker 的输出：

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh             # 实时查看，Ctrl-C 退出
demo/nanomq_zephyr_stm32_art-pi/tools/console.sh -o boot.log # 同时写文件
```

ST-Link 的虚拟串口会缓冲，所以复位后立刻开始的抓取，可能先把**上一次**启动重放出来，一份日志里会出现两个 `Powered by RT-Thread.` 横幅和两条 `*** Booting Zephyr OS ***`。读之前按最后一个 bootloader 横幅切分，或者先丢缓冲：`console.sh --drain <秒>`。同一时刻只能有一个读者：输出看起来被截断或交织时，先确认没有别的 `cat`/`minicom`/`tio` 还占着这个口。

### 5. 验证连接

`tools/verify.sh` 把功能套件封装成对一块已在运行的板子执行：

```sh
demo/nanomq_zephyr_stm32_art-pi/tools/verify.sh <板子IP>
```

broker 的 REST API 是个快速的手工检查：

```sh
curl -u <用户名>:<密码> http://<板子IP>:8081/api/v4/brokers
```

### 一次正常启动长什么样

烧写完成后立刻抓取：

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

逐行读：

* `Powered by RT-Thread.` / `msh >`：**ART-Pi 出厂 bootloader** 自己的横幅，它在映射好 QSPI、跳到 demo 之前打印。它既不表示 demo 没起来，也不表示 RT-Thread 在跑 broker。
* `sdhc_stm32: SDHC Init Passed Successfully`，随后 `sd: Card does not support CMD8`：SDIO 主机起来了，Wi-Fi 卡被按 legacy（SDIO 而非 SD）卡枚举。这里 `Card does not support CMD8` 是正常现象。
* `WLAN MAC Address`、`WLAN Firmware`、`WLAN CLM`、`WHD VERSION`：Infineon WHD 与芯片通信时的原始 `printf` 输出。MAC 是本板 AP6212 的，固件与 CLM 就是 demo 加载的资源。这几行出现在 Zephyr 横幅**之前**，是因为原始 `printf` 不走日志子系统，纯属观感问题。
* `*** Booting Zephyr OS ... ***`：demo 本体，`main()` 开始干活的时刻。
* `wifi: connecting to "<SSID>"` → `wifi: connected` → `wifi: IPv4 address assigned (DHCPv4)`：`src/main.c` 的 STA 流程。这些行会走 Zephyr 日志（本构建里 `printk` 被接进了 deferred 日志线程），而 nanolib 的 `printf` 直接写控制台，所以 `NanoMQ Broker is started successfully!` 可能夹在 `wifi: connecting` 和 `wifi: connected` 之间，同样是观感问题。
* `net_ipv6_nd: DAD failed, no ll IPv6 address!` 是**预期内的错误级别日志**：网络栈开了 IPv6，但这条链路没有 IPv6，重复地址检测无事可做。broker 用 IPv4。
* `NanoMQ Broker is started successfully!` 以及两行 `broker:`/`web_server:`：REST 监听在 `:8081`，MQTT 在 `:1883`，WebSocket 在 `:8083/mqtt`。
* `net: ipv4 192.168.x.y`：`tools/verify.sh` 需要的地址。
* 之后每分钟一行：`broker: status running — uptime 64s, MQTT tcp://0.0.0.0:1883, REST http://0.0.0.0:8081, WS :8083/mqtt, ipv4 192.168.1.3`。broker 的启动横幅**只在它启动时打印一次**，晚接上控制台只能看到心跳；心跳存在的意义就是让"它还在跑吗、地址是多少"不再依赖是否赶上了启动瞬间。

## 运行功能测试

功能套件是三个 demo 共用的，安装与运行方式见[主篇](./port-to-zephyr.md)。在一块走 Wi-Fi 的板子上有两点特殊：

`function_test.py` 是按 qemu/localhost 写的：里面 CI 脚本的 sleep 都假定 broker 在本机。对这块板子实测 TCP 往返是 30–100 ms，所以套件里那条"非 localhost"启发式（`function_test.py` 一行改动：非回环地址 ⇒ `--time-scale 4 --retry 2`）才是让整轮稳定通过的关键：拉大的时间尺度覆盖按 localhost 调的 sleep，重试覆盖两个本身就有竞态的子用例（本调试台上 `mqtt_v5` 的 `retain-as-published` 第一次失败，重试通过）。`tools/verify.sh <board-ip>` 把这套封装好了。

它是启发式而非保证：有一次链路拥塞（RTT 约 200 ms，约为平时 30–100 ms 的 3 倍）时 `mqtt_v5` 两次重试都没过，紧接着重跑就通过了。只有 `mqtt_v5` 失败时，先重跑再排查。

实机验收（2026-09-27）：

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

更早一次（带 bring-up 探针的构建）同样通过，那次 `mqtt_v5` 跑了 235.8s，因为 `retain-as-published` 在这个调试台上本身有竞态，套件重试一次后通过。其中有一次验收是**故意**在控制台正被 `sdhc_stm32: Command response timeout` 刷屏的状态下跑的（见"移植过程"第 8 条），正是这一跑确认了该状态不致命：门禁照样全绿。

全部分组（加上两个 WebSocket 分组与健壮性分组）同样全绿（`verify.sh <ip> --full` → `pass=7 fail=0`：在三道门禁之外，`ws_v311` 260.5s、`ws_v5` 7.7s、`capacity` 7.5s、`ws_abort` 11.5s）。这一轮还发现 demo 自带脚本的一个 bug：`verify.sh --full` 会把一个空参数转发给套件（`${@/--full/}` 替换后会留下一个空串），argparse 直接报错；现在该标志已被正确过滤。

`webhook_smoke` 是唯一的例外：它需要一个打开 `CONFIG_BROKER_WEBHOOK=y` 并把接收端地址编进固件的构建；这种构建能连上 Wi-Fi 并拿到地址，但随后 SDIO 链路几乎立刻卡死（同样是 `Command response timeout` 刷屏）。该配置下内部 SRAM 已到约 88 %，转发器需要更多空间，因此这个分组没能跑起来，demo 也就默认保持 webhook 关闭。

同一时刻的链路状态：`wifi: connected`、DHCPv4 `192.168.1.3`、MQTT :1883 / REST :8081 / WebSocket :8083 均在监听、`NanoMQ Broker is started successfully!`，REST `/api/v4/brokers` 返回 `node_status: Running`。

链路恢复（"移植过程"第 9 条）之后单独做了一轮实机验证。用一个临时构建（钩子没有提交）在启动 180 秒后发 `NET_REQUEST_WIFI_DISCONNECT`，**并且**故意不注册 `NET_EVENT_WIFI_DISCONNECT_RESULT`，也就是说只能靠守护线程的状态轮询发现掉线，对应的是"AP 悄悄消失"，而不是会发事件的那条路：

```
selftest: NET_REQUEST_WIFI_DISCONNECT -> 0                (uptime 180 s)
[00:03:07.558] <err> sdhc_stm32: Command response timeout  <- leave 序列
wifi: link down — reconnecting to "TP-LINK_A57B"          (uptime 约 188 s)
wifi: connected to "TP-LINK_A57B"
[00:03:13.738] <inf> net_dhcpv4: Received: 192.168.1.8
wifi: IPv4 address assigned (DHCPv4)
broker: status running — uptime 244s, ... , ipv4 192.168.1.8
```

轮询在掉线 7 秒后（10 秒周期之内）就发现了，重新关联加重新拿租约又花了约 6 秒，拿回的是同一个地址，broker 全程没有重启，监听端口也没有重开。那条 `Command response timeout` 属于 leave 序列，不是第 8 条的 KSO 刷屏：它只在切换时出现一次，之后不再出现。

## 移植过程

### 1. 先把镜像弄进板子：QSPI XIP 与出厂 bootloader

ART-Pi 的内部 flash 里是睿赛德/RT-Thread 的**出厂 bootloader**。它把 QUADSPI 映射好，然后跳到 0x90000000 处的向量表，所以本 demo 不需要自己当一级 loader，只要**在那个位置**就行：

```dts
/ { chosen { zephyr,flash = &ext_memory; }; };   /* 8 MB QSPI, 0x90000000 */
```

有两个必须说清楚的后果：

* **QSPI 驱动必须保持关闭**（`CONFIG_FLASH` / `FLASH_STM32_QSPI`）。它的初始化会去重配 CPU 正在取指的那个外设。本 demo 没有文件系统，关掉没有损失。
* 直接 `west build -b art_pi` 会把镜像链进 128 KB 内部 flash，装不下 broker，所以设置 `zephyr,flash` 的 overlay 是必需的，`tools/flash.sh` 存在的理由也在这里。

### 2. 让镜像跑起来路上的工具坑

* **pyocd 0.45 + 这颗 ST-Link。** 连接阶段 pyocd 会发 `JTAG_GET_BOARD_IDENTIFIERS` 并期待 128 字节；这颗探针只回 2 字节状态，pyocd 于是抛出致命错误 `received incomplete command response from STLink (got 2, expected 128)`，完全无法访问 SWD，尽管探针本身是好的。board ID 只用来生成人类可读的板名，所以 `tools/artpi_flash.py` 在 import 连接助手之前把它屏蔽掉。
* **厂商的烧写算法不是可选项。** `ART-Pi_W25Q64.FLM` 才认识 QUADSPI 后面那颗 W25Q64；pyocd 自带的 `stm32h750xx` 目标既不知道这块区域，也没有这个算法。它不随 demo 分发；获取方式见"环境搭建"里的那一节。
* **在算法运行之前复位，而不是围着它复位。** 厂商 loader 会从头重配时钟、缓存和 QUADSPI，若它继承了一个正在运行的应用的配置就会超时，所以工具先复位并 halt 再烧写。
* **QUADSPI 处于间接模式时，用 SWD 读 0x90000000 会 fault**，所以代码里把该 flash 区域标成 `are_erased_sectors_readable = False`，工具总是整扇区擦写，而不做回读校验。
* **两种"看起来像板子坏了"的症状。** 一是控制台积压：ST-Link 的虚拟串口会把上一次启动重放出来（按最后一个 bootloader 横幅切分，或 `console.sh --drain`）；二是烧写后内核被留在 halted 状态，板子只打印 bootloader 横幅然后就没声了（工具现在会在最后再复位并 resume 一次）。
* **默认构建必须是能跑的那一个。** `tools/flash.sh` 默认构建 Wi-Fi 变体（除非显式给 `--eth`）；早期版本只带 `prj.conf`，也就是以太网变体，在没有网线的调试台上会一直停在 `eth: still no link`。这个错误看起来和"板子坏了"一模一样。
* **刷屏本身就是缺陷。** STM32 SDHC 驱动每失败一条命令就打一行日志，而 Wi-Fi 芯片进入睡眠（第 8 条）后那就是每秒几百次，控制台变成一整面 `Command response timeout` 墙，别的内容都读不到。现在既加了限流（每 5 秒一行，外加 `Skipped N messages` 计数），也把根因本身修掉了。
* **broker 的启动日志只打印一次，而且只在它真的启动时才有。** nanolib 是在 `broker()` 运行过程中宣告它的；晚接上控制台就只能看到驱动在干什么。由此引出的两个修复：启动阶段的 Wi-Fi 连接循环改成**有限次**（以前是无限重试，于是连不上的板子根本不会启动 broker，也就一条相关日志都没有），之后的链路交给守护线程（第 9 条）；以及 demo 现在每 `CONFIG_BROKER_STATUS_INTERVAL_S` 秒（默认 60）打一行状态心跳，带上 uptime、各监听端口和当前 IPv4 地址。

### 3. 以太网：那条"复位线"是误判

ART-Pi 有 STM32 MAC + LAN8720A PHY，所以第一反应是走更简单的路（`eth.conf`）。它始终没起来：用 SWD 驱动的 MDIO 扫描把 0–31 全试了一遍也没找到东西（`phy_mii: PHY (0) ID FFFF`、`HAL_ETH_Init failed`）。最自然的解释是 PHY 被按在复位里，于是 overlay 把 PA3（厂商 BSP 的 `ETH_RESET_PIN`）接成 `reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>`。这没有帮助，看起来就像 PHY 是坏的，直到把这条覆盖**删掉**再试，MAC 反而干净地初始化了、一条 PHY 错误都没有。也就是说 PA3 并不是这块板子的 PHY 复位脚，把它拉低才是让 PHY 沉默的原因；这条覆盖已经从 overlay 里移除。

没有证实的部分需要手头没有的硬件：没有网线时接口会停在 dormant 等 carrier，所以以太网的链路建立、DHCP 与流量都还没测过。Wi-Fi 才是验证过的通路。

### 4. Wi-Fi：SDIO 这一侧要从头搭

Zephyr 的 ART-Pi 设备树完全没提 AP6212 的 Wi-Fi 侧，所以 overlay 自己加了一个 SDMMC2 上的 SDIO 主机和 AIROC 设备节点：

| 信号 | 引脚 | 来源 |
| --- | --- | --- |
| SDMMC2 D0/D1/D2/D3 | PB14/PB15/PB3/PB4（AF9） | 厂商 `projects/art_pi_wifi` 的 CubeMX 配置 |
| SDMMC2 CK/CMD | PD6/PD7（AF11） | 同上 |
| WL_REG_ON | PC13 | `libraries/drivers/drv_wlan.c`：`AP6212_WL_REG_ON` |

`WL_REG_ON` 值得单独点出来：早期根据原理图文本猜的 PI14 得到的是"连 CMD5 都没有响应"，因为芯片根本没上电。厂商驱动自己的 `GET_PIN(C, 13)` 才是权威。PC13 拉高后 SDIO 正常枚举：CMD5、CCCR rev 2、functions 0/1/2 的 CIS、4 位总线、25 MHz。

### 5. 代价最大的坑：in-band SDIO 卡中断始终不来

现象：固件下载成功，WLAN function 就绪（`SDIOD_CCCR_IORDY` 到了 `0x6`），第一条 ioctl 也写进了 function 2（768 + 36 字节），然后就没了。回包从未被读取，每条 ioctl 都超时（`iovar "cap" -> 101580800`，每条 5 秒），最后 `airoc_wifi_init_primary failed ret = -19`。

在 WHD 的设计里这是致命的：`whd_thread_func()` 只有在 `thread_info->bus_interrupt` 被置位（或 `whd_bus_use_status_report_scheme()` 返回真）时才进入接收路径，而该传输层上这个函数返回 `WHD_FALSE`。这个标志只由 SDIO 卡中断处理函数设置。于是：没有卡中断 = 永远收不到帧。

几个"第一嫌疑"是用**目标板内探针**排除的，而不是靠调试器读寄存器（这套组合下 pyocd 的 halt/寄存器访问并不可靠：应用明明在跑，它却报 `LOCKUP` 并返回垃圾值）：

* `SDMMC_MASK.SDIOITIE` **确实**置位了：`enable_interrupt -> MASK=0x00400000`。
* SDMMC 中断本身工作正常：数据搬运时 ISR 会进。
* `SDMMC_STA.SDIOIT` **从未**置位，整个启动过程一次都没有，包括 WHD 卡在 5 秒 ioctl 超时里的那段时间。芯片根本没有断言 DAT1。
* CCCR `INTEN` 已编程（`wr cccr[0x4] = 0x7`），WLAN function 也就绪，也就是主机侧已经完全武装好了。

规避办法（补丁 0002，`CONFIG_AIROC_WIFI_WHD_POKE`）：用一个 20 ms 定时器去戳 `whd_thread_notify_irq()`。这等于把本该由中断送达的唤醒补给线程，它的轮询就能找到排队的回包，初始化链随即走通：

```
[4179] nanomq-probe: iovar "cap" -> 0            （原来是 101580800）
cmd53 rd func2 addr=0x0 size=39 -> 0             （回包被读到了）
WLAN MAC Address : 70:4A:0E:51:77:9A
```

之后又逐条试过"让真正的中断到来"的其他办法，全部被排除：

* **`DCTRL.SDIOEN`**（STM32 SDMMC 的 "SD I/O enable"，即"把 DAT1 当中断线用"）。置位后主机侧确实完全武装好了（`MASK=0x00400000`、`DCTRL=0x00000800`，且该位在传输过程中一直保持），但 `SDMMC_STA.SDIOIT` 依然从不锁存；而且一旦有数据流量，它会让 4 位传输以 `Command response timeout` 刷屏告终，所以现在刻意不设它。
* **1 位总线**（DAT1 不再是数据线而是专用中断线：`bus-width = <1>` 配合 WHD 的 `sdio_1bit_mode`）。结果相同：没有 `SDIOIT`，也没有链路。
* **Out-of-band host-wake。** 厂商 NVRAM 里 `muxenab=0x11`（`0x10` 位 = "HW OOB"），原理图上也有 `GPIO_WIFI_HOST_WAKE` 网络，所以芯片也可能走 out-of-band。按 `wifi-host-wake-gpios = <&gpioe 3 GPIO_ACTIVE_HIGH>` 接上（PE3 是原理图文本里唯一说得通的 MCU 引脚；PI14/PI15 那些命中其实是 LCD 的 LTDC_CLK/LTDC_R0），依然没有任何唤醒；一旦有流量，同样出现 CMD 刷屏。最终不接。

轮询也正是这块板子**厂商栈**的做法：ART-Pi SDK 自带的 Wi-Fi 主机驱动（`libraries/drivers/drv_sdio.c`）从未打开 `SDMMC_MASK.SDIOITIE`，也没有注册任何卡中断回调，它上面那套 WICED 是靠轮询芯片状态寄存器拿中断的。

因为"中断不来"会让**每一条** ioctl 都超时，它顺带制造了两个很有说服力但错误的早期结论：一是"CLM blob 会让芯片卡住"，二是"必须用厂商 SPI flash 里那份打包固件"。这两个都是症状，不是原因。

### 6. NVRAM 必须是本模块的

规避掉中断问题之后，固件仍然在初始化中途放弃，直到 NVRAM 与模块匹配。ART-Pi 上的 AP6212 是 `boardtype=0x0726` 那一款；blob 清单给 CYW43438 配的 AW-CU427-P NVRAM（`boardtype=0x0865`）在这块板子上不工作。权威文本就是厂商自己的 `wifi_nvram_image[]`（`libraries/drivers/drv_wlan.c`：`prodid=0x0726`、`boardrev=0x1101`、`xtalfreq=26000`），补丁 0003 就是把它按 `COMPONENT_43438` 的 NVRAM 装进去，单独放一个文件，另一个模块的校准数据保持不动。

### 7. CLM blob 不是可选项

`whd_wifi_on()` 结尾会发一条 `country` iovar，没有 regulatory 数据时固件会拒绝：

```
[4079] Could not set Country code
airoc_wifi_init_primary failed ret = -19
```

所以本移植在追中断坑期间加的那个 `CONFIG_AIROC_WIFI_NO_CLM` 开关不可能成立。把 43438 的 CLM 接上后，芯片接受并回报：

```
[4399] WLAN CLM : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3
               Creation: 2021-03-28 22:47:33
```

它是 AW-CU427-P 模块的 CLM（Infineon 为这颗芯片公开发布的只有这一份），因此并不是本模块的校准数据，但芯片接受它，链路可用。

### 8. 控制台刷屏：芯片睡着了，而这是被允许的

连接建立约 50 秒后，控制台开始被 `sdhc_stm32: Command response timeout` 填满，限流后每 5 秒一行，但每行都带着 `Skipped ~1500 messages`，也就是每秒约 300 次失败；而 broker 与数据面完全正常（**刷屏期间整套功能测试依然全绿**）。

把 SDHC 驱动的命令按类别统计（临时探针，用完全部移除）后，特征一目了然：

| 命令类别 | 发送 | 失败 |
| --- | --- | --- |
| CMD52，任意 function（寄存器访问，无数据阶段） | ~215 000 | ~108 000 |
| CMD53，function 1，字节模式（SDIO 背板） | ~20 000 | **0** |
| CMD53，function 1，块模式（SDIO 背板） | 412 | **0** |
| CMD53，function 2（WLAN 数据） | ~2 100 | **0** |

只有 CMD52 失败，约占其一半，而第一条失败的永远是 `CMD52 write, function 1, address 0x1001F, value 1`，也就是写进 `SDIO_SLEEP_CSR` 的 `SBSDIO_SLPCSR_KEEP_WL_KSO`，WHD 设备唤醒序列的第一笔写。WHD 在这笔写旁边的注释写着 "1st KSO write goes to AOS wake up core if device is asleep / Possibly device might not respond to this cmd. So, don't check return value here"：省电开着时，连接稳定后芯片会进入这种 KSO 睡眠，**睡着时它按设计不回应这笔写**。

主机控制器无从知道一颗卡的沉默是预期行为。STM32 SDHC 驱动把每一条没有响应的命令都报成命令超时，于是这场刷屏其实是芯片在按固件文档行事，只是被渲染成了每秒约 300 行错误。

修法是让芯片保持清醒：`whd_wifi_on()` 成功后调用 `whd_wifi_disable_powersave()`，由 `CONFIG_AIROC_WIFI_DISABLE_POWERSAVE` 控制（demo 的 `wifi.conf` 打开）。这是一台市电供电的 broker，芯片没有理由睡觉。改动后的实测：原先从 ~50 秒起每秒约 300 次失败的那次启动，现在 `Command response timeout` 与 CMD52 失败都是**零**；限流则作为真实超时的安全网保留。

值得带出这块板子的结论：沉默的 SDIO 卡不一定是坏的。这颗芯片睡着时会故意沉默，主机能区分两者的唯一办法是知道命令在协议里的位置。

### 9. 链路丢了不会有事件，所以 demo 自己去轮询

这块板上的关联可以以三种方式结束，而其中只有一种会作为 Wi-Fi mgmt 事件到达应用：

| 链路怎么断的 | 驱动做了什么 | 应用收到的事件 |
| --- | --- | --- |
| 显式 `NET_REQUEST_WIFI_DISCONNECT` | `airoc_mgmt_disconnect()` 抛出结果 | `NET_EVENT_WIFI_DISCONNECT_RESULT` |
| AP 发来 deauth / disassoc | 事件任务调用 `net_if_dormant_on()` | 无 |
| AP 直接消失（信标丢失） | 事件任务把 `WLC_E_LINK`（link 标志为清）放过去 | 无 |

于是启动时那次关联成了应用与链路唯一的接触：之后 AP 消失不产生任何事件，而 broker（监听在 `0.0.0.0`，它根本不会注意到）就只剩下一个板子其实已经没有的地址。症状是每 60 秒的状态心跳丢掉 `ipv4 ...` 那一截，唯一的恢复手段是复位。

覆盖上表三行的现成信号其实就在 WHD 里：`JOIN_LINK_READY` 位，`whd_wifi_api.c` 在 `WLC_E_LINK`（link 标志为清）、`WLC_E_DEAUTH_IND` 和 `WLC_E_DISASSOC_IND` 三种情况下都会清它。`NET_REQUEST_WIFI_IFACE_STATUS` 正是能读到 `whd_wifi_is_ready_to_transceive()`（也就是这一位）的 mgmt 请求，所以 demo 用一个守护线程每 `CONFIG_BROKER_WIFI_MONITOR_PERIOD_S` 秒（默认 10）轮询一次，只要答案不是 `WIFI_STATE_COMPLETED` 就重新关联（等连接结果，再 `net_dhcpv4_restart()`）。AP 一直不回来时按 5 秒起步的退避重试，翻倍到 60 秒封顶。它同时也等 `NET_EVENT_WIFI_DISCONNECT_RESULT`，所以唯一会发事件的那种断开是立即处理，而不是等下一个轮询周期。

broker 本身什么都不用做：监听在 `0.0.0.0` 上，重连后拿到同一个租约的话，除了客户端自己的重连之外无感；拿到不同租约也只是心跳里的地址变了。启动行为不变：开头 3 × 30 秒仍然有限次，连不上的板子照样启动 broker 并说明情况，守护线程从那时起一直重试。

## 结语

### 这个方案适合什么场景

ART-Pi 补上了主篇里"ARM 板卡尚未验证"那一格：Cortex-M7 路径、32 位原子操作回退、外部 RAM 分配器都工作正常，移植也达到了与另外两个 demo 功能对等的程度。它带来的难点在板级 bring-up，而不是 POSIX 裁剪或堆损坏：bootloader 占着镜像必须落脚的 flash，SDIO 射频芯片又有三个互不相干的故障（卡中断不来、NVRAM 不匹配、缺 CLM），且都表现为"没有链路"。

有两点能带出这块板子。轮询芯片并不总是"硬件坏了才用的退路"：这块板子厂商自己的协议栈就在轮询，datasheet 描述的那个中断在这里确实没有接线。另外，一条会消失的链路需要有人看着，驱动的断开事件通常只覆盖显式断开，悄悄走掉的 AP 只能靠问驱动自己的关联状态来发现。

### 代码与 demo

demo 位于 [nanomq/nanomq](https://github.com/nanomq/nanomq/tree/zephyr-rtos) 的 `zephyr-rtos` 分支下的 `demo/nanomq_zephyr_stm32_art-pi`，与 ESP32-S3、`qemu_x86` 这两块 demo 并列；完整的编译、烧写与控制台步骤在其 README 里。三处树外补丁在 demo 的 `patches/` 目录，适配的基线版本见 `patches/README.md`。

如果你把移植带到同族的另一块板子上，或者遇到本文没覆盖的故障，欢迎到 [NanoMQ 社区](https://github.com/nanomq/nanomq/discussions)讨论。

### 延伸阅读：本次移植的决策记录

本移植有五个决策做了完整记录（含被否掉的备选方案），就在 demo 自己的 `docs/adr/` 目录里：

| 记录 | 决策 |
| --- | --- |
| [ADR 0001](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0001-qspi-xip-behind-art-pi-factory-bootloader.md) | 镜像从 QSPI XIP 运行，挂在 ART-Pi 出厂 bootloader 之后 |
| [ADR 0002](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0002-broker-heap-in-sdram-through-the-external-ram-allocator.md) | broker 堆放进 SDRAM，走 external-RAM 分配器 |
| [ADR 0003](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md) | 轮询 WHD 线程，因为这块板子从不触发 SDIO 卡中断 |
| [ADR 0004](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0004-keep-the-art-pi-wifi-chip-awake.md) | 让 Wi-Fi 芯片保持清醒，不让它进 KSO 睡眠 |
| [ADR 0005](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_stm32_art-pi/docs/adr/0005-poll-the-join-state-to-recover-a-lost-wi-fi-link.md) | 掉线靠轮询关联状态来恢复 |

## 附录 A：这次移植向上游要了什么

| 改动 | 位置 |
| --- | --- |
| demo 本体，以及 `function_test.py` 的非 localhost 调参 | 本仓库 `zephyr-rtos` 分支 |
| `nng`：`SUCCESS` → `NNG_MQTT_SUCCESS`（与 CMSIS `ErrorStatus.SUCCESS` 重名） | `nng` 子模块，叠在 Zephyr 移植工作之上 |
| STM32 SDHC 的 SDIO 卡中断支持 | `patches/0001`（Zephyr 树） |
| AIROC/WHD 的 SDIO bring-up：poke 定时器、省电修复，以及 43438 的 CLM/NVRAM 接线 | `patches/0002`（Zephyr 树） |
| 本模块的 43438 NVRAM 内容 | `patches/0003`（west 模块 `hal_infineon`） |

bring-up 期间用的探针（Zephyr 树与 WHD 里的 `nanomq-probe` 打印、板内标志位探测）在这套配置跑通之后已全部移除，poke 定时器也改成了 Kconfig 选项 `CONFIG_AIROC_WIFI_WHD_POKE`；补丁就是从这份最终代码生成的。

## 附录 B：给下一块同族板子的清单

1. 先确认镜像必须放在哪里，再去和 loader 较劲：这里是 QSPI XIP，内部 flash 属于 bootloader。
2. 模块的上电与时钟引脚去查**厂商自己的驱动**，不要信任从原理图里抽出来的文本。
3. SDIO Wi-Fi 芯片能枚举但从不回应时，先看 `SDMMC_STA.SDIOIT`（以及驱动的卡中断路径到底实现了没有），再去怀疑固件或 NVRAM。
4. 在目标板内埋探针；如果一个调试器在串口还在不停打印时报 `LOCKUP`，不要信它。
5. NVRAM 要和模块匹配；把缺少 CLM 当作致命错误处理。
6. 给网络链路配一个守护线程（"移植过程"第 9 条）。驱动的断开事件通常只覆盖显式断开，而 AP 自己消失是无声的，所以要轮询驱动自己的关联状态，并在一个与应用同生命周期的线程里重新关联。
7. 下结论说 broker 坏了之前，先按板子的网络条件重新调一遍主机侧测试套件。
