# 把 Zephyr 版 NanoMQ broker 移植到 ART-Pi（STM32H750XBH6）

本文记录 `demo/nanomq_zephyr_stm32_art-pi` 的诞生过程，它是继 qemu_x86
（仿真）和 ESP32-S3（Wi-Fi）之后的第三个 Zephyr broker demo。这里按问题**实际
出现的顺序**来写：有三个互不相同的故障，从控制台看却完全一样
（`airoc_wifi_init_primary failed ret = -19`、没有链路、没有 DHCP）。

验收：可构建、**实机验证**、与另外两个 demo **功能对等**。功能套件的三个硬性
门禁在实机上全部通过。

## 1. 与 ESP32-S3 同类 demo 的差异

| 维度 | ESP32-S3 | ART-Pi | 后果 |
| --- | --- | --- | --- |
| SoC | ESP32-S3（xtensa） | STM32H750XBH6（Cortex-M7） | 32 位原子操作预算、`-mno-movbe` 只给 x86、CMSIS `SUCCESS` 重名（见下） |
| 代码存储 | 16 MB flash（借助 flash cache 原地执行） | 128 KB 内部 flash，已被出厂 bootloader 占满 | 镜像必须链接进 0x90000000 的 8 MB **QSPI** 窗口（ADR 0001） |
| 数据面 | 16 MB 八线 PSRAM，4 MB 堆窗口 | 32 MB FMC SDRAM，4 MB `k_heap`（ADR 0002） | 分配器接法不同，且没有 PSRAM 的 shared multi heap |
| 网络 | ESP32 Wi-Fi（ESP-IDF blob） | 板载 **AP6212 = CYW43438**，SDMMC2 上的 SDIO | 走 Infineon AIROC/WHD，SDIO 主机胶水是 STM32 SDMMC |
| 显示 | LCD（未用） | LTDC 会从 broker 堆里抢 SDRAM | overlay 里关掉 `&ltdc` |
| 时钟 | Wi-Fi 驱动给 SNTP 播种 | 同样做法，可选（`CONFIG_BROKER_SNTP`） | 无 |

应用层没有被改动：`src/main.c` 就是 ESP32-S3 那份，Wi-Fi bring-up 原样保留，
旁边补了一条以太网路径；`src/process_stub.c` 也还是 nanomq POSIX `process.c`
的替身。

## 2. 先把镜像弄进板子

ART-Pi 的内部 flash 里是睿赛德/RT-Thread 的**出厂 bootloader**。它把 QUADSPI
映射好，然后跳到 0x90000000 处的向量表，所以本 demo 不需要自己当一级 loader，
只要**在那个位置**就行：

```dts
/ { chosen { zephyr,flash = &ext_memory; }; };   /* 8 MB QSPI, 0x90000000 */
```

有两个必须说清楚的后果：

* **QSPI 驱动必须保持关闭**（`CONFIG_FLASH` / `FLASH_STM32_QSPI`）。它的初始化
  会去重配 CPU 正在取指的那个外设。本 demo 没有文件系统，关掉没有损失。
* 直接 `west build -b art_pi` 会把镜像链进 128 KB 内部 flash，装不下 broker，
  所以要设置 `zephyr,flash` 的 overlay。

控制台上那句 `Powered by RT-Thread.` 是**bootloader 自己的横幅**（ART-Pi SDK
里 `projects/art_pi_bootloader/applications/boot.c` 打印它，然后跳转）。在
bring-up 过程中，把它误判成"出厂应用还在跑、我的镜像没烧进去"浪费了不少时间。

## 3. 让镜像跑起来路上的工具坑

* **pyocd 0.45 + 这颗 ST-Link。** 连接阶段 pyocd 会发
  `JTAG_GET_BOARD_IDENTIFIERS` 并期待 128 字节；这颗探针只回 2 字节状态，pyocd
  于是抛出致命错误 `received incomplete command response from STLink (got 2,
  expected 128)`，完全无法访问 SWD，尽管探针本身是好的。board ID 只用来生成
  人类可读的板名，所以 `tools/artpi_flash.py` 在 import 连接助手之前把它屏蔽掉
  （`StlinkProbe._get_board_id = lambda self: None`）。
* **厂商的 CMSIS 烧写算法**（`ART-Pi_W25Q64.FLM`）是 QUADSPI 后面那颗 W25Q64
  必需的；它不随本仓库分发（获取方式见 README）。pyocd 自带的 `stm32h750xx`
  目标既不知道这块区域，也没有这个算法。
* **在算法运行之前复位，而不是围着它复位。** 厂商 loader 会从头重配时钟、缓存和
  QUADSPI，若它继承了一个正在运行的应用的配置就会 **Init() 超时**。因此要先
  `reset_and_halt()` 再烧写。
* **QUADSPI 处于间接模式时，用 SWD 读 0x90000000 会 fault**，所以代码里把该
  flash 区域标成 `are_erased_sectors_readable = False`，工具总是整扇区擦写，
  而不做回读校验。
* **控制台有积压。** ST-Link 的虚拟串口会缓冲；复位后立刻开始的抓取，可能先把
  上一次启动的内容重放出来（一份日志里出现两个 `Powered by RT-Thread.` 横幅）。
  读之前按**最后一个** bootloader 横幅切分，或者先丢缓冲：
  `tools/console.sh --drain <秒>`。打开/抓取控制台的命令，以及一次正常启动的逐行
  注释版日志，都在 demo README 的"控制台与启动日志"一节。
* **pyocd 烧写完会把内核留在 halted 状态**，于是"已烧写、已 reset 并运行"的板子
  看起来像死了一样：bootloader 横幅出来了，然后就没了，实际上镜像从未启动。
  `tools/artpi_flash.py` 现在会在最后再复位并 resume 一次。要认得的症状是：
  控制台一直没输出，**并且**板子在局域网里完全不见踪影，而重新烧写没有任何变化。
* **默认构建必须是能跑的那一个。** `tools/flash.sh` 现在默认构建 Wi-Fi 变体（除非
  显式给 `--eth`/`--usb`）；早期版本只带 `prj.conf`，也就是以太网变体，在没有网线的
  调试台上会一直停在 `eth: still no link`。这个错误看起来和"板子坏了"一模一样，
  白花了一轮排查。
* **刷屏本身就是缺陷。** STM32 SDHC 驱动每失败一条命令就打一行日志，而 Wi-Fi 芯片
  进入睡眠（见 §4.7）后那就是每秒几百次，控制台变成一整面
  `Command response timeout` 墙，别的内容都读不到。现在既加了限流（每 5 秒一行，
  外加 `Skipped N messages` 计数），也把根因本身修掉了，所以"控制台安静"重新变成
  常态，而不是运气。
* **broker 的启动日志只打印一次，而且只在它真的启动时才有。** nanolib 是在
  `broker()` 运行过程中宣告它的；晚接上控制台就只能看到驱动在干什么。由此引出的两个
  修复：启动阶段的 Wi-Fi 连接循环改成**有限次**（以前是无限重试，于是连不上的板子
  根本不会启动 broker，也就一条相关日志都没有，正是"看不到 broker 启动日志"那次
  报告），之后的链路交给守护线程（§4.8）；以及 demo 现在每
  `CONFIG_BROKER_STATUS_INTERVAL_S` 秒（默认 60）打一行状态心跳，带上 uptime、
  各监听端口和当前 IPv4 地址，让"它还在跑吗"不再依赖是否赶上了启动瞬间。

## 4. 网络

### 4.1 以太网：那条"复位线"是误判

ART-Pi 有 STM32 MAC + LAN8720A PHY，所以第一反应是走更简单的路（`eth.conf`）。
但它始终起不来：用 SWD 扫了 0–31 全部 MDIO 地址都没有响应，`phy_mii: PHY (0) ID
FFFF`、`HAL_ETH_Init failed`。最自然的解释是 PHY 被按在复位里，于是 overlay 把
PA3（厂商 BSP 的 `ETH_RESET_PIN`）接成
`reset-gpios = <&gpioa 3 GPIO_ACTIVE_LOW>`。结果毫无变化，看起来就像 PHY 坏了，
直到把这条覆盖**去掉**，MAC 反而干净地初始化完成、也不再报任何 PHY 错误。
也就是说 PA3 并不是这块板子的 PHY 复位脚，把它拉低才是让 PHY 沉默的原因；这条
覆盖已从 overlay 中删除。

没有验证的是需要硬件的那部分：没有网线时接口只会以 dormant 状态等待 carrier，
因此链路建立、DHCP 与以太网数据通路仍未测。已验证的通路是 Wi-Fi。

### 4.2 Wi-Fi：SDIO 这一侧要从头搭

Zephyr 的 ART-Pi 设备树对 AP6212 的 Wi-Fi 侧只字未提，所以 overlay 自己加上了
SDMMC2 上的 SDIO 主机与 AIROC 设备节点：

| 信号 | 引脚 | 来源 |
| --- | --- | --- |
| SDMMC2 D0/D1/D2/D3 | PB14/PB15/PB3/PB4（AF9） | 厂商 `projects/art_pi_wifi` 的 CubeMX 配置 |
| SDMMC2 CK/CMD | PD6/PD7（AF11） | 同上 |
| WL_REG_ON | PC13 | `libraries/drivers/drv_wlan.c`：`AP6212_WL_REG_ON` |

`WL_REG_ON` 值得单独说：早期根据原理图文本提取猜的 PI14 会导致连 CMD5 都没有
响应，因为芯片根本没上电。权威来源是厂商驱动自己的 `GET_PIN(C, 13)`。把 PC13
拉高后 SDIO 立刻能枚举：CMD5、CCCR rev 2、function 0/1/2 的 CIS、4 位总线、
25 MHz。

### 4.3 代价最大的坑：in-band SDIO 卡中断始终不来

现象：固件下载成功，WLAN function 就绪（`SDIOD_CCCR_IORDY` 到了 `0x6`），第一条
ioctl 也写进了 function 2（768 + 36 字节），然后就没了。回包从未被读取，每条
ioctl 都超时（`iovar "cap" -> 101580800`，每条 5 秒），最后
`airoc_wifi_init_primary failed ret = -19`。

在 WHD 的设计里这是致命的：`whd_thread_func()` 只有在
`thread_info->bus_interrupt` 被置位（或
`whd_bus_use_status_report_scheme()` 返回真）时才进入接收路径，而该传输层上这个
函数返回 `WHD_FALSE`。这个标志只由 SDIO 卡中断处理函数设置。于是：没有卡中断
= 永远收不到帧。

几个"第一嫌疑"是用**目标板内探针**排除的，而不是靠调试器读寄存器（这套组合下
pyocd 的 halt/寄存器访问并不可靠：应用明明在跑，它却报 `LOCKUP` 并返回垃圾
值）：

* `SDMMC_MASK.SDIOITIE` **确实**置位了：`enable_interrupt -> MASK=0x00400000`。
* SDMMC 中断本身工作正常：数据搬运时 ISR 会进。
* `SDMMC_STA.SDIOIT` **从未**置位，整个启动过程一次都没有，包括 WHD 卡在 5 秒
  ioctl 超时里的那段时间。芯片根本没有断言 DAT1。
* CCCR `INTEN` 已编程（`wr cccr[0x4] = 0x7`），WLAN function 也就绪，也就是主机
  侧已经完全武装好了。

规避办法（补丁 0002，`CONFIG_AIROC_WIFI_WHD_POKE`）：用一个 20 ms 定时器去戳
`whd_thread_notify_irq()`。这等于把本该由中断送达的唤醒补给线程，它的轮询就能
找到排队的回包，初始化链随即走通：

```
[4179] nanomq-probe: iovar "cap" -> 0            （原来是 101580800）
cmd53 rd func2 addr=0x0 size=39 -> 0             （回包被读到了）
WLAN MAC Address : 70:4A:0E:51:77:9A
```

之后又逐条试过"让真正的中断到来"的其他办法，全部被排除：

* **`DCTRL.SDIOEN`**（STM32 SDMMC 的 "SD I/O enable"，即"把 DAT1 当中断线用"）。
  置位后主机侧确实完全武装好了（`MASK=0x00400000`、`DCTRL=0x00000800`，且该位在
  传输过程中一直保持），但 `SDMMC_STA.SDIOIT` 依然从不锁存；而且一旦有数据流量，
  它会让 4 位传输以 `Command response timeout` 刷屏告终，所以现在刻意不设它。
* **1 位总线**（DAT1 不再是数据线而是专用中断线：`bus-width = <1>` 配合 WHD 的
  `sdio_1bit_mode`）。结果相同：没有 `SDIOIT`，也没有链路。
* **Out-of-band host-wake。** 厂商 NVRAM 里 `muxenab=0x11`（`0x10` 位 = "HW OOB"），
  原理图上也有 `GPIO_WIFI_HOST_WAKE` 网络，所以芯片也可能走 out-of-band。按
  `wifi-host-wake-gpios = <&gpioe 3 GPIO_ACTIVE_HIGH>` 接上（PE3 是原理图文本里
  唯一说得通的 MCU 引脚；PI14/PI15 那些命中其实是 LCD 的 LTDC_CLK/LTDC_R0），
  依然没有任何唤醒；一旦有流量，同样出现 CMD 刷屏。最终不接，理由写在 overlay 里。

轮询也正是这块板子**厂商栈**的做法：ART-Pi SDK 自带的 Wi-Fi 主机驱动
（`libraries/drivers/drv_sdio.c`）从未打开 `SDMMC_MASK.SDIOITIE`，也没有注册任何
卡中断回调，它上面那套 WICED 是靠轮询芯片状态寄存器拿中断的。这个决策及其后果
记录在
[ADR 0003](../adr/0003-poll-the-whd-thread-because-the-art-pi-never-asserts-the-sdio-card-interrupt.md)。

因为"中断不来"会让**每一条** ioctl 都超时，它顺带制造了两个很有说服力但错误的
早期结论：一是"CLM blob 会让芯片卡住"，二是"必须用厂商 SPI flash 里那份打包
固件"。这两个都是症状，不是原因。

### 4.4 NVRAM 必须是本模块的

规避掉中断问题之后，固件仍然在初始化中途放弃，直到 NVRAM 与模块匹配。ART-Pi
上的 AP6212 是 prodid/`boardtype=0x0726` 那一款；blob 清单给 CYW43438 配的
AW-CU427-P NVRAM（`boardtype=0x0865`）在这块板子上不工作。权威文本就是厂商
自己的 `wifi_nvram_image[]`（`libraries/drivers/drv_wlan.c`：`prodid=0x0726`、
`boardrev=0x1101`、`xtalfreq=26000`、`macaddr=…`），补丁 0003 就是把它按
`COMPONENT_43438` 的 NVRAM 装进去。

### 4.5 CLM blob 不是可选项

`whd_wifi_on()` 结尾会发一条 `country` iovar，没有 regulatory 数据时固件会拒绝：

```
[4079] Could not set Country code
airoc_wifi_init_primary failed ret = -19
```

所以本移植在追中断坑期间加的那个 `CONFIG_AIROC_WIFI_NO_CLM` 开关不可能成立。把
43438 的 CLM 接上后，芯片接受并回报：

```
[4399] WLAN CLM : API: 12.2 Data: 9.10.39 Compiler: 1.29.4 ClmImport: 1.36.3
               Creation: 2021-03-28 22:47:33
```

它是 AW-CU427-P 模块的 CLM（Infineon 为这颗芯片公开发布的只有这一份），因此
并不是本模块的校准数据，但芯片接受它，链路可用。

### 4.6 USB-ECM：第三条路，以及它停在哪

Wi-Fi 通了之后，又把板子的 USB-OTG 口当成另一条网络通路试了一遍
（`usb.conf` + `boards/art_pi_usb.overlay`）：板子变成暴露 CDC-ECM 的 USB
**设备**；而接到它这一端的主机没有理由去跑 DHCP 服务器，所以板子同时充当这条链路
的 DHCPv4 **服务器**，主机端桌面环境自己就把新接口配好，既不需要手工 `ip(8)`
也不需要主机侧特权。west 树里一行都不用改：ART-Pi 的 Zephyr 板级文件本来就使能了
`zephyr_udc0`，ECM 类在 `subsys/usb/device/class/netusb/` 里，DHCPv4 服务器也是
树内现成的。

固件侧的实测证据（这套调试环境下调试器读寄存器不可靠，所以由固件自己打印）：

* `usb_dc_attach` → `HAL_PCD_Init` → `HAL_PCD_Start`，随后端点配置并使能，ECM
  功能注册完成。
* OTG 核心自报 `GCCFG=0x00010000`（PHY 已上电）、`DCTL=0x00000000`（`SDIS=0`，
  软连接、D+ 上拉已使能）、`GOTGCTL=0x030900c0`（HAL 的 B-session valid 覆盖，
  对于引脚复用里没有 `usb_otg_fs_vbus_pa9` 的板子、`vbus_sensing_enable` 关闭时
  正是这个值）。
* PA11/PA12 复用为 **AF10**（展开后的设备树里 `pinmux = <0x16a>`、`<0x18a>`），
  是正确的 USB OTG FS 复用功能。

始终没发生的是主机侧动作：`GINTSTS` 既没有 `USBRST`(12) 也没有 `ENUMDNE`(13)，
而 PC 上 `journalctl -k` **什么也没记录**，即使固件把 D+ 上拉做了断开/接通循环
也一样（只要端口电气上连着，任何 xHCI 主机都会报告这个事件）。所以卡点在物理
通路，不在固件。候选原因与检查步骤写在 demo 的 README 里（先查线型：按旧式设备
接法布线的 Type-C 母座需要 CC 下拉，没有下拉时 C-to-C 线插上去就是一片漆黑）。

这件事就停在这里：它是硬件侧问题（换线/换口），不是还有代码要写。

### 4.7 控制台刷屏：芯片睡着了，而这是被允许的

连接建立约 50 秒后，控制台开始被 `sdhc_stm32: Command response timeout` 填满，
限流后每 5 秒一行，但每行都带着 `Skipped ~1500 messages`，也就是每秒约 300 次
失败；而 broker 与数据面完全正常（**刷屏期间整套功能测试依然全绿**）。

把 SDHC 驱动的命令按类别统计（临时探针，用完全部移除）后，特征一目了然：

| 命令类别 | 发出 | 失败 |
| --- | --- | --- |
| CMD52（任意 function，寄存器访问、无数据阶段） | ~215 000 | ~108 000 |
| CMD53 func1 byte 模式（SDIO backplane） | ~20 000 | **0** |
| CMD53 func1 block 模式（SDIO backplane） | 412 | **0** |
| CMD53 func2（WLAN 数据） | ~2 100 | **0** |

只有 CMD52 失败（约一半），而第一条失败的总是
`CMD52 write, function 1, address 0x1001F, value 1`：即写 `SDIO_SLEEP_CSR` 的
`SBSDIO_SLPCSR_KEEP_WL_KSO`，也就是 WHD 唤醒设备序列的第一笔写。WHD 在那里的注释
写着设备可能不回应（"1st KSO write goes to AOS wake up core if device is
asleep"）并忽略该错误。省电开着时，连接稳定后芯片会进入睡眠；**睡着时它按设计
保持沉默**，而 STM32 主机控制器只能把沉默报成命令超时（它对 CMD8 已经为同样的
原因开了豁免）。

修法是让芯片保持清醒：`whd_wifi_on()` 成功后调用
`whd_wifi_disable_powersave()`，由 `CONFIG_AIROC_WIFI_DISABLE_POWERSAVE` 控制
（`wifi.conf` 打开），驱动的限流则作为安全网保留。改动后的实测：原先从 ~50 秒起
每秒约 300 次失败的那次启动，现在 `Command response timeout` 与 CMD52 失败都是
**零**；三道门禁照样全绿；连续三分钟抓取中心跳与 DHCP 租约稳定。决策与备选方案见
[ADR 0004](../adr/0004-keep-the-art-pi-wifi-chip-awake.md)。

### 4.8 链路丢了不会有事件，所以 demo 自己去轮询

这块板上的关联可以以三种方式结束，而其中只有一种会作为 Wi-Fi mgmt 事件到达应用：

| 链路怎么断的 | 驱动做了什么 | 应用收到的事件 |
| --- | --- | --- |
| 显式 `NET_REQUEST_WIFI_DISCONNECT` | `airoc_mgmt_disconnect()` 抛出结果 | `NET_EVENT_WIFI_DISCONNECT_RESULT` |
| AP 发来 deauth / disassoc | 事件任务调用 `net_if_dormant_on()` | 无 |
| AP 直接消失（信标丢失） | 事件任务把 `WLC_E_LINK`（link 标志为清）放过去 | 无 |

于是启动时那次关联成了应用与链路唯一的接触：之后 AP 消失不会产生任何事件，而
broker（监听在 `0.0.0.0`，它根本不会注意到）就只剩下一个板子其实已经没有的地址。
症状是每 60 秒的状态心跳丢掉 `ipv4 ...` 那一截，唯一的恢复手段是复位。

覆盖上表三行的现成信号其实就在 WHD 里：`JOIN_LINK_READY` 位，
`whd_wifi_api.c` 在 `WLC_E_LINK`（link 标志为清）、`WLC_E_DEAUTH_IND` 和
`WLC_E_DISASSOC_IND` 三种情况下都会清它。`NET_REQUEST_WIFI_IFACE_STATUS` 正是
能读到 `whd_wifi_is_ready_to_transceive()`（也就是这一位）的 mgmt 请求。所以
守护线程每 `CONFIG_BROKER_WIFI_MONITOR_PERIOD_S` 秒（默认 10）轮询一次，只要
答案不是 `WIFI_STATE_COMPLETED` 就重新关联（等连接结果，再
`net_dhcpv4_restart()`。AP 一直不回来时按 5 秒起步的退避重试，翻倍到 60 秒封顶。
它同时也等 `NET_EVENT_WIFI_DISCONNECT_RESULT`，所以唯一会发事件的那种断开是立即
处理，而不是等下一个轮询周期。

broker 本身什么都不用做：监听在 `0.0.0.0` 上，重连后拿到同一个租约的话，除了客户端
自己的重连之外无感；拿到不同租约也只是心跳里的地址变了。启动行为不变：开头
3 × 30 秒仍然有限次，连不上的板子照样启动 broker 并说明情况，守护线程从那时起
一直重试。备选方案（只看 dormant 标志、给驱动补 `WLC_E_LINK` 处理、什么都不做）
以及它们为什么落选，见
[ADR 0005](../adr/0005-poll-the-join-state-to-recover-a-lost-wi-fi-link.md)。

## 5. 让功能测试套件适配一块 Wi-Fi 板

`function_test.py` 是按 qemu/localhost 写的：CI 脚本里的 sleep 都假定 broker 在
本机。对这块板子实测 TCP 往返是 30–100 ms，所以套件里那条"非 localhost"启发式
（`function_test.py` 一行改动：非回环地址 ⇒ `--time-scale 4 --retry 2`）才是让
整轮稳定通过的关键：拉大的时间尺度覆盖按 localhost 调的 sleep，重试覆盖两个
本身就有竞态的子用例（本调试台上 `mqtt_v5` 的 `retain-as-published` 第一次失败，
重试通过）。`tools/verify.sh <board-ip>` 把这套封装好了。

它是启发式而非保证：有一次链路拥塞（RTT 约 200 ms，约为平时 30–100 ms 的 3 倍）
时 `mqtt_v5` 两次重试都没过，紧接着重跑就通过了。只有 `mqtt_v5` 失败时，先重跑
再排查。

## 6. 验收结果（实机，2026-09-27）

```
broker connect RTT 39.8 ms -> time-scale 4.0 (auto), retry 2 (auto)
mqtt_v311      PASS       64.1s
mqtt_v5        PASS      117.8s
rest_get       PASS        1.1s
RESULT: pass=3 fail=0
```

更早一次（带 bring-up 探针的构建）同样通过，那次 `mqtt_v5` 跑了 235.8s，因为
`retain-as-published` 在这个调试台上本身有竞态，套件重试一次后通过。

其中有一次验收是**故意**在控制台正被 `sdhc_stm32: Command response timeout`
刷屏的状态下跑的（见 §3），正是这一跑确认了该状态不致命：门禁照样全绿。

全部分组（加上两个 WebSocket 分组与健壮性分组）同样全绿
（`verify.sh <ip> --full` → `pass=7 fail=0`：在三道门禁之外，`ws_v311` 260.5s、
`ws_v5` 7.7s、`capacity` 7.5s、`ws_abort` 11.5s）。这一轮还发现 demo 自带脚本的
一个 bug：`verify.sh --full` 会把一个空参数转发给套件（`${@/--full/}` 替换后会
留下一个空串），argparse 直接报错；现在该标志已被正确过滤。

`webhook_smoke` 是唯一的例外：它需要一个打开 `CONFIG_BROKER_WEBHOOK=y` 并把接收端
地址编进固件的构建；这种构建能连上 Wi-Fi 并拿到地址，但随后 SDIO 链路几乎立刻
卡死（`Command response timeout` 刷屏）。该配置下内部 SRAM 已到约 88 %，转发器
需要更多空间，因此这个分组没能跑起来，`prj.conf` 也保持 webhook 关闭。

同一时刻的链路状态：`wifi: connected`、DHCPv4 `192.168.1.3`、MQTT :1883 /
REST :8081 / WebSocket :8083 均在监听、`NanoMQ Broker is started successfully!`，
REST `/api/v4/brokers` 返回 `node_status: Running`。

链路恢复（§4.8）之后单独做了一轮实机验证。用一个临时构建（钩子没有提交）在启动
180 秒后发 `NET_REQUEST_WIFI_DISCONNECT`，**并且**故意不注册
`NET_EVENT_WIFI_DISCONNECT_RESULT`，也就是说只能靠守护线程的状态轮询发现掉线，
对应的是"AP 悄悄消失"，而不是会发事件的那条路：

```
selftest: NET_REQUEST_WIFI_DISCONNECT -> 0                (uptime 180 s)
[00:03:07.558] <err> sdhc_stm32: Command response timeout  <- leave 序列
wifi: link down — reconnecting to "TP-LINK_A57B"          (uptime 约 188 s)
wifi: connected to "TP-LINK_A57B"
[00:03:13.738] <inf> net_dhcpv4: Received: 192.168.1.8
wifi: IPv4 address assigned (DHCPv4)
broker: status running — uptime 244s, ... , ipv4 192.168.1.8
```

轮询在掉线 7 秒后（10 秒周期之内）就发现了，重新关联加重新拿租约又花了约 6 秒，
拿回的是同一个地址，broker 全程没有重启，监听端口也没有重开，租约一恢复
`/api/v4/brokers` 就又能访问。那条 `Command response timeout` 属于 leave 序列，
不是 §4.7 的 KSO 刷屏：它只在切换时出现一次，之后不再出现。

## 7. 改动都在哪里

| 改动 | 位置 |
| --- | --- |
| demo 本体、`function_test.py` 的非 localhost 调参 | 仓库分支 `alvin/art-pi`（nanomq-upstream） |
| `nng`：`SUCCESS` → `NNG_MQTT_SUCCESS`（与 CMSIS `ErrorStatus.SUCCESS` 重名） | nng 分支 `alvin/art-pi`，基于 `alvin/zephyr-port` |
| STM32 SDHC 的 SDIO 卡中断支持；AIROC/WHD 的 SDIO bring-up（poke 定时器） | `patches/0001`、`patches/0002`（Zephyr 树） |
| WHD 胶水里 43438 的 CLM/NVRAM 接线 | `patches/0002`（Zephyr 树） |
| 43438 NVRAM 内容 | `patches/0003`（west 模块 `hal_infineon`） |
| USB-ECM 网络通路（`usb.conf`、`boards/art_pi_usb.overlay`、应用侧 bring-up） | 只在 demo 内，west 树无需任何改动 |

bring-up 期间用的探针（Zephyr 树与 WHD 里的 `nanomq-probe` 打印、板内标志位
探测）在这套配置跑通之后已全部移除，poke 定时器也改成了 Kconfig 选项
`CONFIG_AIROC_WIFI_WHD_POKE`（由 demo 的 `wifi.conf` 打开）；补丁就是从这份最终
代码生成的。

## 8. 给下一块同族板子的清单

1. 先确认镜像必须放在哪里，再去和 loader 较劲：这里是 QSPI XIP，内部 flash
   属于 bootloader。
2. 模块的上电与时钟引脚去查**厂商自己的驱动**，不要信任从原理图里抽出来的文本。
3. SDIO Wi-Fi 芯片能枚举但从不回应时，先看 `SDMMC_STA.SDIOIT`（以及驱动的卡中断
   路径到底实现了没有），再去怀疑固件或 NVRAM。
4. 在目标板内埋探针；如果一个调试器在串口还在不停打印时报 `LOCKUP`，不要信它。
5. NVRAM 要和模块匹配；把缺少 CLM 当作致命错误处理。
6. 下结论说 broker 坏了之前，先按板子的网络条件重新调一遍主机侧测试套件。
7. 给网络链路配一个守护线程（§4.8）。驱动的断开事件通常只覆盖显式断开，而 AP
   自己消失是无声的，所以要轮询驱动自己的关联状态，并在一个与应用同生命周期的
   线程里重新关联。
