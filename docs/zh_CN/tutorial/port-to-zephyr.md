# NanoMQ 移植到 Zephyr RTOS：把 MQTT Broker 跑在 MCU 上

## 引言

MQTT 与 Zephyr 的组合通常出现在客户端侧：Zephyr 设备作为 MQTT 客户端，连接到远端 broker。本文讨论的是另一个方向——**将 broker 本身运行在 MCU 上**。

这一需求来自边缘侧的典型场景：现场数十个设备使用 Modbus、串口或私有协议，需要统一收敛为 MQTT；或者现场网络不稳定，数据需要先在本地缓存，待链路恢复后再上传。常规方案是在设备旁部署一台 Linux 网关，但其供电、维护与防护成本往往不划算。若 broker 能直接运行在既有的 MCU 上，这一层即可省去。

[NanoMQ](https://nanomq.io/) 是 EMQX 旗下的开源边缘 MQTT Broker，原本面向 Linux 等 POSIX 环境。本文所述的移植将 broker 核心运行于 Zephyr RTOS：应用层仍是同一份 `nanomq/` 源码加上 NanoNNG 的 MQTT 协议栈，未做裁剪；外围能力则依 Zephyr 平台的实际条件禁用或尚未验证——完整的边界清单见[附录 A](#附录-a与通用版-nanomq-的差异)。仓库包含两个 demo，分别运行于 ESP32-S3 实机与 `qemu_x86` 模拟环境，两者的对比与选择见[附录 B](#附录-b两个-demo-的对比)。

## Zephyr 简介

Zephyr 是由 Linux Foundation 托管的开源实时操作系统（RTOS），面向资源受限的嵌入式设备。与本移植相关的特性主要有四点：

- **可裁剪的配置系统**。系统功能通过 Kconfig 选项逐项启用，最小配置可压缩至数十 KB，因此同一套代码可以覆盖从传感器节点到网关的不同量级。
- **设备树描述硬件**。板级差异由 devicetree 与 board overlay 表达，应用代码不感知具体板卡，这也是本移植能够用同一份源码同时构建 `qemu_x86` 与 ESP32-S3 的前提。
- **自带网络协议栈**。包含 TCP/IP、BSD 兼容的 socket 层以及 TLS 等，nng 的 Zephyr 平台适配层正是建立在这套 socket API 之上。
- **POSIX 子集**。提供 `CONFIG_POSIX_API` 覆盖 pthread、文件描述符等接口，使原本面向 POSIX 的中间件具备迁移的可能。

本文基于 Zephyr 4.4（`11a87708d41`）。

## NanoMQ 简介

[NanoMQ](https://nanomq.io/) 是 EMQX 旗下的开源 MQTT Broker，属于 LF Edge 项目，官方定位为「面向 IoT 边缘的超轻量、高速 MQTT Broker」。与面向云端的 EMQX 不同，NanoMQ 面向嵌入式与工业现场设计。

### 架构

NanoMQ 采用分层设计，自下而上为：

- **平台适配层**：探测硬件与操作系统，向上提供兼容 API，避免绑定特定平台——这也是本次移植能够仅通过新增一个平台适配层来完成的基础。
- **任务层**：内置 Actor 模型与线程级并行，可在 SMP 系统上横向扩展。
- **传输层**：按 pipe / client 管理 TCP、UDP 流，采用 zero-copy 降低内存占用。
- **协议层**：将字节流解析为 MQTT 报文，生成事件并维护 in-flight 窗口。
- **应用层**：对接 rule 引擎与全局主题树，以无锁状态机向用户暴露 MQTT 消息与事件。

### 实现

NanoMQ 为纯 C 实现，无外部运行时依赖，便于交叉编译到各类目标板。其异步 I/O 与 Actor 架构构建在 nanomq 组织维护的 NNG fork（[NanoNNG](https://github.com/nanomq/NanoNNG)）之上，并在其上扩展了 MQTT 协议实现与 nanolib 工具库。协议层面完整支持 MQTT 3.1.1 / 3.1 与 MQTT 5.0，包括 QoS 0/1/2、保留消息、遗嘱消息、共享订阅、主题别名等特性。

## 环境搭建

### 依赖

- Zephyr ≥ 4.4 的 west workspace，以及配套的 python 虚拟环境。**`west` 本身与 Zephyr 的 python 依赖都装在这个 venv 里**，它的位置由你决定：Zephyr 官方文档用的是工作区根下的 `.venv/`，本文验证环境用的是 `~/zephyr-venv`。激活后 `west` 即在 `PATH` 上：

  ```sh
  source <venv>/bin/activate                   # 本文验证环境为 ~/zephyr-venv
  export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
  ```

- Zephyr SDK 1.0.x（需单独下载，解压后将 `ZEPHYR_SDK_INSTALL_DIR` 指向该目录）
- **构建 ESP32-S3 实机 demo 另需 ESP-IDF**（见下节；只跑 `qemu_x86` 则不需要）
- 运行功能测试另需 Python 依赖与 mosquitto 客户端，见「运行功能测试」一节

本文的验证环境固定到以下版本。其中 e1000 补丁只适用于对应的 Zephyr 源码版本，升级 Zephyr 后需重新确认：

| 组件 | 版本 / 提交 |
|---|---|
| Zephyr | 4.4，`11a87708d41`（e1000 补丁针对此版本） |
| Zephyr SDK | 1.0.1 |
| NanoMQ | 0.25.6（基于 upstream `master`） |
| NanoNNG（`nng/` 子模块） | 基于 upstream `main` + Zephyr 平台适配层。`zephyr-rtos` 分支已把子模块 gitlink 一并提交，`git clone --recursive` 即可检出完整平台适配层 |

workspace 尚未搭建时（下面把 venv 放在 `~/zephyr-venv`，也就是本文验证环境的位置；放别处、或按官方文档放进 `<workspace>/.venv` 都可以）：

```sh
python3 -m venv ~/zephyr-venv
source ~/zephyr-venv/bin/activate
pip install west

west init ~/zephyrproject
cd ~/zephyrproject
west update
pip install -r zephyr/scripts/requirements.txt
```

### ESP32-S3 开发环境

**本节只针对 ESP32-S3 实机 demo；只构建 `qemu_x86` 请跳过，用上一节的标准 Zephyr 环境即可。** 实机 demo 需要 Espressif 的 HAL blobs 与烧录/串口工具，但**交叉编译器仍来自 Zephyr SDK**：1.0.1 已包含本目标所需的 `xtensa-espressif_esp32s3_zephyr-elf`，ESP-IDF 侧不参与编译。

**1. 获取 ESP-IDF**（提供 `west`、`esptool` 与 `idf-monitor`）。两种装法都可以：

```sh
# a) 从 git 克隆
git clone --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf
cd ~/esp/esp-idf && ./install.sh esp32s3
#    激活脚本为 ~/esp/esp-idf/export.sh

# b) 用 ESP-IDF Installation Manager（eim）安装
#    激活脚本为 ~/.espressif/tools/activate_idf_v<版本>.sh
```

**2. 每次构建前激活环境**，并把 `ZEPHYR_SDK_INSTALL_DIR` 指向 Zephyr SDK。

本文验证环境把这一步做成了一条别名，写在 `~/.bashrc` 里：

```sh
alias esp-zephyr='source ~/.espressif/tools/activate_idf_v6.1.sh \
    && export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1'
```

之后每次编译前先执行 `esp-zephyr`。展开就是：

```sh
source ~/.espressif/tools/activate_idf_v6.1.sh   # git 装法为 ~/esp/esp-idf/export.sh
export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
```

**这样做时它会代替上一节的 Zephyr venv**：ESP-IDF 的 python 环境里自带一份 `west`（以及 `python3`），两者激活其一即可——后激活的那个生效。要构建 ESP32 目标就用这一套；只构建 `qemu_x86` 则用上一节的 Zephyr venv，不必安装 ESP-IDF。

激活 ESP-IDF 与编译器来源无关：它只是把 `west`、`esptool`（`west flash` 的 esp32 runner 会调用）和 `idf-monitor` 放进 `PATH`；真正决定编译器的是 `ZEPHYR_SDK_INSTALL_DIR` 与 `ZEPHYR_TOOLCHAIN_VARIANT=zephyr`——后者指向 Zephyr SDK 中与本目标匹配的那套 xtensa 工具链。**不要**设为 `espressif`：该变体已被当前 Zephyr 移除，会让 CMake 去源码树里找不存在的文件。`ZEPHYR_TOOLCHAIN_VARIANT` 也可以不设（Zephyr 会自行定位 Zephyr SDK），显式写出更不容易出错。

**3. 拉取 Espressif HAL blobs**（在 workspace 内执行一次）：

```sh
cd ~/zephyrproject
west blobs fetch hal_espressif
```

**这一步不能跳过**：若未拉取，`CONFIG_WIFI_ESP32` 会静默变为不可见——构建照常成功、固件照常启动，只是没有 Wi-Fi，且构建系统不会给出任何警告。表现为串口上始终等不到 `wifi: connected`。

更详细的发行版相关步骤（系统依赖、SDK 安装、权限与常见报错）见 [setup-fedora-zh.md（中文）](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_esp32s3/setup-fedora-zh.md) 或 [setup-fedora-en.md（English）](https://github.com/nanomq/nanomq/blob/zephyr-rtos/demo/nanomq_zephyr_esp32s3/setup-fedora-en.md)（以 Fedora 为例，其他发行版替换包管理器即可）。

### 获取源码

```sh
cd ~/zephyrproject
git clone --recursive -b zephyr-rtos https://github.com/nanomq/nanomq.git
cd nanomq
```

`--recursive` 会同时拉取 `nng/` 子模块（即包含 Zephyr 平台适配层的 NanoNNG 分支）。`zephyr-rtos` 分支把子模块的 gitlink 一并提交在仓库里，所以检出的就是上表列出的那个提交；`git clone --recursive` 检出的始终是仓库记录的 gitlink，切换提交需要显式 checkout。若克隆时未加 `--recursive`，可补执行：

```sh
git submodule update --init --recursive
```

克隆完成后可用 `git submodule status nng` 核对：输出**不以 `-` 或 `+` 开头**即说明子模块已按仓库记录的 gitlink 检出（`-` 表示尚未初始化，`+` 表示检出的提交与记录不一致）。后续命令均在本仓库根目录（`~/zephyrproject/nanomq`）执行。

### qemu_x86：Zephyr e1000 驱动补丁

使用 `qemu_x86` demo 需要为 Zephyr 打一个两行补丁。**该补丁为必需项**：未打补丁时 broker 会正常启动并输出 `NanoMQ Broker is started successfully!`，但任何客户端都无法建立连接。

原因是 QEMU 的 e1000 设备模型在复位后会清空 RCTL 寄存器，其中包括 **RCTL_BAM**（Broadcast Accept Mode，bit 15）——真实硬件默认置位，而设备模型不置位。Zephyr 的 `eth_e1000` 驱动只写入 `RCTL_EN | RCTL_MPE`，从不设置 BAM，导致**所有广播帧被设备模型静默丢弃**，ARP 无法完成解析，SLIRP 也就无法递交第一个 TCP 连接。上游 Zephyr 截至 4.4（`11a87708d41`）仍存在该问题。

补丁打在 **Zephyr 自身的源码树**（workspace 下的 `zephyr/` 目录，不是本仓库）。将下面的 diff 存为 `zephyr-e1000-bam.patch` 后应用：

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

注意 `RCTL_MPE` 是 **Multicast** Promiscuous Enabled（bit 4），只影响组播，与广播接收无关——驱动已有的这一位不能替代 BAM，这正是该问题长期未被发现的原因。

该补丁仅影响 qemu 的模拟网卡，ESP32-S3 实机 demo 无需应用。

### 端口与服务

两个 demo 在本文验证的配置下对外提供的 MQTT / REST / WebSocket 端口一致（qemu 一侧的实际可达性取决于端口转发，见下节）：

| 服务 | 端口 | ESP32-S3 | qemu_x86 | 认证 / 加密 |
|---|---:|---|---|---|
| MQTT over TCP | 1883 | 支持 | 支持 | 无认证，无 TLS |
| REST API | 8081 | 支持 | 支持 | Basic 认证，凭据须自行配置（没有可用的默认凭据），无 TLS |
| MQTT over WebSocket | 8083 | 支持 | 支持 | 无认证，无 TLS（路径 `/mqtt`） |

其中 REST 监听由 Kconfig `CONFIG_BROKER_REST_API` 打开：`main.c` 据此设置 `http_server.enable` 与 `auth_type`，而 `conf_init` 的默认值是关闭。**但光有这个开关还不够**——`CONFIG_BROKER_REST_USER` / `CONFIG_BROKER_REST_PASS` 的 Kconfig 默认值是空串，也就是没有可用的默认凭据，而上游已公开的 `admin` / `public` 也会被拒绝：两者都设成自有凭据后 8081 才会监听，否则 broker 启动时打印一行说明并保持关闭。若自行裁剪掉这个开关，8081 上同样不会有任何监听，客户端会收到 RST，这是预期结果而非故障。

### 安全前提

两个 demo 的默认配置都以**受控实验环境**为前提，直接照搬会带来风险：

| 项 | 现状 |
|---|---|
| 监听地址 | MQTT `nmq-tcp://0.0.0.0:1883`、WebSocket `nmq-ws://0.0.0.0:8083/mqtt`、REST `0.0.0.0:8081`，**均监听所有网卡** |
| REST 认证 | Basic 认证；凭据由 Kconfig `CONFIG_BROKER_REST_USER` / `_PASS` 提供，两者**默认为空串（没有可用的默认凭据）**——未配置、或仍用上游公开的 `admin` / `public` 时，8081 上不会启动监听 |
| MQTT 认证 | 未启用，任何客户端均可连接、发布与订阅 |
| 传输加密 | 无。TLS 在 NanoNNG 的 Zephyr 移植中未启用，MQTT / WebSocket / REST 均为明文 |

需要特别说明：**Basic 认证在明文 HTTP 上只是 Base64 编码，不是加密。** 凭据可被同一链路上的嗅探者还原，因此它挡得住无意访问，挡不住有意攻击。真正的访问控制仍然依赖网络边界。

因此在实验网络之外使用前，至少需要：将监听地址收窄到特定网卡、为 REST 设置自有凭据（公开的 `admin` / `public` 现已被拒绝）、并把管理接口置于可信网络之后或额外的 TLS 代理之后。至于 MQTT 认证：若本移植的认证路径已被验证即可直接启用，否则应在链路层或 TLS 代理上实施访问控制——**不要假设通用版 NanoMQ 的认证配置能直接套用到本 demo 的内嵌 conf 上**（配置来源的差异见[附录 A](#附录-a与通用版-nanomq-的差异)）。**不要将 demo 的默认配置直接暴露到公网或不可信网络。**

## 编译与运行：ESP32-S3 实机

### 1. 配置本地凭据（Wi-Fi 与 REST）

将 `local.conf.example` 复制为 `local.conf`（该文件已在 `.gitignore` 中，凭据不会进入仓库），并填入 SSID 与 PSK：

```sh
cp demo/nanomq_zephyr_esp32s3/local.conf.example \
   demo/nanomq_zephyr_esp32s3/local.conf
```

编辑 `demo/nanomq_zephyr_esp32s3/local.conf`：

```conf
CONFIG_BROKER_WIFI_SSID="your-ssid"
CONFIG_BROKER_WIFI_PSK="your-passphrase"

# prj.conf 已打开 CONFIG_BROKER_REST_API，但 8081 要等这两个值设好
# （且不是公开的 admin/public）才开始监听；不设就是关闭。
CONFIG_BROKER_REST_USER="your-rest-user"
CONFIG_BROKER_REST_PASS="your-rest-passphrase"
```

### 2. 编译

`EXTRA_CONF_FILE` 相对 app 目录解析：

```sh
west build -b esp32s3_devkitc/esp32s3/procpu -d build/esp32s3_nanomq \
    demo/nanomq_zephyr_esp32s3 -- -DEXTRA_CONF_FILE=local.conf
```

构建成功后输出的内存报告（本文验证的配置，已启用 MQTT/REST/WS）：

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

看点有两个：`dram0_0_seg`（内部 SRAM）已用 **95.12%**——这是最紧张的一块，也是为什么要把 broker 堆与静态池挪进 PSRAM；`ext_dram_seg` 一行的 5152752 B（≈5.2 MB）是**已放进外部 PSRAM 的量**，占该 region 的 15.36%——它与「region 大小 32 MB」「模组容量 16 MB」三者的关系见「关于开发板」一节。

### 3. 烧录

开发板通过 USB 连接主机后，会在系统中枚举出一个串口设备，设备名取决于是走板载 USB-UART 桥接芯片还是 USB-JTAG/Serial：

- `/dev/ttyUSB*` —— 独立桥接芯片（常见 CP2102、CH34x）；
- `/dev/ttyACM*` —— 芯片原生 USB CDC（ESP32-S3 的 USB-JTAG/Serial 即属此类）。

本文示例使用 `/dev/ttyUSB0`，实际设备名以下列命令为准：

```sh
ls /dev/ttyUSB* /dev/ttyACM*
# 或观察插入开发板时内核新增的设备节点
dmesg | tail -5
```

若烧录时提示权限不足，需要将当前用户加入**该设备实际所属的组**，重新登录后生效：

```sh
ls -l /dev/ttyUSB0                 # 第 4 列就是属组
sudo usermod -aG <group> "$USER"
```

Debian/Ubuntu 与 Fedora 上这个组通常是 `dialout`（Arch 为 `uucp`）——以 `ls -l` 的结果为准，不要照搬。

确认后执行烧录（将 `/dev/ttyUSB0` 替换为实际设备名）：

```sh
west flash -d build/esp32s3_nanomq --runner esp32 --esp-device /dev/ttyUSB0
```

### 4. 查看串口

波特率 115200，可使用 `idf-monitor` 或 `miniterm`。传入 ELF 可启用二进制日志解码：

```sh
idf-monitor --port /dev/ttyUSB0 build/esp32s3_nanomq/zephyr/zephyr.elf
```

以下是一次实际启动的日志（略去路径前缀，SSID 以占位符替换）：

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

`start_rest_server` / `Serving HTTP Server` 这两行只在编译时配置了 REST 凭据（第 1 步的 `local.conf`）时才会出现；没配置时这里会换成一行 `rest: REST API stays off - ...`，8081 上无监听。

启动是一条顺序链路：PSRAM 检测与内存自检 → Zephyr 启动 → Wi-Fi 关联 → DHCP 获取地址 → SNTP 播种真实时钟 → broker 初始化完成。就绪判据是最后一行 `NanoMQ Broker is started successfully!`。

### 5. 验证连接

确认 broker 就绪后，从同一网段的主机发起验证。REST 接口（凭据即 `local.conf` 里设的那对；没设的话 8081 上不会有监听，curl 直接连接失败——那是预期）：

```sh
curl -u <rest-user>:<rest-pass> http://<board-ip>:8081/api/v4/brokers/
```

MQTT 收发（使用 mosquitto 客户端，任一终端订阅）：

```sh
mosquitto_sub -h <board-ip> -t 'test/#' -v
```

另一终端发布：

```sh
mosquitto_pub -h <board-ip> -t 'test/hello' -m 'hello from mosquitto' -q 1
```

订阅端应收到 `test/hello hello from mosquitto`。

### 关于开发板

本 demo 在 [ESP32-S3-LCD-EV-Board](https://docs.espressif.com/projects/esp-dev-kits/zh_CN/latest/esp32s3/esp32-s3-lcd-ev-board/user_guide.html#esp32-s3-lcd-ev-board-v1-5) 上验证，使用 ESP32-S3-WROOM-1-**N16R16V** 模组（16 MB flash + 16 MB **八线** PSRAM）。板级配置使用 SoC 相同的 `esp32s3_devkitc/esp32s3/procpu`，模组差异由两处表达：`boards/esp32s3_devkitc_procpu.overlay`（flash 与 PSRAM 容量）和 `prj.conf` 的 `CONFIG_SPIRAM_MODE_OCT`（八线模式）。**若所用模组不是 N16R16V，这两处都要改**——八线与四线 PSRAM 并非修改参数即可互换：四线模组还需把 `CONFIG_SPIRAM_MODE_OCT` 换成 `CONFIG_SPIRAM_MODE_QUAD`。

资源占用（链接报告）：FLASH 961204 B，内部 SRAM 379640 B / 399108 B（95.12%），放进外部 PSRAM 的部分 5152752 B。

这里的最后一个数字（约 5.2 MB）容易被误读成 PSRAM 的容量或窗口大小，把三者的关系说清：模组的 PSRAM 物理容量是 **16 MB**（`CONFIG_ESP_SPIRAM_SIZE`）；链接脚本给 `ext_dram_seg` 声明的 region 是 **32 MB**，那是它与 `drom0_0_seg` 共享的 DCACHE0 地址窗口，属于地址空间上限而非可用容量；而链接报告里的 **5152752 B（约 5.2 MB）是这个 region 的 `Used Size`**，即真正放进 PSRAM 的量——包含 `CONFIG_ESP_SPIRAM_HEAP_SIZE` 指定的 4 MB broker 堆，以及从内部 SRAM 迁出的静态池（Wi-Fi 驱动 `.noinit`、net_buf 池、Zephyr POSIX 对象池等）。换言之，5.2 MB 既不是 PSRAM 的容量，也不是它的映射窗口大小。

关于时钟：开发板无 RTC，因此 DHCP 绑定完成后 `main.c` 会做一次播种式对时——依次尝试 2 台公共 SNTP 服务器、最多 2 轮，命中即返回——以播种 `CLOCK_REALTIME`，日志时间戳由此为真实 UTC。该步骤是尽力而为的：若无服务器应答，broker 仍会正常启动，仅时间戳停留在 1970 纪元（每次查询超时 2 秒、两轮之间间隔 1 秒，最坏情况会额外增加约 9 秒启动延迟）。

## 编译与运行：qemu_x86

### 1. 编译

应用 e1000 补丁后（先按「环境搭建 → 依赖」激活 Zephyr 工作区的 venv，让 `west` 可用；不需要 ESP-IDF）：

```sh
west build -b qemu_x86 -d build/nanomq_zephyr_qemu_x86 demo/nanomq_zephyr_qemu_x86
```

构建成功后的输出：

```
[289/290] Building C object zephyr/CMakeFiles/zephyr_final.dir/misc/empty_file.c.obj
[290/290] Linking C executable zephyr/zephyr.elf
Memory region         Used Size  Region Size  %age Used
             RAM:     2608020 B        31 MB      8.02%
        IDT_LIST:           0 B         2 KB      0.00%
Generating files from build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf for board: qemu_x86/atom
```

（该数字对代码布局敏感：改动几十字节的代码就可能让某个段跨过页边界，报告值随之整页平移 4 KB，这属于对齐填充而非真实增长。）

末尾的 `qemu_x86/atom` 是该 board 的完整限定名——`atom` 是 qemu_x86 的 SoC 限定符（与 ESP32 侧的 `esp32s3_devkitc/esp32s3/procpu` 同一个机制），并不表示 `-b qemu_x86` 选错了板子。

### 2. 运行

以后台方式启动，串口写入文件（推荐——终端要留给后面的验证步骤）：

```sh
qemu-system-i386 -m 32 -cpu qemu32,+nx,+pae,sse,sse2,pni -machine q35 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -machine acpi=off \
    -serial file:/tmp/qemu.log -display none \
    -netdev user,id=n1,hostfwd=tcp:127.0.0.1:1883-:1883,hostfwd=tcp:127.0.0.1:8081-:8081,hostfwd=tcp:127.0.0.1:8083-:8083 \
    -device e1000,netdev=n1 \
    -kernel build/nanomq_zephyr_qemu_x86/zephyr/zephyr.elf &
```

端口转发配置位于 `prj.conf` 的 `CONFIG_NET_QEMU_USER_EXTRA_ARGS`，把 1883/8081/8083 绑到 `127.0.0.1`，与上面的手工命令一致。两者都遵循同一条规则：**谁在跑 qemu，端口就绑在谁的网卡上**。

也可以让 west 直接启动：

```sh
west build -d build/nanomq_zephyr_qemu_x86 -t run
```

它会按 `prj.conf` 自动带上三个端口转发，**但把串口接在 stdio 上、会占住当前终端**，只适合盯着看启动过程。

**重新启动前先清掉旧实例。** 残留的 qemu 会占着三个端口，新实例启动即失败：

```
qemu-system-i386: ... Could not set up host forwarding rule 'tcp:127.0.0.1:8083-:8083'
```

`-t run` 尤其容易留下这样的进程——停掉它未必会带走它启动的 qemu。清理时按端口反查 PID：

```sh
ss -ltnp | grep -E ':(1883|8081|8083)' | grep -oP 'pid=\K[0-9]+' | sort -u | xargs -r kill
```

`qemu-system-i386` 也可以由 west 自行定位（Zephyr SDK 的 hosttools，或 `PATH` 上的发行版包，如 Fedora 的 `qemu-system-x86`）。手工执行时若提示 `command not found`，把 qemu 所在目录加入 `PATH` 即可。

这里的 `-m 32` 是为 QEMU 分配 32 MB 内存；Zephyr 的链接脚本从中保留了一部分，因此链接报告中的可用 RAM 约为 31 MB（本文镜像占用约 2.5 MB，其中约 1 MB 为 malloc arena）。

### 3. 启动日志

以下为实际启动输出（省略了部分 DEBUG 行与路径前缀）：

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

那两行 REST 日志只在编译时配置了凭据时出现。

就绪判据是最后一行 `NanoMQ Broker is started successfully!`，随后可验证 REST（前提是编译时通过 `local.conf` 设置了 `CONFIG_BROKER_REST_USER` / `_PASS`；没设的话 8081 上没有监听）：

```sh
curl -u <rest-user>:<rest-pass> http://127.0.0.1:8081/api/v4/brokers/
```

### 关于 malloc arena

`qemu_x86` 启用了 MMU，Zephyr 的 libc `malloc` 默认 arena 仅 16 KB，而 nng 的 Zephyr 平台分配器即为 `malloc()`，单条 pipe 的接收队列增长（`msq_len * 8` 字节）即可超出该值。`prj.conf` 将 arena 提升至 1 MB，因此镜像中约 1 MB 属于该 arena，并非 broker 自身开销。

## 运行功能测试

仓库提供了一套功能测试，覆盖两个 demo 的同一批用例。运行前需要以下依赖（runner 会检查，缺失时直接报错退出）：

```sh
python3 -m pip install paho-mqtt requests
```

系统还需提供 mosquitto 命令行客户端（`mosquitto_pub` / `mosquitto_sub`），Debian/Ubuntu 上为 `mosquitto-clients`，Fedora 上为 `mosquitto`。

`--list` 可列出全部测试组（本文覆盖其中 8 组，见后文表格）：

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --list
```

针对实机运行（`--no-manage` 表示 broker 已在运行，不由 runner 管理）：

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr <board-ip>
```

也可只运行指定测试组：

```sh
python3 demo/nanomq_zephyr_qemu_x86/function_test.py --no-manage --addr <board-ip> \
    --group mqtt_v311 --group rest_get
```

以下为针对 ESP32-S3 实机的实际运行输出——用 `--group` 逐项挂上下表中的 8 个组；为便于阅读，省略了路径前缀：

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

`rest_get` 组还要求被测 broker 在编译时配置了 REST 凭据（见各 demo 的 `local.conf.example`）。没配置时这一组不会失败，而是 **SKIP**：

```
| [worker rest_get] SKIP: no REST API on <addr>:8081 — the demos leave it off
| until CONFIG_BROKER_REST_USER/PASS are set (local.conf); pass
| --rest-user/--rest-pass for a broker that has them
```

也就是说套件把「没开 REST」与「REST 坏了」区分开了：前者跳过并说明原因，后者才 FAIL。broker 配好凭据后，用 `--rest-user` / `--rest-pass` 把同一对凭据交给套件即可正常执行。

各测试组的覆盖范围与实机耗时：

| 测试组 | 覆盖范围 | 实机耗时 |
|---|---|---|
| `mqtt_v311` | 会话、保留消息、v4/v5 互通 | 120.1s |
| `mqtt_v5` | 会话过期、用户属性、`$share`、主题别名 | 211.3s |
| `rest_get` | REST GET 全部路由 | 2.9s |
| `ws_v311` | MQTT 3.1.1 over WebSocket | 279.0s |
| `ws_v5` | MQTT 5 over WebSocket | 15.9s |
| `capacity` | 12 个并发 CONNECT + QoS1 回环 | 13.1s |
| `ws_abort` | WebSocket 连接异常中止时的连接池稳定性 | 31.9s |
| `survival` | 上游 `attack.py` 的缩比负载/会话 churn | 90.3s |

runner 会自动调整参数：它先测量到 broker 的 TCP 往返时延（本机环回低于 1 ms，实机经 Wi-Fi 为十几到数百毫秒，本轮测得 16.1 ms），判定为非本机后默认切换至 `--time-scale 4`，用于拉长 CI 脚本中按本机时延设定的 sleep。

## 移植过程

NanoMQ 的分层里本来就有一层平台适配层（nng 的 `nni_plat_*`），所以移植的大头是**把这层在 Zephyr 上补齐**；真正的硬阻断反而在应用层——`nanomq/` 里有几处直接调用 POSIX，绕不过去。以下按层说明。

### 一、应用层：POSIX 依赖裁剪

应用层对 POSIX 的依赖集中在四处，一律用 `__ZEPHYR__` 条件编译处理，不引入新的抽象层：

| 文件 | 原 POSIX 依赖 | 处理 |
|---|---|---|
| `apps/broker.c` | `signal()` / `sigaction` 安装信号处理 | 整段跳过。Zephyr 没有 POSIX 信号语义；嵌入式 broker 的主循环靠自身条件结束，不依赖 `^C` |
| `nanomq.c` | `#include <sys/ptrace.h>` | 条件编译。`check_trace()` 只在 CLI 路径被调用，嵌入式 broker 不会走到 |
| `mqtt_api.c` | `nng_access(dir, W_OK)`（文件日志目录可写性检查） | 条件编译。picolibc 没有 `W_OK`；文件日志后端在嵌入式上恒关，跳过检查无副作用 |
| `process.c`（整个编译单元） | `fork` / `kill` / `chdir`、`<paths.h>` | 不参与构建；demo 提供 `process_stub.c` 补齐其公开符号（一律返回 -1） |

`process_stub.c` 能这样"假装"，是因为这五个符号要么没有调用点，要么其调用点都在不执行的路径上：`process_daemonize()` 的两处调用都先判 `daemon == true`，`process_send_signal()` 只被 CLI 路径上的 `check_trace()` 调用，而 `process_is_alive()` / `pidgrp_send_signal()` / `process_create_child()` 在整个应用里**根本没有调用点**。嵌入式 broker 直接调用 `broker()`、`conf_init()` 的 `daemon` 默认为 false，上述路径永不触达——**stub 的实际作用只是让链接通过**。

### 二、平台适配层：接口清单与 POSIX 差异

这一层是 nng 的 Zephyr 实现（`src/platform/zephyr/`，22 个文件，其中 18 个 `.c`：16 个实现下面的接口族，另 2 个是 stub——`zephyr_peerid.c` 与 `zephyr_socketpair.c`，对应下表里那两行不支持的设施）。它按 nng 的接口族划分，每个族落在 Zephyr 的一项设施上：

**接口清单**

| 接口族 | 实现文件 | 对应 POSIX 设施 | Zephyr 落点 |
|---|---|---|---|
| 内存 | `zephyr_alloc.c` | `malloc` / `free` | PSRAM 上的 `k_heap`，或 libc `malloc()`（按目标） |
| 时钟与睡眠 | `zephyr_clock.c` | `clock_gettime` / `nanosleep` | `k_uptime_get()`，以及 Zephyr POSIX 层的 `nanosleep()` |
| 线程与同步 | `zephyr_thread.c` | `pthread_*`（互斥量 / 读写锁 / 条件变量 / 线程） | Zephyr 的 pthread 实现（`CONFIG_POSIX_API`） |
| 原子操作 | `zephyr_atomic.c` | C11 `<stdatomic.h>` | 原生 64 位原子，或内嵌互斥量回退 |
| 调试与错误码 | `zephyr_debug.c` | `abort` / `printf` / `strerror` / `errno` | `printk`、libc，以及 errno ↔ nng 错误码映射 |
| TCP（客户端） | `zephyr_tcpdial.c`、`zephyr_tcpconn.c` | `socket` / `connect` / `setsockopt` | Zephyr net 栈的 BSD 兼容 socket |
| TCP（服务端） | `zephyr_tcplisten.c` | `socket` / `bind` / `listen` / `accept` | 同上 |
| UDP | `zephyr_udp.c` | `socket` / `sendmsg` / `recvmsg` | 同上 |
| 描述符与 poll 队列 | `zephyr_pollq_poll.c`、`zephyr_sockfd.c` | `poll()`（POSIX 上还叠了 epoll / kqueue / eventfd） | Zephyr 的 `poll()` |
| 套接字地址转换 | `zephyr_sockaddr.c` | `sockaddr` 与 nng 结构互转 | Zephyr 的 `sockaddr`（AF_UNIX 已移除） |
| DNS 解析 | `zephyr_resolv_gai.c` | `getaddrinfo()` | Zephyr 有该接口，但语义不同（见下表） |
| 随机数 | `zephyr_rand_urandom.c` | `/dev/urandom`、`getrandom()` | 按有无硬件熵源分岔（见下表） |
| 文件 | `zephyr_file.c` | `stdio`、`stat`、文件锁 | `stdio` + `stat` 为真实实现，临时目录与文件锁为回退（见下表） |
| 唤醒管道 | `zephyr_pipe.c` | `pipe()` / `eventfd()` | Zephyr 无对应设施（见下表） |

**POSIX 假设在哪里不成立**

| POSIX 假设 | Zephyr 现状 | 处理 |
|---|---|---|
| `readv()` / `writev()` | 无，也没有 `<sys/uio.h>` | 用 `read()` / `write()` 循环模拟，并显式对齐短传输语义（展开①） |
| `pipe()` / `eventfd()` | 无 | poll 队列不注册唤醒描述符，改由自身超时推进 |
| `flock()` / `lockf()` | 无文件锁 | 照 `posix_file.c` 自身的嵌入式回退写法：成功，但不加锁 |
| 临时目录 / 工作目录 | 无这两个概念 | `nni_plat_temp_dir()` 返回 `"/tmp"`（该处是否真挂了文件系统，由调用者的文件操作自行报错）；`nni_plat_getcwd()` 返回 NULL |
| `SO_PEERCRED` 一类的对端凭据 | 不可用 | 返回 `NNG_ENOTSUP`。对端凭据只服务于 AF_UNIX 的 IPC 传输，而该传输在 Zephyr 上不存在 |
| `socketpair()`（AF_UNIX 域套接字对） | 无 AF_UNIX | 返回 `NNG_ENOTSUP`；依赖它的 IPC 传输因此在 Zephyr 上不可用（见附录 A） |
| `/dev/urandom` | 无该设备 | 有硬件熵源（ESP32-S3 的 TRNG）时走 `sys_csrand_get()`；没有熵源的目标退回软件生成器，并在代码中标注不适用于机密用途 |
| 64 位原子操作 | 32 位非 x86 目标没有原生支持 | 回退为"内嵌互斥量上做原子"（展开②） |
| `SO_BINDTODEVICE` | 无接口绑定 | 在选项设置点直接返回 `NNG_ENOTSUP`，而不是接受后静默走默认接口 |
| `getaddrinfo()` | 有，但是同步的 | 接受同步语义：解析在调用者线程上完成，不引入 worker 线程 |
| `pthread_condattr_setclock()` | 依赖 `CONFIG_POSIX_CLOCK_SELECTION` | 启动时校验；取不到单调时钟即终止——否则所有定时等待会静默地立即超时 |

**展开①：`readv` / `writev` 的短传输语义。** 直接"循环把所有 iovec 写完"是错的。POSIX 的 `readv` / `writev` 在**第一次短传输**处就返回，并报告已传字节数，余下部分由调用方重新提交。模拟实现若跨过 iovec 继续写，就会在字节流里制造空洞；若在一次成功之后又遇到 `EAGAIN` 却返回 -1，调用方会认为这段根本没发出去而重发。正确做法是首个短传输即停、返回累计值——`posix_sockfd.c` 里那句注释（"we didn't send all the data, the caller will resubmit"）就是调用方对它的契约。

**展开②：原子操作为什么不用 pthread 互斥量。** 直觉做法是给每个原子变量内嵌一个 `pthread_mutex_t`，但 Zephyr 的 `pthread_mutex_init()` 是**从固定池里分配**的（`posix_mutex_pool`，位图分配，池耗尽时返回 `ENOMEM`）。而 nng 有 26 处原子变量初始化，其中只有 5 处配了 `nni_atomic_fini*()` 归还（pipe 的 3 个、消息的 refcnt、inproc 的 pair），其余都没有对应的归还调用。改用内核自带的 `struct k_mutex` 没有这个问题：内嵌、不占池、也无需释放。

**展开③：`ENABLE_LOG` 必须同时到达两侧。** nanolib 的 `conf.c` 是否初始化日志后端、`log_*()` 是否编出实体，由 `-DENABLE_LOG` 决定，而它必须**同时**传给应用与 libnng。原因在构建系统：nng 的 CMake 只认 `NNG_*` 形式的缓存变量，普通宏必须经 `CMAKE_C_FLAGS` 送进去。只给一侧的后果是静默的——链接照过、broker 照跑，只是一行日志都没有（`conf->log.type` 未初始化）。`ACL_SUPP` 同理，且不满足时的表现更危险：两侧定义不一致会让 `struct conf` 的布局错位。

### 三、编译期宏契约

| 宏 | 作用 | 不满足时 |
|---|---|---|
| `ENABLE_LOG` | 让 nanolib 初始化日志后端、`log_*()` 编出实体 | 日志静默失效 |
| `ACL_SUPP` | 让 `struct conf` 含 ACL 字段（默认开） | 两侧定义不一致 → 结构体布局错位 |
| `SUPP_NANO_LIB` | 隐藏 `nanomq.c` 的 `main()`，保留 `get_cache_argc/argv` | 与 demo 自身入口冲突 |
| `SUPP_SYSLOG` | **故意不设** | 会去找 Zephyr 没有的 `syslog()` |

### 四、两个框架层陷阱

以下两个问题都属于同一类：Zephyr 的 API 行为与直觉不符，且失败时没有任何错误提示，排查成本很高。

#### 一、PSRAM 堆在首个客户端连接时损坏

ESP32-S3 的内部 SRAM 约 512 KB（可用 416 KB），而 broker 的数据面需要数 MB，因此必须使用 PSRAM。Zephyr 提供了 `shared_multi_heap` 用于管理此类多堆区域，看似正合适——**但它不是线程安全的**，底层是未加锁的裸 `sys_heap`。

而 nng 会从多个线程分配内存：poller、taskq worker，以及每条连接自身的 aio。结果是**第一个客户端连接建立时堆即损坏**。

解决方案是不使用 `shared_multi_heap_alloc()`，改为在该 PSRAM 窗口上使用一个带锁的普通 `struct k_heap`。此外，Wi-Fi 驱动的 `.noinit`、net_buf 池、Zephyr POSIX 对象池（约 60 KB）等无需 SRAM 的静态池也一并迁移至 PSRAM，将内部 SRAM 留给真正需要的部分。

#### 二、net_mgmt 回调掩码不是按位匹配

Wi-Fi 连接流程需要监听多个事件。直觉上会把它们或进同一个掩码，注册一个回调：

```c
/* 错误：两个事件来自不同的 layer code */
net_mgmt_init_event_callback(&cb, handler,
    NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_IPV4_DHCP_BOUND);
net_mgmt_add_event_callback(&cb);
```

这样注册的回调**永远不会被触发**，且没有任何日志或错误码。

原因在 `mgmt_run_slist_callbacks()`（`subsys/net/ip/net_mgmt.c`）。它判断回调是否匹配某个事件时，用的是**整段 layer code 的相等比较**，而不是按位与：

```c
if (!(NET_MGMT_GET_LAYER(mgmt_event->event) ==
      NET_MGMT_GET_LAYER(cb->event_mask)) ||
    !(NET_MGMT_GET_LAYER_CODE(mgmt_event->event) ==
      NET_MGMT_GET_LAYER_CODE(cb->event_mask)) || ...
```

把两个不同 layer code 的事件或进同一个掩码后，`cb->event_mask` 中的 layer code 等于两者的按位或，既不等于 A 也不等于 B，于是任何事件都无法匹配。以这两个事件为例，Wi-Fi 事件的 layer code 为 `0x0D`、IPv4 为 `0x03`，或运算后得到 `0x0F`，与两者均不相等。

正确做法是**每个事件注册一个回调**（handler 可以复用）：

```c
/* 正确：每个事件一个回调结构体 */
net_mgmt_init_event_callback(&wifi_cb, handler, NET_EVENT_WIFI_CONNECT_RESULT);
net_mgmt_add_event_callback(&wifi_cb);

net_mgmt_init_event_callback(&dhcp_cb, handler, NET_EVENT_IPV4_DHCP_BOUND);
net_mgmt_add_event_callback(&dhcp_cb);
```

## 结语

将 broker 运行在 MCU 上的价值在于省去一台边缘网关：同一块已在现场的开发板，多运行一个 broker，即可将异构设备收敛为 MQTT，并在链路中断时于本地缓存。

### 适用边界

结合[附录 A](#附录-a与通用版-nanomq-的差异)的清单，当前实现适合的场景是受控网络内的小规模边缘汇聚与协议转换；在选型前需要明确以下几点：

- 不含 TLS、磁盘持久化与 MQTT 侧认证（这三项在附录 A 的「后续计划」列中标注为会补），**现阶段不适合直接作为公网或不可信网络中的 broker**；本文 demo 的默认配置监听全网卡，REST 虽提供 Basic 认证但无加密、且必须自行配置凭据（没有可用的默认凭据），见「安全前提」。
- 无文件系统，断电后缓存消息与持久会话不会保留。
- 并发能力受 Zephyr 线程配额约束；本文未将吞吐与并发作为正式 benchmark 发布，附录 A 中列出的官方性能数据出自多核 POSIX 环境，不代表本 demo 的表现。
- 除 `qemu_x86` 与 ESP32-S3 外，其他板卡均未验证。

### 代码与 Demo

代码位于 [nanomq/nanomq](https://github.com/nanomq/nanomq) 的 `zephyr-rtos` 分支，两个 demo 均在 `demo/` 目录下，各自的 README 记录了完整的 bring-up 过程。

若在其他板卡上完成验证，或遇到新的问题，欢迎在 [NanoMQ 社区](https://github.com/nanomq/nanomq/discussions)参与讨论。

## 附录 A：与通用版 NanoMQ 的差异

本移植并非 NanoMQ 在 Zephyr 上的等价替代，在若干维度上存在明确差异。了解这些边界有助于判断其是否适用于具体场景。

**基线版本。** 本移植基于 upstream `master`，即 NanoMQ **0.25.6**。

**配置来源。** 通用版 NanoMQ 从 `nanomq.conf` 文件读取配置；Zephyr 版采用**内嵌最小 conf**——由 `conf_init()` 的内置默认值加上启动代码直接设置关键字段（如监听地址），绕过配置文件解析。`conf` 结构体的语义保持不变，仅配置来源由文件换为内存构造。

**功能裁剪。** 外围功能（REST、rule 引擎、bridge 等）的策略是**全量编译 + 运行时开关**，而非编译期裁剪，以保证同一份源码在两个平台行为一致。下表列出本版本不可用或未经验证的能力，并区分**移植尚未完成（后续会补）**与**受平台或依赖所限（不补）**：

| 能力 | 状态 | 后续计划 |
|---|---|---|
| 文件系统相关 | 配置、日志、持久会话均不落盘；`$SYS` 仅反映运行时状态 | **支持**：挂载 Zephyr 的 fs 子系统（fat / ext2 / fcb 等）后即可 |
| SQLite 持久化 | 不包含（`NNG_ENABLE_SQLITE=OFF`） | **支持**：随文件系统一并打开 |
| Parquet | 不包含。由 `SUPP_PARQUET` 宏控制（不是 CMake 选项），未定义即不编入 | **支持**：同上，依赖文件系统 |
| TLS | 不包含（`NNG_ENABLE_TLS=OFF`）。Zephyr 侧提供 mbedTLS（本构建已启用）与 `tls_credentials` 子系统 | **支持**：打开后 MQTTS / WSS / HTTPS 可用 |
| MQTT 侧认证（口令 / ACL） | 未接线也未验证，当前任何客户端均可连接 | **支持**：属 conf 接线与验证工作 |
| rule 引擎 | 嵌入式 conf 无对应开关路径，未验证 | **支持**：纯软件模块，只差 conf 接线 |
| IPC 传输 | 在 demo 中被关闭（`main.c` 设 `ipc_internal = false`，属运行时赋值而非构建选项），因此 `nanomq ctl` 管理通道不可用 | **待平台支持**：需要具名 AF_UNIX，而 Zephyr 目前只有匿名 `socketpair` |
| QUIC | 不包含（`NNG_ENABLE_QUIC=OFF`）。nng 的 QUIC 实现依赖 msquic | **不计划**：依赖体量与嵌入式目标不合 |

**线程模型。** Linux 版依赖完整的 POSIX 动态线程池。Zephyr 版的 nng 线程数固定（taskq=2 / poller=1 / expire=1），叠加 Zephyr 的 POSIX 线程池上限（`CONFIG_POSIX_THREAD_THREADS_MAX=16`，每个 pthread 的栈由 `CONFIG_DYNAMIC_THREAD_STACK_SIZE` 定为 16 KB），broker 的并发能力受此约束。

**性能数据。** [NanoMQ 官方](https://nanomq.io/)公布的指标包括：最小功能集下启动占用低于 200 KB；百万级 TPS；在多核 CPU 上相较 Mosquitto 快至 10 倍。需要强调这些指标的适用范围：它们出自**多核 POSIX 环境**的 benchmark，官方页面未给出对应测试的硬件与配置细节，也**不代表本文 demo 的性能**——Zephyr 侧的线程配额远小于多核 Linux（见上一条），实际并发能力与此不同。本文未对 demo 做正式的性能测试。

**内存分配。** 分配器按目标而异：`qemu_x86` 用 libc `malloc()`，libc 的 malloc arena 就是 broker 堆（见 qemu 一节的说明）；ESP32-S3 内部 SRAM 放不下数据面，因此定义了 `NNG_ZEPHYR_ALLOC_SMH`，把 nng 的分配切到 PSRAM 上的 `k_heap`（见「移植过程 → 四、两个框架层陷阱」）。

**时间源。** 两个 demo 均使用真实 UTC，但来源不同：`qemu_x86` 从 QEMU 的 CMOS RTC 播种，ESP32-S3 实机因无 RTC 而通过 SNTP 播种。Zephyr 不带时区数据库，显示恒为 UTC。

**已剔除的模块。** broker 的 `process.c` 依赖 `fork`/`kill`/`chdir`，无法在 Zephyr 上编译，由 demo 中一个提供同名符号的 stub 替代。这些符号的调用点要么位于 daemon 与 CLI 路径、要么根本不存在，嵌入式 broker 都不会触达（替代方式见「移植过程 → 一、应用层」的对应表项）。

**已验证的目标平台。** `qemu_x86`（32 位）与 ESP32-S3。构建系统对**所有 32 位非 x86 目标**（ARM、RISC-V、Xtensa 等）启用原子操作回退（`NNG_ZEPHYR_NO_STDATOMIC`，机制见「移植过程 → 二、平台适配层」的展开②）——**ESP32-S3（Xtensa）本身就在使用该回退**，因此这条路径已随实机验证一并覆盖；尚未验证的是 ARM / RISC-V **板卡**本身（后续计划：ARM / RISC-V 等板卡的验证，网络驱动、中断与内存预算均需重验）。

## 附录 B：两个 demo 的对比

| | `demo/nanomq_zephyr_esp32s3` | `demo/nanomq_zephyr_qemu_x86` |
|---|---|---|
| 目标平台 | ESP32-S3 实机 | `qemu_x86` |
| 硬件需求 | ESP32-S3 开发板 | 无 |
| 网络 | Wi-Fi STA + DHCP | QEMU SLIRP 用户态网络 |
| 内存 / 存储 | 16 MB flash + 八线 PSRAM（数据面在 PSRAM） | 31 MB 模拟内存，无持久存储 |
| 额外前提 | Wi-Fi 凭据 | Zephyr e1000 驱动补丁 |
| 适用场景 | 真实评估、硬件测试 | 开发阶段的快速验证 |

两个 demo 共用同一份应用源码与同一个 NanoNNG ExternalProject 构建，差异仅在板级与网络层。开发阶段建议使用 `qemu_x86`：一轮构建加运行仅需数秒，显著快于烧录与复位。两者的完整编译与运行步骤见正文对应章节。
