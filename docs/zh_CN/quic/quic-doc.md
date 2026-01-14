# MQTT over QUIC 桥接产品说明


## 一、MQTT over QUIC 概述

QUIC（Quick UDP Internet Connections）是 IETF 标准化的一种新型传输层协议，基于 UDP，内建加密与多路复用特性。与传统基于 TCP 的 TLS 相比，QUIC 具有以下优势：

- 更快的连接建立：支持 0-RTT/1-RTT 建连，大幅缩短首次连接与重连时延。
- 多路复用无队头阻塞：单条连接上可并行多个 Stream，一个流阻塞不会影响其他数据流。
- 更灵活的拥塞与超时控制：在高丢包、高时延网络下表现更稳定。

基于 QUIC 协议，NanoMQ 支持 **MQTT over QUIC 桥接**：在 NanoMQ 与云端 MQTT Broker（如 EMQX 5.x）之间使用 QUIC 作为传输层，实现更快、更稳、更节省带宽的云边链路。


## 二、能力概览

MQTT over QUIC 桥接具备以下能力：

- 在云边之间建立基于 QUIC 的 MQTT 数据桥接。
- 在不改动终端设备 SDK 的前提下，通过桥接获得 QUIC 的性能优势。
- 支持 MQTT v3.1.1 与 MQTT v5 协议版本。
- 支持 QUIC 连接的超时、保活和拥塞控制等关键参数配置。
- 支持 QoS 1/2 消息优先传输策略，保障关键业务流量。
- 支持 QUIC/TCP 混合桥接模式，在 QUIC 不可用时自动回退到 TCP/TLS。


## 三、典型使用场景

### 1. 终端难以升级到 MQTT over QUIC

很多已部署终端仍使用 MQTT/TCP 协议，短期内难以升级 SDK。此时可以：

1. 终端设备继续以 MQTT/TCP 连接部署在边缘的 NanoMQ。
2. NanoMQ 通过 MQTT over QUIC 桥接连接云端 EMQX。

这样即可在不改动终端的前提下，让云边链路享受 QUIC 带来的性能提升。

### 2. 弱网、高时延与高丢包环境

在如下场景中，QUIC 相较于 TCP 具有明显优势：

- 跨地域公网传输（跨国、跨运营商）。
- 4G/5G 移动网络、车载网络等链路抖动较大的环境。
- 卫星网络等丢包率高、RTT 大的场景。

QUIC 的快速重连、多流与优化的拥塞控制，可以显著降低应用层时延和连通性抖动。

### 3. 高价值业务数据优先保障

当链路带宽有限、同时承载大量监控数据与少量关键业务数据时，可通过 **QoS 1/2 优先传输** 配置，优先保证告警、控制指令等高价值数据的可靠传输。

### 4. QUIC 能力的渐进引入

当尚不确定网络环境对 QUIC 的支持情况时，可开启 QUIC/TCP 混合桥接：

- 优先尝试通过 QUIC 建立连接。
- QUIC 不可用或多次失败后自动回退到传统 TCP/TLS。

这种方式便于在生产环境中逐步灰度引入 QUIC，而不影响现有业务稳定性。


## 四、启用 MQTT over QUIC 的步骤

### 1. 构建时启用 QUIC 功能

默认情况下，NanoMQ 二进制版本可能未启用 QUIC 模块。如需使用 MQTT over QUIC 桥接，需要自行构建并开启选项：

```bash
git clone https://github.com/emqx/nanomq.git
cd nanomq
git submodule update --init --recursive

mkdir build && cd build

# 启用 QUIC 桥接功能
cmake -G Ninja -DNNG_ENABLE_QUIC=ON ..
ninja install
```

如需将 msquic 编译为静态库，可额外添加：

```bash
cmake -G Ninja -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF ..
```

> 提示：国内网络环境下拉取 msquic 子模块可能耗时较长，请预留下载时间。

### 2. 基于 HOCON 配置文件启用桥接

主配置文件为 `nanomq.conf`。在该文件中使用 HOCON 语法定义桥接客户端：

1. 在 `bridges.mqtt.<name>` 段落中，设置 `server` 为 `mqtt-quic://host:port`。
2. 填写基础的 MQTT 桥接参数（协议版本、用户名密码、转发与订阅规则等）。
3. 配置一组 `quic_` 前缀的 QUIC 专用参数，精细控制连接行为。


## 五、配置项说明

### 1. 基础 MQTT 桥接参数

以下参数在 TCP / TLS / QUIC 桥接下通用，仅列出与 QUIC 使用最相关的部分：

- **`bridges.mqtt.<name>.server`**  
  - 含义：桥接目标 MQTT 服务器地址 URL。  
  - 示例：  
    - `mqtt-tcp://127.0.0.1:1883`（MQTT over TCP）  
    - `tls+mqtt-tcp://127.0.0.1:8883`（MQTT over TLS）  
    - `mqtt-quic://54.75.171.11:14567`（MQTT over QUIC）  

- **`bridges.mqtt.<name>.proto_ver`**  
  - 含义：桥接客户端使用的 MQTT 协议版本。  
  - 取值：`5`（MQTT v5）、`4`（MQTT v3.1.1）、`3`（MQTT v3.1）。  

- **`bridges.mqtt.<name>.clientid`**  
  - 含义：桥接客户端 ID，不配置时会自动生成随机 ID。  

- **`bridges.mqtt.<name>.keepalive`**  
  - 含义：MQTT 协议层保活间隔。  
  - 说明：该参数作用于 MQTT 协议本身，与 QUIC 传输层的 `quic_keepalive` 概念不同。  

- **`bridges.mqtt.<name>.username` / `password`**  
  - 含义：连接远端 Broker 的认证用户名、密码。  

- **`bridges.mqtt.<name>.forwards`**  
  - 含义：从本地转发到远端 Broker 的主题映射数组。  
  - 每个元素可配置：  
    - `local_topic`：本地匹配主题（支持通配符）。  
    - `remote_topic`：转发到远端时使用的主题。  
    - 可选 `qos`、`retain`、`prefix`、`suffix` 等。

- **`bridges.mqtt.<name>.subscription`**  
  - 含义：从远端 Broker 订阅并回流到本地的主题数组。  
  - 每个元素可配置：  
    - `remote_topic`：远端订阅主题。  
    - `local_topic`：回流到本地时使用的主题。  
    - `qos`，以及可选的 `retain_as_published`、`retain_handling`。

只要 `server` 使用 `mqtt-quic://` 前缀，上述桥接逻辑就会运行在 QUIC 传输层之上。

### 2. QUIC 专用配置参数

以下参数以 `bridges.mqtt.<name>.quic_` 前缀出现，仅在 `server` 使用 `mqtt-quic://` 时生效。

#### 2.1 基础超时与保活

- **`quic_keepalive`**  
  - 类型：Duration（示例：`120s`）  
  - 作用：通过 QUIC 传输层发送 keepalive 探测包的间隔，用于保持连接与路径可用。  
  - 默认值：`120s`。

- **`quic_idle_timeout`**  
  - 类型：Duration（示例：`120s`、`0s`）  
  - 作用：连接可以保持空闲的最长时间，超时后连接将被优雅关闭。  
  - 特殊值：`0` 表示禁用该超时（可能导致断连事件难以及时感知）。  
  - 默认值：`120s`。

- **`quic_discon_timeout`**  
  - 类型：Duration（示例：`20s`）  
  - 作用：在判定路径失效并断开连接前，等待 ACK 的最长时间，影响 QUIC Stream 的存活时长。  
  - 默认值：`20s`。

- **`quic_handshake_timeout`**  
  - 类型：Duration（示例：`60s`）  
  - 作用：建立 QUIC 连接时，完整握手允许占用的最长时间，超出则认为握手失败。  
  - 默认值：`60s`。

#### 2.2 拥塞控制与 RTT 相关参数

- **`quic_send_idle_timeout`**  
  - 类型：Duration（示例：`2s`、`60s`）  
  - 作用：发送端在该时间段内保持空闲后，将重置拥塞控制状态，以便重新估计网络状况。  
  - 默认值：`60s`（示例配置中常用较小值如 `2s`，可根据网络特性调整）。

- **`quic_initial_rtt_ms`**  
  - 类型：Duration（毫秒，示例：`800ms`）  
  - 作用：在尚未测量到实际 RTT 之前的初始 RTT 估计值，用于计算初始超时与窗口。  
  - 默认值：`800ms`。

- **`quic_max_ack_delay_ms`**  
  - 类型：Duration（毫秒，示例：`100ms`）  
  - 作用：接收端在收到数据后，最多等待多长时间再发送 ACK。  
  - 默认值：`100ms`。  
  - 调优建议：适当增大可以减少 ACK 包数量，减轻带宽负担；但过大可能轻微增加端到端时延。

#### 2.3 多流与 QoS 优先级

- **`quic_multi_stream`**  
  - 类型：Boolean（`true` / `false`）  
  - 作用：是否启用 QUIC 的多流桥接模式：  
    - `true`：一个 QUIC 连接上为不同 Topic/订阅自动分配不同 Stream，降低队首阻塞影响。  
    - `false`：不启用多流，所有数据使用单流发送。  
  - 默认值：`false`。  
  - 建议：在弱网或高并发订阅场景下，可在充分测试后开启。

- **`quic_qos_priority`**  
  - 类型：Boolean（`true` / `false`）  
  - 作用：是否在链路拥塞、发送队列有限时优先传输 QoS 1/2 消息：  
    - `true`：QoS 1/2 报文在内部缓冲与调度上具备更高优先级。  
    - `false`：所有 QoS 报文按同等优先级处理。  
  - 默认值：`true`。  
  - 典型场景：关键控制、告警数据使用 QoS 1/2，普通监测数据使用 QoS 0。

#### 2.4 0-RTT 快速重连

- **`quic_0rtt`**  
  - 类型：Boolean（`true` / `false`）  
  - 作用：是否启用 QUIC 的 0-RTT 重连能力，使重连时可以在 0 RTT 阶段发送应用数据，进一步降低重连时间。  
  - 默认值：`true`。  


## 六、QUIC/TCP 混合桥接配置

当希望在「优先使用 QUIC」的同时，确保在 QUIC 不可用时能自动回退到 TCP/TLS，可启用混合桥接：

- **`hybrid_bridging`**  
  - 类型：Boolean（`true` / `false`）  
  - 作用：是否开启混合桥接模式。开启后，桥接会在一组候选地址之间自动切换。

- **`hybrid_servers`**  
  - 类型：字符串数组  
  - 示例：  
    ```hcl
    hybrid_servers = [
      "mqtt-quic://127.0.0.1:14567",
      "mqtt-tcp://127.0.0.1:1883"
    ]
    ```  
  - 作用：配置候选的桥接服务器地址列表，一般第一个为 QUIC 地址，其余为 TCP/TLS 地址。当当前连接异常断开或无法建立时，会自动尝试列表中的下一个地址。

推荐在生产环境中采用「QUIC 优先 + TCP 兜底」的混合方式进行灰度，引导业务逐步迁移到 QUIC。


## 七、配置示例

### 1. 单一 MQTT over QUIC 桥接

```hcl
bridges.mqtt.emqx_quic {
  server    = "mqtt-quic://your_server_address:14567"
  proto_ver = 4
  clientid  = "bridge_client"
  username  = "emqx"
  password  = "emqx123"
  keepalive = "60s"

  # QUIC 专用参数
  quic_keepalive         = "120s"
  quic_idle_timeout      = "120s"
  quic_discon_timeout    = "20s"
  quic_handshake_timeout = "60s"
  quic_send_idle_timeout = "2s"
  quic_initial_rtt_ms    = "800ms"
  quic_max_ack_delay_ms  = "100ms"
  quic_multi_stream      = false
  quic_qos_priority      = true
  quic_0rtt              = true
  hybrid_bridging        = false

  # 消息转发：本地 -> 远端
  forwards = [
    { remote_topic = "fwd/topic1", local_topic = "topic1", qos = 1 },
    { remote_topic = "fwd/topic2", local_topic = "topic2", qos = 2 }
  ]

  # 消息订阅：远端 -> 本地
  subscription = [
    { remote_topic = "cmd/topic1", local_topic = "topic3", qos = 1 },
    { remote_topic = "cmd/topic2", local_topic = "topic4", qos = 2 }
  ]

  max_parallel_processes = 2
  max_send_queue_len     = 32
  max_recv_queue_len     = 128
}
```

### 2. QUIC/TCP 混合桥接

```hcl
bridges.mqtt.emqx_hybrid {
  server    = "mqtt-quic://your_server_address:14567"
  proto_ver = 5

  # 开启混合桥接：QUIC 优先，失败后回退到 TCP
  hybrid_bridging = true
  hybrid_servers  = [
    "mqtt-quic://your_server_address:14567",
    "mqtt-tcp://your_server_address:1883"
  ]

  quic_keepalive      = "120s"
  quic_idle_timeout   = "120s"
  quic_discon_timeout = "20s"
  quic_0rtt           = true
  quic_qos_priority   = true
}
```


## 八、使用命令行工具进行验证

内置 `nanomq_cli` 工具可用于快速验证 MQTT over QUIC 桥接。

### 1. 基于 QUIC 的订阅

```bash
./nanomq_cli sub --quic \
  -h remote.broker.address \
  -p 14567 \
  -t "forward1/#" \
  -q 2
```

### 2. 基于 QUIC 的发布

```bash
./nanomq_cli pub --quic \
  -h remote.broker.address \
  -p 14567 \
  -t "recv/topic1" \
  -m "cmd_msg" \
  -q 2 \
  -u emqx \
  -P emqx123
```

