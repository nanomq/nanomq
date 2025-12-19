## MQTT Stream 数据落盘与查询机制说明

本文档基于当前 NanoMQ 代码实现，对 **MQTT Stream（基于 exchange/ringbus 的数据落盘能力）** 做系统性说明，重点覆盖以下三个方面：

- **数据链路与背景**：MQTT 消息从接入到进入 ringbus 的全过程  
- **落盘插件与编码机制**：`streamType` / 插件如何决定 encode/decode 逻辑以及最终落盘  
- **落盘数据查询能力**：如何基于 `exchange_consumer` 对 ringbus / 文件中数据进行查询与消费  

---

## 一、数据链路与背景

### 1.1 背景与定位

MQTT Stream 在本项目中的主要定位，是面向**车端数据闭环**场景，为整车厂和 Tier1 提供一条“**从车载总线 → 网关 → 本地落盘 → 事后排查与分析**”的稳定通路。

在典型的车端部署中：

- 车内存在多条总线和数据源，例如：  
  - CAN / CAN-FD 报文（通过 `canudp`、`canspi` 等主题上报）  
  - 电池、电机等子系统的高频传感数据  
  - 网关自有的状态与诊断信息  
- 这些数据经过车载网关汇聚后，通过 MQTT 报文上传到本地的 NanoMQ 实例。

在实际量产环境中，仅依赖“在线上报到云端”往往无法满足以下关键诉求：

- **异常场景下的数据可追溯性**：  
  - 当车辆在路试或量产运营过程中出现异常（如动力中断、电池告警、总线异常抖动等）时，整车厂需要拿到**事发前后完整的一段原始数据**；  
  - 这些数据往往需要覆盖多个子系统、多条总线，且时间跨度可能从秒级到分钟级，用于问题重现、Root Cause 分析以及后续标定与改版。

- **弱网 / 离线环境下的数据可靠性**：  
  - 车辆行驶环境复杂，蜂窝网络可能弱覆盖或完全中断；  
  - 若只依赖“实时上报云端”，异常发生时的数据很可能无法第一时间送达；  
  - 通过在车端本地进行 **批量缓冲 + parquet 落盘**，可以保证即使云端长时间不可达，关键数据也能在车端完整留下。

- **车端-云端数据闭环与反馈**：  
  - 落盘数据可以在车厂的车间/实验环境中通过导出或者远程采集带回；  
  - 与云端分析平台、仿真平台对接后，可以形成**从车端采集 → 云端分析 → 策略/标定更新 → 再下发到车端**的完整闭环。

基于上述目标，NanoMQ 在 Broker 内部引入了 **Exchange + Ringbus + Parquet/自定义 Stream 插件** 的体系，来实现：

- 对特定主题（例如 `canudp`）的 MQTT 消息进行旁路采集与筛选；  
- 通过 ringbus 实现高性能本地缓冲，并在达到一定数量（如 1000 条）时触发批处理；  
- 由 Stream 插件负责将这一批消息统一编码为结构化数据（parquet 等），写入本地磁盘；  
- 后续再通过查询接口和 `exchange_consumer` 等工具，把这些历史数据以**时间窗口、key 范围等方式**提取出来，用于问题排查、回放与分析。

因此，可以把 MQTT Stream 理解为：  
**“在车端 NanoMQ 上，为 CAN/诊断等高频数据构建的一条可靠、本地可追溯的落盘与查询链路，是整车数据闭环能力的基础设施之一。”**

### 1.2 端到端数据链路概览（简要版）

从用户视角看，一条 `canudp` 等主题的 MQTT 消息，在开启 MQTT Stream 后大致会经历以下阶段：

1. **MQTT 接入**：  
   - 设备向 NanoMQ 发布 PUBLISH（例如主题 `canudp`），Broker 按标准 MQTT 协议接收并完成常规转发逻辑。
2. **Hook 复制到 Exchange**：  
   - 在 `webhook_post.c::hook_entry` 中，Broker 克隆这条 PUBLISH 消息，补充时间戳等元信息；  
   - 根据 `exchange_client.mqX.exchange.topic` 做 topic 匹配，命中后通过本地 NNG socket 把消息发给 Exchange Server。
3. **Exchange / Ringbus 缓冲**：  
   - Exchange Server 端根据配置为每个 exchange 维护一个 ringbus；  
   - 收到的 MQTT 消息按时间戳（key）入队 ringbus，ringbus 按 `cap` 限制缓冲条数。
4. **fullOp 满载处理 + 批量输出**：  
   - 当某个 ringbus 累积到 `cap` 条消息时，根据 `fullOp` 选择具体行为；  
   - 推荐使用 `RB_FULL_RETURN`：此时 ringbus 会把当前批次消息一次性返回给上层逻辑（而不是直接写文件），再清空自己，继续接收后续消息。
5. **Stream 插件编码与 Parquet 落盘**：  
   - 上层（Hook 回调 / Exchange 辅助逻辑）拿到这批消息后，构造 `stream_data_in`，调用 `stream_encode(streamType, ...)` 进入具体 Stream 插件；  
   - 插件负责把这一批消息编码为适合 parquet 的结构，随后通过 parquet 异步接口将其写入指定目录下的 parquet 文件。

如果用户只关心“**开关在哪、数据从哪到哪**”，理解上述 5 步即可；若希望精确了解每一步对应的源码与调用栈，可以参见下一节“**1.3 端到端数据链路详细解析（代码视角）**”。

### 1.3 端到端数据链路详细解析（代码视角）

本节从源码角度梳理一条完整链路：**MQTT PUBLISH → Hook → Exchange / Ringbus → FULL_RETURN → Stream 插件编码 → Parquet 落盘（以及后续查询）**。

#### 1.3.1 配置加载与 Exchange 初始化

- **配置解析（`conf_ver2.c::conf_exchange_parse_ver2`）**  
  - 从 `nanomq.conf` 中读取 `exchange_client.mqX` 节点，填充 `conf_exchange_node`：  
    - `name`：MQ 名称（如 `"exchange_no1"`）  
    - `topic`：要匹配的 MQTT 主题（如 `"canudp"`）  
    - `streamType`：对应 Stream 插件 ID（0=RAW，1=SPI，或用户自定义）  
    - `ringbus`：包含 `name/cap/fullOp` 等 ringbuffer 参数  
  - 所有 `conf_exchange_node` 被挂到全局 `conf.exchange.nodes[]` 中（`conf_exchange`），供运行期使用。

- **Exchange Client / Server 建立（`broker.c` + `exchange_server.c`）**  
  - 在 Broker 启动阶段，`broker.c` 会根据 `conf_exchange`：  
    - 为每个 `exchange_client.mqX` 创建一个 NNG socket，并根据 `exchange_url` 连接到本地 Exchange Server（`nng/src/mqtt/protocol/exchange/exchange_server.c`）；  
    - 将建立好的 `nng_socket*` 存入 `conf_exchange_node->sock`，供 Hook 阶段直接使用。  
  - Exchange Server 侧基于这些连接创建 `exchange_t` 实例，并为每个 exchange 初始化对应的 `ringBuffer_t`（`exchange.c::exchange_init` + `ringBuffer_init`）。

#### 1.3.2 Broker 侧 Hook：从 MQTT 流复制消息到 Exchange

- **入口：`webhook_post.c::hook_entry`**  
  - 每当 Broker 收到一条 MQTT PUBLISH（`work->flag == CMD_PUBLISH`），都会进入 `hook_entry`：  
    - 通过 `work->config->exchange` 获取 `conf_exchange`；  
    - 通过 `work->config->parquet` 判断是否开启 parquet 能力。  
  - 满足以下条件时，才会触发 Exchange 数据流：
    - `ex_conf->count > 0`（存在至少一个 `exchange_client` 配置）；  
    - `parquetconf->enable == true`；  
    - 当前消息类型为 PUBLISH。

- **消息克隆与时间戳设置**  
  - 为避免影响原始 MQTT 流，Hook 会执行（见 `hook_entry` 中部）：  
    - `nng_msg_alloc` 新建一条内部消息 `msg`；  
    - 拷贝 header 与 body（`nng_msg_header_append` / `nng_msg_append`）；  
    - 调整 payload 指针（`nng_msg_set_payload_ptr`）确保指向正确位置；  
    - 设置时间戳 `ts`：
      - `ts = nng_timestamp()`，并使用 `ts_mtx` 保证单调递增，最后写入 `nng_msg_set_timestamp(msg, ts)`；  
    - 这个时间戳就是后续 ringbus / parquet 查询中的 **key** 基础。

- **按 topic 匹配并发送到 Exchange**  
  - 遍历所有 `conf_exchange_node`：
    - 使用 `topic_filter(ex_conf->nodes[i]->topic, work->pub_packet->var_header.publish.topic_name.body)` 判断是否命中；  
    - 命中后，从 `hook_conf->saios[...]` 取出对应异步 `aio`，并等待其空闲；  
    - 将克隆后的 `msg` 绑定到 `aio`，通过 `nng_send_aio(*ex_sock, aio)` 发送到该节点对应的 Exchange Client socket（`ex_sock = ex_conf->nodes[i]->sock`）。  
  - 至此，一条 MQTT PUBLISH 消息被“旁路复制”到 Exchange 模块，进入 **MQ 内部队列 / ringbus 管线**。

#### 1.3.3 Exchange Server：写入 Ringbus 并处理满载

- **接收并入队（`exchange_server.c::exchange_sock_send` → `exchange_do_send`）**  
  - Exchange Server 收到来自 Hook 的 PUBLISH 消息后，调用：
    - `exchange_client_handle_msg(ex_node, msg, aio)`，内部会基于消息上的时间戳 `key` 调用：  
      - `exchange_handle_msg(ex_node->ex, key, msg, aio)`（见 `exchange.c`）。  
  - `exchange_handle_msg` 将消息写入对应的 ringbuffer：  
    - 实际调用 `ringBuffer_enqueue(ex->rbs[i], key, msg, -1, aio)`；  
    - `key` 即前面在 Hook 中设置的 `nng_msg_timestamp`。

- **满载行为（`ringbuffer.c::ringBuffer_enqueue`）**  
  - 当 `rb->size == rb->cap` 时，根据配置的 `fullOp` 执行不同策略：
    - `RB_FULL_NONE`：报错并返回入队失败，不清理旧数据；  
    - `RB_FULL_DROP`：`ringBuffer_clean_msgs(rb, 1)` 清空并释放当前所有消息，然后再入队当前新消息；  
    - `RB_FULL_RETURN`：  
      - `ringBuffer_get_and_clean_msgs` 获取并清空 ringbus 中当前所有消息，返回为一个 `nng_msg** list`；  
      - 通过 `put_msgs_to_aio(rb, aio)` 把 `list`（以及长度信息）塞到传入的 `aio` 中，交给上层回调（例如 `send_exchange_cb` / `hook_last_flush`）做后续处理（编码 + 落盘）；  
      - ringbus 清空后，再把当前新消息入队；  
    - `RB_FULL_FILE`：  
      - 在启用 parquet/BLF 的前提下，直接调用 `write_msgs_to_file(rb)` 将当前缓冲区写入文件，然后清空 ringbus，再入队新消息（目前主要用于内部测试）。

#### 1.3.4 从 FULL_RETURN 到 Stream 编码与 Parquet 落盘

- **FULL_RETURN 的回调处理（`webhook_post.c::send_exchange_cb` / `hook_last_flush`）**  
  - 当 `RB_FULL_RETURN` 触发时，`aio` 中已经带有一批 `nng_msg**`（以及条数信息）：  
    - `get_flush_params()` 会从 `aio` / `msg` 中解析出：
      - `msgs_del`：需要落盘的消息数组；  
      - `msgs_len`：数组长度；  
      - `topic`：对应 exchange 的 topic；  
      - `streamType`：本 exchange 使用的 Stream 插件 ID。  
  - 随后调用 `flush_smsg_to_disk()`：
    - 内部首先将 `nng_msg**` 封装为 `struct stream_data_in`（keys 来自 `nni_msg_get_timestamp`）；  
    - 再调用 `stream_encode(streamType, sdata)`，也就是进入具体插件的 `encode` 实现（如 RAW 的 `raw_encode`），生成适合 parquet 写入的结构（如 `parquet_data*`）；  
    - 最终通过 `parquet_object_alloc` + `parquet_write_batch_async` 将本批数据写入 parquet 文件。

通过以上几个阶段，**一条 MQTT PUBLISH 消息从 Broker 被采集、旁路复制、写入 Exchange/ringbus，并在 FULL_RETURN 触发时经由 Stream 插件统一编码后批量落入 parquet 文件**，为后续的查询与回放提供了可靠的数据基础。查询端从 parquet/ringbus 取数据、经 `stream_decode` 解码再回到 `exchange_consumer` 的过程，则在后文专门章节中展开。

### 1.4 配置示例：以 `canudp` 为例

在 `etc/nanomq.conf` 中，数据落盘链路主要通过如下配置启用（节选，已将 `fullOp` 改为推荐值 `2`，即 `RB_FULL_RETURN`）：

```conf
# Exchange configuration for Embedded Messaging Queue
exchange_client.mq1 {
    # Exchange Server 地址（Exchange Server / MQ 后端）
    exchange_url = "tcp://127.0.0.1:10000"

    # exchanges contains multiple MQ exchanger
    exchange {
        # MQTT Topic 过滤条件
        topic = "canudp",
        # MQ 名称
        name  = "exchange_no1",
        # 可选：指定流插件类型（编码/解码策略）
        # streamType = 0  # 0: raw; 1: SPI stream; ...

        # MQ category: 当前仅支持 Ringbus
        ringbus = {
            name = "ringbus",
            # ring buffer 最大消息条数
            cap  = 1000,
            # ringbus 满载策略，2 表示 FULL_RETURN（推荐）
            fullOp = 2
        }
    }
}

# Parquet 落盘配置
parquet {
    compress         = zstd
    dir              = "./parquet"
    file_name_prefix = "nanomq"
    file_count       = 10
    file_size        = 100MB
    limit_frequency  = 5
}
```

在上述配置中：

- 主题为 `canudp` 的 MQTT 消息会被 `hook_entry` 捕获并投递到 `exchange_client.mq1` 对应的 Exchange Server；  
- ringbus 容量为 1000，当累计 1000 条消息后会触发 `fullOp = 2 (RB_FULL_RETURN)` 行为：ringbuffer 将当前缓冲区内的所有消息一次性返回给上层 aio，并清空自身，再入队新消息；  
- 上层基于这一批返回的消息，通过 Stream 插件和 parquet 统一完成编码与落盘处理，既保证性能，又便于扩展与调试。

---

## 二、落盘数据插件与编码/解码机制

### 2.1 Stream 插件体系概览

在 NanoMQ 中，真正决定“**如何编码/解码 MQTT 消息并落盘**”的是 **Stream 插件体系**，核心代码位于：

- `nng/exchange/stream/stream.c`  
- `nng/exchange/stream/raw_stream.c`  
- `nanomq/plugin_spi_stream.c` / `nanomq/plugin/plugin_spi_stream.c`

核心抽象是：

- `stream_register(name, id, decode, encode, cmd_parser)`  
  - 每个 Stream 插件通过 `id` 唯一标识  
  - 提供三组关键函数：
    - `encode`：将内部标准消息结构编码为适合落盘/传输的二进制格式（如 parquet 列式数据）  
    - `decode`：将落盘数据解析还原为上层可直接消费的结构（如连续二进制缓冲区）  
    - `cmd_parser`：解析上层传入的查询指令字符串（如 RAW 的 `"sync-<start>-<end>"`）

当前系统内置至少两类 Stream：

- **Raw Stream（`RAW_STREAM_ID = 0`）**  
  - 直接对 MQTT payload 做相对简单的封装，适合通用场景  
- **SPI Stream（`SPI_STREAM_ID = 0x1`）**（在 `spi_plugin_init` / `nano_plugin_init` 中注册）  
  - 为 SDV/车载场景设计的流插件，配合自定义的 key 结构与查询协议使用

`conf_exchange_node` 中的 `streamType` 字段，即是告诉 Exchange：**当前 MQ 节点使用哪一个 Stream 插件 ID 来处理数据**。

### 2.2 从 ringbus 到落盘：编码流程

以推荐的 `RB_FULL_RETURN` + `flush_smsg_to_disk` 路径为例，从 ringbus 到 parquet 落盘的核心编码流程如下（对应 `ringbuffer.c`、`webhook_post.c` 和 `stream.c`）：

1. **构造输入数据结构 `stream_data_in`**  
   - 当 ringbus 满且配置为 `RB_FULL_RETURN` 时，`ringBuffer_get_and_clean_msgs` 会取出当前缓冲区内的所有 `nng_msg*`，并清空 ringbus；  
   - 在 `webhook_post.c::flush_smsg_to_disk` / `cb_data_init` 中，这批消息被规整为 `struct stream_data_in`：  
     - `datas[i]` 指向每条消息的 payload；  
     - `lens[i]` 为对应 payload 长度；  
     - `keys[i]` 为每条消息的关键 key（此处使用 `nni_msg_get_timestamp(msg)`，即时间戳）。  

2. **调用 Stream 插件的 `encode`**  
   - 上层调用 `stream_encode(streamType, sdata)`：  
     - 对于 RAW 插件，`raw_encode` 会将 `stream_data_in` 转成 `stream_data_out`，再经 `parquet_data_alloc` 组装为 parquet 所需的列式结构；  
     - 对于其他插件，可以在此阶段实现自定义的列裁剪、压缩、字段规整等逻辑。  
   - 编码后的结果（通常是 `parquet_data*`）作为“批量数据块”被传入后端写盘逻辑。

3. **调用 Parquet 等后端写入**  
   - 在 `SUPP_PARQUET` 场景下，插件会将编码后的数据组装为 `parquet_data` 或相应结构：  
     - 包含列式 schema（字段名、类型）  
     - 各列 payload  
     - 时间戳列（`ts`）  
   - 然后通过 `parquet_object_alloc` + `parquet_write_batch_async` 等接口异步写入磁盘文件，实际路径与前缀由 `parquet { ... }` 配置决定。  
   - BLF 等其他格式目前仍处于内部测试阶段，本文不做展开；其数据流同样会在 ringbus 满载时经由相应后端写入文件。

通过上述流程，MQTT 消息从 ringbus 被 Stream 插件标准化、编码，并最终以列式数据的形式落入磁盘文件，兼顾了性能与后续可检索性。

### 2.3 从落盘到查询结果：解码流程

当上层需要对历史数据进行查询（例如通过 `exchange_consumer`）时，解码路径大体为：

1. **解析查询命令（`cmd_parser`）**  
   - 上层通过 pair0 通道向 Exchange Server 发送一条查询命令字符串：  
     - RAW 插件场景下，命令形式为 `sync-<start_key>-<end_key>` 或 `async-<start_key>-<end_key>`；  
     - 其他插件（如 SPI）可以定义各自的命令格式。  
   - `exchange_server.c::query_cb` 收到命令后，根据 `streamType` 调用：  
     - `cmd_data *cmd = stream_cmd_parser(streamType, keystr)`  
   - `cmd_data` 中一般包含：
     - `is_sync`：同步 / 异步查询模式；  
     - `start_key` / `end_key`：查询的 key（时间戳）范围；  
     - `schema`：需要返回的列集合（RAW 默认 `{"ts","data"}`，见 `raw_stream.c::parse_input_cmd`）。

2. **Exchange Server 调用 Stream 查询/解码**  
   - 在 `query_send_sync` / `query_send_async` 中，Exchange 会：
     - 从 ringbus 中按 key 范围取出在内存中的数据（`exchange_client_get_msgs_fuzz`）；  
     - 同时调用 parquet 查询接口（如 `parquet_get_data_packets_in_range_by_column`）从落盘文件中取回 `parquet_data_ret**`；  
   - 对于从 parquet 取回的每个 `parquet_data_ret*`，根据 `streamType` 调用：
     - `struct stream_decoded_data *out = stream_decode(streamType, parquet_data_ret_ptr)`  
   - 以 RAW 插件为例，`raw_decode` 会：
     - 计算所有单元格 `payload_arr[i][j]` 的总长度；  
     - 分配一块连续缓冲区，将各条记录的 `data` 按顺序拼接到一起，形成最终可下发的数据流。

3. **数据重组与返回**  
   - Exchange 将来自 ringbus 的实时数据和来自 parquet 的历史数据分别解码后，按一定顺序写入返回消息：  
     - 同步查询模式下，会将所有解码结果累积到一条或少量几条 NNG 消息中再一次性发送；  
     - 异步查询模式下，则可能按文件 / 时间片拆分为多条消息逐个发送。  
   - 返回载荷的具体二进制格式完全由 Stream 插件定义：  
     - 对于 RAW 插件，就是一块连续的原始二进制数据（多个报文的 payload 拼接）；  
     - 对于自定义插件，可以是 JSON、TLV 或任意自定义协议。  
   - 上层应用（如 `exchange_consumer`）只需按插件约定的格式解析收到的字节流，即可完成历史数据的消费。

通过 `encode` / `decode` 的双向封装，NanoMQ 实现了 **“原始 MQTT 报文 → 结构化落盘 → 插件自定义格式回读”** 的能力，而不会把落盘格式和查询协议写死在核心代码中，具备较好的可扩展性与可演进空间。

### 2.4 自定义 Stream 插件扩展

在内置 RAW / SPI 之外，用户也可以根据自身业务定义新的 Stream 插件，只需实现统一的接口并在启动时完成注册。

#### 2.4.1 需要实现的数据结构与接口

在 `nng/include/nng/exchange/stream/stream.h` 中，Stream 相关的公共结构与注册接口定义如下（节选）：

```c
struct stream_data_in {
    void     **datas;  // 每条消息的 payload 指针
    uint64_t  *keys;   // 每条消息对应的 key（通常是时间戳）
    uint32_t  *lens;   // 每条消息 payload 的长度
    uint32_t   len;    // 消息条数
};

struct stream_data_out {
    uint32_t                col_len;     // 列数
    uint32_t                row_len;     // 行数
    uint64_t               *ts;          // 时间戳列
    char                  **schema;      // 列名数组
    parquet_data_packet ***payload_arr;  // 各列数据（供 parquet 使用）
};

struct stream_decoded_data {
    void     *data;   // 解码后的连续缓冲区
    uint32_t  len;    // data 长度
};

struct cmd_data {
    bool      is_sync;     // true: sync; false: async
    uint64_t  start_key;   // 起始 key（通常是起始时间戳）
    uint64_t  end_key;     // 结束 key
    uint32_t  schema_len;  // 需要查询的列数
    char    **schema;      // 列名数组（如 {"ts", "data"}）
};

int   stream_register(char *name, uint8_t id,
                      void *(*decode)(void *),
                      void *(*encode)(void *),
                      void *(*cmd_parser)(void *));
void *stream_decode(uint8_t id, void *buf);
void *stream_encode(uint8_t id, void *buf);
void *stream_cmd_parser(uint8_t id, void *buf);
```

用户自定义的插件通常需要实现如下三个函数（以 `my` 为例）：

```c
// 1) 编码：将 ringbus 批量消息转换为写盘所需格式（通常是 parquet_data）
void *my_encode(void *data);
// data 实际类型：struct stream_data_in *
// 返回值：用于写入 parquet 的编码结果（常见做法是构造 struct stream_data_out，
//         然后调用 parquet_data_alloc，返回 parquet_data*）

// 2) 解码：将 parquet 查询结果（parquet_data_ret*）转换为可直接下发/展示的连续缓冲区
void *my_decode(void *data);
// data 实际类型：struct parquet_data_ret *
// 返回值：struct stream_decoded_data *

// 3) 查询命令解析：把字符串形式的查询指令解析为 cmd_data
void *my_cmd_parser(void *data);
// data 实际类型：const char *（来自 exchange_consumer 传入的命令字符串）
// 返回值：struct cmd_data *
```

插件在初始化时，通过 `stream_register` 完成注册，例如（参考 `raw_stream_register` / `spi_plugin_init`）：

```c
int my_stream_init() {
    int   ret  = 0;
    char *name = malloc(strlen("my_stream") + 1);
    if (name == NULL) {
        return -1;
    }
    strcpy(name, "my_stream");

    // 假设自定义 ID 为 0x2，需确保不与现有的 0（RAW）、0x1（SPI）冲突
    ret = stream_register(name, 0x2, my_decode, my_encode, my_cmd_parser);
    if (ret != 0) {
        free(name);
        return -1;
    }
    return 0;
}
```

完成注册后，只要在 `nanomq.conf` 中为对应的 `exchange` 设置 `streamType = 0x2`，整个链路就会自动切换到你的插件逻辑。

#### 2.4.2 在链路中的调用时机

结合前文的数据流，可以概括自定义 Stream 插件的三个关键介入点：

- **1）写盘前的批量编码（`encode`）**  
  - 触发条件：ringbus 满载且为 `FULL_RETURN`，或调用 `hook_last_flush` 进行强制 flush。  
  - 调用栈（示意）：
    - `ringBuffer_enqueue` 在 `RB_FULL_RETURN` 时，将当前批次消息打包放入 `aio`；  
    - `webhook_post.c::send_exchange_cb` / `hook_last_flush` 中通过 `get_flush_params` 拿到 `streamType` 和消息列表；  
    - 构造 `struct stream_data_in` 后，调用：  
      - `stream_encode(streamType, sdata)` → 实际落到你的 `my_encode`；  
    - 返回的编码结果（通常是 `parquet_data*`）会被传入 `parquet_object_alloc` / `parquet_write_batch_async`，最终写入 parquet 文件。

- **2）查询指令解析（`cmd_parser`）**  
  - 触发条件：`exchange_consumer` 通过 pair0 向 Exchange 发送一条查询命令字符串。  
  - 调用栈（示意）：
    - `exchange_consumer` 把命令（如 `"sync-<start>-<end>"`）作为 payload 发给 Exchange Server；  
    - `exchange_server.c::query_cb` 取出字符串 `keystr` 后调用：  
      - `cmd_data *cmd = stream_cmd_parser(streamType, keystr)` → 实际落到你的 `my_cmd_parser`；  
    - 返回的 `cmd_data`（含 `is_sync/start_key/end_key/schema` 等）会被 `query_send_sync` / `query_send_async` 用来驱动后续 ringbus + parquet 查询。

- **3）查询结果解码（`decode`）**  
  - 触发条件：`query_send_sync` / `query_send_async` 从 parquet 文件或 ringbus 中取回原始批量数据。  
  - 调用栈（示意）：
    - 从 parquet 文件读出 `parquet_data_ret*` 数组（`parquet_get_data_packets_in_range_by_column` 等）；  
    - 对每个元素调用：  
      - `stream_decode(streamType, parquet_data_ret_ptr)` → 实际落到你的 `my_decode`；  
    - `my_decode` 负责把列式结构重组为最终要下发的字节流（如拼接成连续二进制或 JSON）；  
    - 解码结果（`struct stream_decoded_data`）被追加到 NNG 消息中，通过 pair0 socket 回送给 `exchange_consumer` 或其他上层组件。

通过这三个扩展点，用户可以：

- 定制**写盘前的打包/编码策略**（例如自定义列、压缩方式、payload 规整）；  
- 定制**查询协议与语法**（不仅限于 `sync/async-<start>-<end>`，也可以引入更多参数）；  
- 定制**返回数据的最终格式**（原始二进制、JSON、特定业务协议等），而无需修改 NanoMQ 核心逻辑。  

---

## 三、编译与测试流程示例

本节结合仓库脚本与推荐配置，给出一套可直接执行的 **编译 + 落盘测试** 流程，方便快速验证 MQTT Stream 能力。

### 3.1 编译 NanoMQ（二进制开启 Parquet 能力）

在仓库根目录下，推荐直接使用已有的 `build.sh`：

```bash
cd /path/to/NanoMQ_mirror
./build.sh
```

`build.sh` 内容大致为：

```bash
mkdir build
cd build
cmake -DENABLE_PARQUET=ON -DENABLE_FILETRANSFER=ON ../
make -j32
```

- **ENABLE_PARQUET=ON**：开启 Parquet 支持，用于将 ringbus 批量数据写入 parquet 文件  
- **ENABLE_FILETRANSFER=ON**：开启文件传输相关能力（可配合后续扩展使用）

编译完成后，在 `build/` 目录下会生成 `nanomq` 可执行文件以及相关 demo 程序。

### 3.2 推荐测试配置（节选自 `nanomq.conf`）

下面的配置直接节选自默认的 `etc/nanomq.conf`，以 `canudp` 主题为例，ringbus 容量为 1000，`fullOp` 采用 **FULL_RETURN（2）**：

```conf
# #====================================================================
# # Exchange configuration for Embedded Messaging Queue
# #====================================================================
# # Initialize multiple MQ exchanger by giving them different name (mq1)
exchange_client.mq1 {
	# # Currently NanoMQ only support one MQ object. URL shall be exactly same.
	exchange_url = "tcp://127.0.0.1:10000"
	# # exchanges contains multiple MQ exchanger
	exchange {
		# # MQTT Topic for filtering messages and saving to queue
		topic = "canudp",
		# # MQ name
		name = "exchange_no1",
		# # MQ category. Only support Ringbus for now
		ringbus = {
			# # ring buffer name
			name = "ringbus",
			# # max length of ring buffer (msg count)
			cap = 1000,
			# #  0: RB_FULL_NONE: When the ringbus is full, no action is taken and the message enqueue fails
			# #  1: RB_FULL_DROP: When the ringbus is full, the data in the ringbus is discarded
			# #  2: RB_FULL_RETURN: When the ringbus is full, the data in the ringbus is taken out and returned to the aio
			# #  3: RB_FULL_FILE: When the ringbus is full, the data in the ringbus is written to the file
			#
			# # Value: 0-4
			# # Default: 0
			# # Note: SDV flow is only applicable to RB_FULL_RETURN(2)
			fullOp = 2
		}
	}
}

# #====================================================================
# # Parquet configuration (Apply to Exchange/Messaging_Queue)
# #====================================================================
parquet {
	# # Parquet compress type.
	# #
	# # Value: uncompressed | snappy | gzip | brotli | zstd | lz4
	compress = zstd
	# # The dir for parquet files.
	# #
	# # Value: Folder
	dir = "./parquet"
	# # The prefix of parquet files written.
	# #
	# # Value: string
	file_name_prefix = "nanomq"
	# # Maximum rotation count of parquet files.
	# #
	# # Value: Number
	# # Default: 5
	file_count = 10
	# # The max size of parquet file written.
	# #
	# # Default: 10M
	# # Value: Number
	# # Supported Unit: KB | MB | GB
	file_size = 100MB
	# # The max number of searches per second.
	# #
	# # Default: 5
	# # Value: Number
	limit_frequency = 5
}
```

**说明与建议：**

- 对普通用户，**优先推荐使用 FULL_RETURN（2）**，由上层 SDV 流程/插件负责消费返回的数据并写入 parquet；  
- `RB_FULL_FILE（3）` 直接由 ringbus 将数据写文件，目前仍在内部测试场景中使用，**不建议对外作为首选方案**。  
- `dir`、`file_name_prefix` 等项可根据实际部署环境修改。

### 3.3 启动 NanoMQ 与发送测试数据

1. **启动 NanoMQ**

   在 `build/` 目录中执行：

   ```bash
   cd build/
   ./nanomq start --conf=../etc/nanomq.conf
   ```

2. **发送 1000 条 `canudp` 主题的 RAW 数据**

   可以使用任意 MQTT 客户端（如 `emqtt_bench`、`mosquitto_pub` 或自研工具），下面以 `emqtt_bench` 为例：

   ```bash
   # 示例：发送 1000 条消息到 canudp 主题，payload 可根据业务自定义
   emqtt_bench pub \
     -h 127.0.0.1 -p 1883 \
     -c 1 -I 1 -i 1 \
     -t "canudp" \
     -s 16 \
     -n 1000
   ```

   只要 MQTT 客户端向 `canudp` 发布 1000 条消息，且内容满足 RAW Stream 解析预期，即可触发后续 FULL_RETURN 行为。

### 3.4 观察日志与 parquet 落盘结果

当 ringbus 中累计消息达到 `cap = 1000` 后：

- 在 NanoMQ 日志中可以看到与 ringbus 满载、FULL_RETURN 行为相关的日志输出，表示：
  - ringbus 已达到阈值  
  - 当前批次数据已通过 FULL_RETURN 回传给上层流程

在推荐的 SDV 流程中，上层会在收到 FULL_RETURN 返回的数据后，进一步驱动 **Parquet 写入逻辑**，最终你可以在 `parquet.dir` 指定目录下看到生成的 parquet 文件，例如：

```text
./parquet/nanomq-canudp-xxxx.parquet
```

该 parquet 文件中即存储了本次触发 FULL_RETURN 的 1000 条 `canudp` 数据。后续可以使用任意 Parquet 工具进行查看与分析，例如：

- `parquet-tools`  
- Pandas / PyArrow（Python）  
- Spark / Flink 等大数据组件

---

## 四、落盘数据查询与 `exchange_consumer` 使用

### 4.1 查询通道与协议形式

NanoMQ 为 Exchange 暴露了一条用于数据查询的 **本地 NNG 通道**。在仓库中可以看到 demo：

- `nng/demo/exchange_consumer/exchange_consumer.c`

该 demo 的核心行为是：

- 使用 `nng_pair0` 连接到 Exchange Server：  
  - 默认地址：`tcp://127.0.0.1:10000`（与 `exchange_url` 一致）  
- 将**一条命令字符串**作为 payload 发送给 Exchange Server  
- 持续接收回复，直到收到一个特殊 EOF 消息：
  - 消息长度为 2 字节  
  - 内容为 `0x0B 0xAD`（在 `exchange_server.c::query_send_eof` 中定义）

在 EOF 之前，每一条收到的消息都可以被视为“**查询结果的一个批次**”。

### 4.2 ringbus/file 中数据的组织方式（RAW Stream）

在使用 **RAW Stream（`streamType = 0`）** 的场景下，ringbus/file 中的数据可以抽象为 **key/value** 结构：

- **key**：当前实现中采用 `nng_msg_set_timestamp` 设置的 64 位时间戳（毫秒级单调递增），可用于按时间范围检索  
- **value**：MQTT 报文 payload 的编码结果（在 RAW 场景下通常是原始二进制数据，落盘后在 parquet 中对应 `data` 列）

基于时间戳作为 key，有两个直接好处：

- 方便按时间窗口（如某一段行驶时间）进行范围查询  
- 查询指令只需携带起止 key，即可一次性拉取该时间范围内的所有记录

### 4.3 `exchange_consumer` Demo 使用方式（新查询命令）

当前 RAW Stream 的查询命令格式已经更新，统一采用：

```text
sync-<start_key>-<end_key>
async-<start_key>-<end_key>
```

其中：

- `sync` / `async`：表示查询模式  
  - `sync`：同步查询，一次性拉取指定 key 范围内的数据  
  - `async`：异步查询模式，由 Exchange 决定以何种方式分批返回结果  
- `<start_key>`：起始 key，一般对应起始时间戳（整数）  
- `<end_key>`：结束 key，一般对应结束时间戳（整数，需大于等于 `<start_key>`）

结合前文描述的 key 语义，一个常见用法是：

- 使用较小的起始 key（如 `0`）和较大的结束 key（如当前时间附近的上界），实现“从头到尾”的全量查询；  
- 或者根据业务需要，精确指定某个时间窗口的起止时间戳。

假设已按上一节完成配置并启动 NanoMQ：

```bash
nanomq start --conf=/etc/nanomq.conf
```

并确保有消息持续写入 ringbus/文件后，可以通过 `exchange_consumer` 执行查询。

#### 4.3.1 按时间范围同步查询

```bash
$ ./demo/exchange_consumer/exchange_consumer "sync-1700000000000-1700000005000"
Received 1234 bytes
Received 5678 bytes
...
```

含义说明：

- 向 Exchange Server 发送命令：`"sync-1700000000000-1700000005000"`  
- RAW Stream 的 `raw_cmd_parser` 会将其解析为：
  - `is_sync = true`  
  - `start_key = 1700000000000`  
  - `end_key = 1700000005000`  
- Exchange Server 将从 parquet 中读取这一时间窗口内的所有记录，解码后按多帧消息返回，直到收到 EOF（`0x0B 0xAD`）为止。

#### 4.3.2 按时间范围异步查询

```bash
$ ./demo/exchange_consumer/exchange_consumer "async-1700000000000-1700000005000"
Received 1024 bytes
Received 2048 bytes
...
```

与 `sync` 形式类似，只是 `is_sync = false`，由 Exchange 决定内部如何调度与返回（例如更适合长时间窗或大批量数据查询）。

> 提示：`start_key` / `end_key` 的具体数值，可以结合业务时间戳、parquet 中的 `ts` 列或上游系统记录来确定；对于简单验证场景，也可以直接使用较大的范围（如 `sync-0-9223372036854775807`）做近似“全量拉取”。

在更复杂场景下，可以在 RAW 之上扩展自己的 Stream 插件与 `cmd_parser`，支持：

- 自定义 schema（返回更多字段）；  
- 组合条件查询；  
- 分页与游标等高级功能。

### 4.4 与在线管道的协同

由于 Exchange 查询通道与 MQTT 在线转发解耦，可以灵活组合：

- **在线 + 离线混合模式**：  
  - 实时处理通过普通 MQTT 订阅实现  
  - 历史补偿通过 Exchange 查询实现  
- **离线回放**：  
  - 将 `exchange_consumer` 输出的数据再次写入 MQTT 或其他总线，实现重放  
- **多下游系统共享**：  
  - 相同的落盘数据可被不同的分析/监管系统消费，避免重复采集与存储

---

## 五、总结
 
- **车端数据闭环定位清晰**：  
  - MQTT Stream 以车端 CAN/诊断等高频数据为主要对象，通过 Exchange + Ringbus + Parquet 的组合，在 NanoMQ 内部构建了一条“从采集到本地落盘再到事后查询”的稳定链路；  
  - 在车辆异常、弱网/离线等复杂场景下，依然可以保证关键数据被可靠缓存和持久化，为整车厂后续的问题追溯和策略优化提供基础数据。
 
- **端到端链路与 FULL_RETURN 策略可控可扩展**：  
  - 从 `webhook_post.c::hook_entry` 的旁路复制，到 `exchange_server.c` 写入 ringbus，再到 `RB_FULL_RETURN` 触发 `flush_smsg_to_disk`，整条路径在代码层面是清晰可循的；  
  - 推荐使用 `fullOp = 2 (RB_FULL_RETURN)`，让 ringbus 只负责高效缓冲与批量回传，而具体的编码与落盘则由上层通过 Stream 插件与 parquet 实现，既便于调试也有利于后续扩展。
 
- **Stream 插件与查询能力灵活**：  
  - 通过 `stream_register` / `stream_encode` / `stream_decode` / `stream_cmd_parser` 四个统一接口，用户可以在 RAW/SPI 之外，按需扩展自己的编码格式、查询协议和返回格式；  
  - 当前 RAW 插件已经支持基于时间戳 key 的 `sync/async-<start>-<end>` 范围查询，配合 `exchange_consumer` demo，可以方便地实现车端 parquet 文件的时间段回放与数据导出。
 
- **实用的编译与测试路径**：  
  - 通过仓库自带的 `build.sh` 和推荐的 `exchange_client` / `parquet` 配置，用户可以快速在本地复现完整链路：发送 `canudp` 主题的 1000 条测试数据 → 触发 FULL_RETURN → 观察 parquet 文件生成 → 使用 `exchange_consumer` 进行时间范围查询，从而验证整套 MQTT Stream 能力是否符合预期。

