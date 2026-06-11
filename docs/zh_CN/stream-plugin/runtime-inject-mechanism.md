# Stream Plugin Runtime 与 Inject 机制详解

本文面向“要读源码/要做插件”的开发者，重点解释：

- `stream_plugin` 运行时如何加载、分发、停止
- `stream_inject` 如何把插件输出重新注入 Broker 主发布链路
- 两者如何配合，以及配置项该如何选

---

## 1. 先看整体：两条链路

在 NanoMQ 中，Stream Plugin 相关能力可以理解为两条互补链路：

1. **消费链路（Broker -> Plugin）**
  Broker 在处理 PUBLISH 时，根据 `stream_plugin.spX.topic` 做 topic 过滤，把消息旁路分发给插件的 `on_msg`。
2. **注入链路（Plugin -> Broker）**
  插件调用 `nano_mqtt_publish_async()`（或 `nano_mqtt_publish()`），消息先入 `stream_inject` 队列，再由注入 worker 重新走 Broker 的发布处理流程。

消费链路负责“看消息并处理”，注入链路负责“把处理结果回灌到 Broker”。

---

## 2. Runtime 生命周期（`stream_plugin_runtime.c`）

### 2.1 启动顺序

Broker 启动时（`apps/broker.c`）按如下顺序调用：

1. `stream_plugin_load_all(cfg)`：按配置逐个 `dlopen` 插件
2. `stream_inject_start(cfg, sock)`：初始化注入队列与 worker
3. `stream_plugin_start_all(cfg)`：启动插件实例（含 async worker）并回调 `on_start`

这意味着：插件开始处理前，注入基础设施已就绪。

### 2.2 加载阶段做了什么

对每个 `stream_plugin.spX`：

- `dlopen(path, RTLD_NOW | RTLD_LOCAL)`
- `dlsym(..., "nano_plugin_init")`
- 调用 `nano_plugin_init()`，并通过线程局部变量 `tls_loading_inst` 让插件内的 `nano_register_`* 绑定到当前实例

加载成功的最低条件：

- `nano_plugin_init()` 返回 0
- 至少注册了 `on_msg`（`nano_register_msg`）

否则该实例加载失败，不进入运行态。

### 2.3 分发阶段（Broker -> Plugin）

分发入口是 `stream_plugin_pub_dispatch_from_work(work)`，会：

- 从 `work->pub_packet` 提取 topic/payload/qos/retain/client_id/timestamp
- 遍历全部插件实例
- 用 `topic_filter(spX.topic, publish_topic)` 判定匹配
- 命中后调用 `sp_dispatch(inst, &m)`

注意：这是**旁路分发**，插件不会直接改写当前发布给订阅者的原始消息。

### 2.4 sync / async 两种运行模式

每个插件实例由 `stream_plugin.spX.mode` 决定：

- `sync`：在分发路径直接调用 `on_msg`
- `async`：实例独享 ring queue + worker 线程，分发时只做入队（深拷贝 `topic/payload/client_id`）

`async` 适合重逻辑/高吞吐，避免阻塞 Broker 主路径。

### 2.5 队列满策略（`full_op`）

`stream_plugin.spX.full_op` 有两种：

- `drop`：队列满时丢弃新消息
- `block`：队列满时阻塞生产者等待队列可写

`queue_cap` 默认为 4096。

### 2.6 失败保护（fail-open）

每个插件实例维护错误计数：

- `total_calls` / `total_errors` / `consec_errors`
- 连续错误达到阈值（当前为 20）后自动 `disabled=true`

被自动禁用后，该实例不再接收分发，避免持续拖垮系统；Broker 主流程仍继续运行。

### 2.7 停止与卸载

- `stream_plugin_stop_all`：先停 async worker（尽量排空队列），再调 `on_stop`，并打印统计
- `stream_plugin_unload_all`：`dlclose` + 释放 runtime 结构

---

## 3. Inject 机制（`stream_inject.c`）

`stream_inject` 是插件发布接口的运行时后端，核心目标是：**让插件发布也走 Broker 既有处理链路，而不是绕过内部语义**。

### 3.1 启动时初始化

`stream_inject_start(cfg, broker_sock)` 会初始化：

- 全局注入队列（ring buffer）
- `worker_num` 个注入 worker 线程
- 一个发送 `ctx` + `aio`（用于向目标 pipe 发消息）
- 统计计数器（enqueued/dropped/processed/failed/send_failed）

默认配置：

- `enable=true`
- `queue_cap=4096`
- `worker_num=1`
- `full_op=drop`

### 3.2 插件调用发布 API 后发生什么

插件调用：

- `nano_mqtt_publish_async(topic, payload, len, qos, retain)`  
（`nano_mqtt_publish` 当前是它的同步包装，语义也是入队即返回）

执行流程：

1. 参数校验（topic/qos/payload）
2. 深拷贝为 `inject_item`
3. 入注入队列（满队列直接 drop）
4. 返回给插件调用方（不等待真正下发）

### 3.3 worker 如何“重走发布流程”

注入 worker 出队后会：

1. 构造内部 MQTT PUBLISH `nng_msg`
2. 组装 `nano_work`（`PROTO_STREAM_INJECT`）
3. 调 `handle_pub(...)` 生成目标投递信息
4. 编码并向匹配订阅者 pipe 发送
5. 清理 `pub_packet/msg_infos/msg/cparam` 等资源

也就是说，插件回灌消息不是“直接发 socket 原始字节”，而是复用了 Broker 的发布处理框架。

### 3.4 注入队列满策略

`stream_inject` 固定采用 `drop`：

- 队列满直接返回 `-EAGAIN` 并累计 dropped
- 不阻塞调用线程（避免把反压传回插件调用路径）

兼容说明：

- 旧配置里的 `stream_inject.full_op="block"` 会被降级为 `drop` 并打印 warning

---

## 4. Runtime 与 Inject 的配合关系

最常见业务闭环如下：

1. 外部设备上行 `can/...`
2. `stream_plugin.sp0.topic` 命中，插件 `on_msg` 处理
3. 插件调用 `nano_mqtt_publish_async()` 输出 `metrics/...` 或 `alert/...`
4. `stream_inject` worker 回灌到 Broker，最终投递给订阅者

这个闭环非常灵活，但有一个关键风险：**自激**。

如果插件输出 topic 仍命中自身 `topic filter`，插件会再次处理自己的输出。  
建议至少做一层隔离：

- 输入：`can/raw/#`
- 输出：`metrics/can/#`、`alert/can/#`

必要时再叠加来源标记（如 `client_id`、payload 字段）防止环路。

---

## 5. 时序图风格小节

### 5.1 启动时序（Broker 启动阶段）

```text
参与者:
  BrokerMain        = broker 主线程
  Runtime           = stream_plugin_runtime
  InjectRuntime     = stream_inject
  Plugin(spX)       = 单个 stream plugin 实例
  PluginWorker(spX) = spX 的 async worker（仅 async 模式）
  InjectWorker      = 注入 worker 线程池

BrokerMain -> Runtime: stream_plugin_load_all(cfg)
Runtime -> Plugin(spX): dlopen(path) + dlsym(nano_plugin_init)
Runtime -> Plugin(spX): nano_plugin_init()
Plugin(spX) -> Runtime: nano_register_msg/on_start/on_stop
Runtime --> BrokerMain: load 完成（失败实例跳过）

BrokerMain -> InjectRuntime: stream_inject_start(cfg, sock)
InjectRuntime -> InjectRuntime: 初始化 ring queue / ctx / aio / stats
InjectRuntime -> InjectWorker: 创建 worker_num 个线程
InjectRuntime --> BrokerMain: inject 就绪

BrokerMain -> Runtime: stream_plugin_start_all(cfg)
Runtime -> Runtime: sp_async_start(spX)（仅 async）
Runtime -> PluginWorker(spX): 创建插件 worker
Runtime -> Plugin(spX): on_start()（可选）
Runtime --> BrokerMain: start 完成
```

要点：

- 启动顺序是 `load -> inject_start -> plugin_start`。
- 先有 inject，再让插件开始处理，保证插件发布 API 调用时后端已就绪。
- 某个插件加载失败不阻塞其他实例启动。

### 5.2 消息流转时序（外部消息 -> 插件处理 -> 回灌）

```text
参与者:
  Publisher         = 外部发布端
  BrokerPipeline    = Broker 发布处理链路（handle_pub 等）
  Runtime           = stream_plugin_runtime
  Plugin(spX)       = 插件 on_msg
  InjectRuntime     = stream_inject API 入队侧
  InjectWorker      = stream_inject worker
  Subscribers       = MQTT 订阅者

Publisher -> BrokerPipeline: PUBLISH(topic=can/raw/..., payload=...)
BrokerPipeline -> BrokerPipeline: handle_pub(...) / retain / fanout 信息计算
BrokerPipeline -> Runtime: stream_plugin_pub_dispatch_from_work(work)
Runtime -> Runtime: topic_filter(spX.topic, publish_topic)

alt spX.mode = sync
  Runtime -> Plugin(spX): on_msg(&m) 直接调用
else spX.mode = async
  Runtime -> Runtime: 深拷贝消息并入 spX 队列
  Runtime -> Plugin(spX): 由 PluginWorker 异步出队后调用 on_msg(&m)
end

Plugin(spX) -> InjectRuntime: nano_mqtt_publish_async(metrics/..., ...)
InjectRuntime -> InjectRuntime: 入 inject 队列（drop）
InjectRuntime --> Plugin(spX): 返回（入队即返回）

InjectWorker -> BrokerPipeline: 出队后构造 nng_msg + nano_work
InjectWorker -> BrokerPipeline: handle_pub(...) 重新走发布链路
BrokerPipeline -> Subscribers: 投递回灌消息
```

要点：

- `stream_plugin` 是旁路消费，不改写当前原始投递结果。
- 插件输出通过 `stream_inject` 回到 Broker 主发布链路，语义更一致。
- 若插件输出 topic 命中自身 filter，会形成自激，需要通过 topic 分层规避。

---

## 6. 配置项对照（建议重点关注）

### 6.1 `stream_plugin.spX`

- `path`：插件 `.so` 绝对路径（必填）
- `topic`：输入 topic filter（必填）
- `name`：实例名（可选）
- `mode`：`sync` / `async`（默认 `async`）
- `queue_cap`：仅 async 有效，默认 4096
- `full_op`：`drop` / `block`，默认 `drop`

### 6.2 `stream_inject`

- `enable`：是否启用注入运行时（默认 true）
- `queue_cap`：注入队列容量（默认 4096）
- `worker_num`：注入 worker 数（默认 1）
- `full_op`：仅支持 `drop`（`block` 已弃用并自动降级）

---

## 7. 运行与排障建议

1. **优先 async**：除非逻辑极轻且确认无阻塞，否则插件都建议 `mode=async`。
2. **观察统计日志**：Broker 会周期打印 `stream_inject` 统计，结合 dropped/failed 调优队列和 worker。
3. **关注 auto-disabled**：若日志出现插件连续错误被禁用，优先检查插件输入容错。
4. **容量先粗后细**：初期可先放大 `queue_cap`，跑出峰值后再回收。
5. **严格分层 topic**：这是避免自激与递归风暴的第一手段。

---

## 8. 一个简化配置示例

```hocon
stream_plugin {
  sp0 {
    path      = "/abs/path/to/my_stream_plugin.so"
    topic     = "can/raw/#"
    name      = "can_pipeline"
    mode      = "async"
    queue_cap = 10000
    full_op   = "drop"
  }
}

stream_inject {
  enable     = true
  queue_cap  = 8192
  worker_num = 2
  full_op    = "drop"
}
```

---

## 9. 总结

`stream_plugin` 负责“消费与处理”，`stream_inject` 负责“回灌与投递”。  
前者关注插件生命周期、并发模型和失败隔离；后者关注注入吞吐、反压策略和投递成功率。把两边队列策略与 topic 规划设计好，插件体系就能在不改 Broker 主体的前提下稳定扩展业务能力。