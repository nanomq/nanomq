# Stream Plugin 介绍与实现原理

本目录已精简为 4 份文档，分别覆盖：

1. **介绍与实现原理**（本文）
2. **Runtime 与 Inject 机制详解**：`runtime-inject-mechanism.md`
3. **快速 Demo 手册**：`quick-demo.md`
4. **AI 生成插件手册**：`ai-plugin-guide.md`

---

## 1. Stream Plugin 是什么

Stream Plugin 是 NanoMQ 的动态插件机制：你可以把业务逻辑编译为 `.so`，在 broker 启动时按配置加载，让插件旁路处理消息（解析、过滤、聚合、告警、落盘、回灌），而不改 broker 主体代码。

典型用途：

- 车载 CAN 数据实时规则告警
- 5s/10s 窗口统计指标输出
- 高频消息批量落盘审计
- 插件内计算后再发布到新 topic

---

## 2. 运行时架构（当前实现）

### 2.1 插件侧

- 固定入口：`int nano_plugin_init(void)`
- 在入口注册回调：
  - `nano_register_msg(on_msg)`
  - `nano_register_start(on_start)`（可选）
  - `nano_register_stop(on_stop)`（可选）
- 与 broker 交互只通过 SDK：`nanomq/include/nano_sdk.h`

### 2.2 Broker 侧

- `stream_plugin_runtime.c`：按配置 `dlopen` / 启动 / 停止 / 分发
- `pub_handler.c`：在主 PUBLISH 流程做 stream plugin 旁路分发
- `stream_inject.c`：承接 `nano_mqtt_publish_async()` 的内部注入队列

---

## 3. 处理模型与关键语义

### 3.1 两种模式

- `sync`：`on_msg` 在分发路径直接执行，延迟低，但不能做重活
- `async`：每插件实例独立队列 + worker 异步执行，吞吐更稳，推荐默认使用

### 3.2 旁路语义

- 插件可以监听 broker 已处理的消息
- 插件不会改写原消息给订阅者的投递
- 插件如需输出结果，应发布到新 topic 或落盘

### 3.3 自激规避

插件输出若再次匹配输入 filter，会触发插件再次处理。建议：

- 输入与输出 topic 分层（例如 `can/#` -> `alert/can/...`、`metrics/can/...`）
- 必要时加来源标记或 `client_id` 防护

---

## 4. 生命周期建议

- `on_start`：创建窗口、batch、缓存、DBC 等资源
- `on_msg`：只做短耗时逻辑，避免阻塞 I/O
- `on_stop`：flush 并释放资源，确保退出干净

---

## 5. 你应该先看哪篇文档

- 想看 runtime / inject 调度细节：看 `runtime-inject-mechanism.md`
- 想先跑通效果：看 `quick-demo.md`
- 想让 AI 直接产出可编译插件：看 `ai-plugin-guide.md`

---

## 6. 与 `nanomq/plugin/templates` 的关系

`nanomq/plugin/templates` 已按“最小模板”收敛，只保留：

- `skeleton.c`（最小插件骨架）
- `Makefile`（默认产出 `my_stream_plugin.so`）
- `README.md`（模板目录自述）

文档侧统一约定：

- 需要最快落地时，先走 `templates/skeleton.c` + `make`
- 需要完整业务范式时，再参考 `nanomq/plugin/can_pipeline_sample.c`