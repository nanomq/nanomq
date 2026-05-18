# AI 生成 Stream Plugin 手册

本手册用于“给 AI 一份可直接执行的说明”，让 AI 稳定输出：

- 一个可编译的插件 `.c` 文件
- 一条可执行编译命令（生成 `.so`）
- 一段 `nanomq.conf` 片段
- 一组最小验证命令

---

## 1. 先给 AI 的固定上下文

每次提需求时，至少同时提供这 2 份材料：

1. `nanomq/include/nano_sdk.h`（接口契约）
2. 本文档（生成约束 + 提示模板）

如使用窗口/批处理/DBC，可额外说明：

- `nanomq/skill/include/nano_skill.h`
- `nanomq/skill/src/*.c` 可直接编进插件

推荐再补 1 份模板范式（稳定性更高）：

- `nanomq/plugin/templates/skeleton.c`

---

## 2. AI 必须遵守的硬约束

- 插件唯一入口：`int nano_plugin_init(void)`
- 只允许使用 SDK 暴露接口（`nano_sdk.h`）
- 在 `nano_plugin_init` 中注册：
  - `nano_register_msg(on_msg)`
  - `nano_register_start(on_start)`（可选）
  - `nano_register_stop(on_stop)`（可选）
- 禁止使用未在 `nano_sdk.h` 声明的内部符号
- `on_msg` 必须短耗时，禁止 sleep/慢 I/O/长阻塞
- 输出 topic 与输入 topic 必须分层，避免自激

---

## 3. 推荐实现模式（让 AI 选 1~3 个组合）

- **模式 A：规则告警**
  - 解析 payload -> 阈值判断 -> 发布 `alert/...`
- **模式 B：窗口指标**
  - tumbling window（如 5s）-> 输出 avg/max/min/count 到 `metrics/...`
- **模式 C：批量落盘**
  - 每 N 条或每 T ms flush -> 写 `jsonl`/`csv`
- **模式 D：组合**
  - A + B + C 同时启用，但输出 topic 必须分层

---

## 4. 可直接复制给 AI 的请求模板

把下面模板复制给 AI，只改尖括号部分：

```text
你要为 NanoMQ 生成一个 Stream Plugin（.so），请严格遵守：
1) 入口必须是 int nano_plugin_init(void)
2) 只能使用 nano_sdk.h 暴露的 nano_* 接口
3) 代码包含 on_msg / on_start(可选) / on_stop(可选)
4) on_msg 不允许阻塞，重 I/O 使用 batch flush
5) 输出 topic 与输入 topic 分层，避免自激

需求如下：
- 输入 topic filter: <INPUT_TOPIC_FILTER>
- payload 格式: <PAYLOAD_FORMAT>
- 处理规则: <RULES>
- 窗口配置(可选): <WINDOW>
- 批处理配置(可选): <BATCH>
- 输出 topic 规划: <OUTPUT_TOPICS>
- 是否落盘及格式: <FILE_OUTPUT>

请按顺序输出：
1) 完整 C 源码（单文件）
2) gcc 编译命令（必须含 -fPIC -shared，输出 my_stream_plugin.so）
3) nanomq.conf 配置片段（stream_plugin + 需要时 stream_inject）
4) 最小验证命令（nanomq_cli sub/pub + 落盘验证）
```

---

## 5. 编译命令标准写法（可给 AI 参考）

```bash
gcc -O2 -Wall -Wextra -fPIC -shared \
  -I"$REPO/nanomq/include" \
  -I"$REPO/nanomq/skill/include" \
  my_stream_plugin.c \
  "$REPO/nanomq/skill/src/nano_skill_time.c" \
  "$REPO/nanomq/skill/src/nano_skill_window.c" \
  "$REPO/nanomq/skill/src/nano_skill_batch.c" \
  "$REPO/nanomq/skill/src/nano_skill_dbc_stub.c" \
  -lpthread \
  -o my_stream_plugin.so
```

---

## 6. 交付验收清单

让 AI 自检并输出以下结论：

- 能编译：无未定义符号、能生成 `.so`
- 能加载：NanoMQ 启动日志看到插件加载成功
- 能验证：订阅端可看到输出 topic 消息
- 有落盘时：目标文件存在且有内容

---

## 7. 与模板目录联动的推荐流程

1) 先在 `nanomq/plugin/templates/skeleton.c` 上改业务逻辑（或让 AI 直接生成同结构源码）  
2) 在 `nanomq/plugin/templates` 执行 `make NMQ_INCLUDE="$REPO/nanomq/include"`  
3) 默认得到 `my_stream_plugin.so`，按 `quick-demo.md` 的配置方式加载验证
