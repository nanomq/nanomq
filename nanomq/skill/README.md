# NanoMQ Skill Library 说明

`nanomq/skill` 是给 Stream Plugin 使用的“独立能力库”，提供窗口聚合、批处理、时间工具和 DBC 预留接口。

它的设计目标是：

- 可直接和插件源码一起编译成 `.so`，不依赖 broker 导出符号。
- 提供通用算法能力，减少每个插件重复造轮子。
- 与 `nano_sdk.h` 形成分层：`nano_sdk` 偏 broker 交互，`nano_skill` 偏本地处理能力。

## 目录结构

- `include/nano_skill.h`：对外头文件（API 入口）
- `src/nano_skill_time.c`：单调时钟毫秒接口
- `src/nano_skill_window.c`：数值 tumbling window 聚合
- `src/nano_skill_batch.c`：按 count/bytes/time 触发 flush 的批处理
- `src/nano_skill_dbc_stub.c`：DBC 预留接口（当前为 stub）
- `CMakeLists.txt`：构建 `nanomq_skill` 静态库

## 能力概览

### 1) time

- `nano_skill_time_ms()`：返回单调时钟毫秒值（适合计算时间间隔，不用于绝对墙钟时间）。

### 2) window（tumbling）

- 句柄：`nano_skill_window *`
- 常用流程：
  1. `nano_skill_window_tumbling_ms(window_ms)`
  2. `nano_skill_window_push(...)`
  3. `nano_skill_window_ready(...)` 判断是否到窗口边界
  4. 读取 `avg/max/min/count`
  5. `nano_skill_window_reset(...)` 或复用（实现里在 ready 后下一次 push 会自动 reset）
  6. `nano_skill_window_free(...)`

### 3) batch

- 句柄：`nano_skill_batch *`
- 触发条件：`max_count` / `max_total_bytes` / `flush_ms` 至少一个非 0
- `nano_skill_batch_push` 会 deep-copy 数据，调用返回后可释放调用方 buffer
- `on_flush` 回调在 batch 内部工作线程执行
- `nano_skill_batch_close` 会停止线程并释放资源

### 4) dbc（预留）

当前默认实现是 stub：

- `nano_skill_dbc_load(...)` 返回 `NULL`
- `nano_skill_dbc_decode(...)` 返回 `-ENOSYS`

后续可替换为真实 DBC backend，不影响调用侧接口形态。

## 线程与并发语义

- `window`：单句柄不保证并发安全，建议单线程使用。
- `batch`：
  - push/flush/close 通过内部锁与条件变量协调；
  - flush 回调在 worker 线程执行，回调内请避免耗时阻塞太久；
  - 回调如需访问外部共享状态，请自行加锁。

## 错误码约定（常见）

- `0`：成功
- `-EINVAL`：参数非法
- `-ENOMEM`：内存不足
- `-ESHUTDOWN`：batch 已关闭或正在停止
- `-ENOSYS`：接口未实现（如当前 DBC stub）

## 构建方式

### 方式 A：作为静态库构建

`nanomq/skill/CMakeLists.txt` 默认构建：

- 目标：`nanomq_skill`（STATIC）
- 依赖：`Threads::Threads`

可在 CMake 工程中通过 `add_subdirectory(nanomq/skill)` 后链接使用。

### 方式 B：直接把源码编入插件（推荐给独立 .so）

示例（与模板目录做法一致）：

```bash
gcc -O2 -Wall -Wextra -fPIC -shared \
  -I<NanoMQ>/nanomq/include -I<NanoMQ>/nanomq/skill/include \
  my_plugin.c \
  <NanoMQ>/nanomq/skill/src/nano_skill_time.c \
  <NanoMQ>/nanomq/skill/src/nano_skill_window.c \
  <NanoMQ>/nanomq/skill/src/nano_skill_batch.c \
  <NanoMQ>/nanomq/skill/src/nano_skill_dbc_stub.c \
  -lpthread \
  -o my_plugin.so
```

## 最小使用片段

```c
static nano_skill_window *g_win;

void on_start(void) {
    g_win = nano_skill_window_tumbling_ms(5000);
}

int on_msg(const nano_msg *m) {
    if (m && m->payload && m->payload_len >= 1 && g_win) {
        double v = (double)((const uint8_t *)m->payload)[0];
        nano_skill_window_push(g_win, m->ts_ms, v);
        if (nano_skill_window_ready(g_win)) {
            double avg = nano_skill_window_avg(g_win);
            (void)avg;
            nano_skill_window_reset(g_win);
        }
    }
    return 0;
}
```

## 与 `nano_sdk` 的边界

- `nano_skill`：纯本地处理能力（窗口、批处理、工具函数）
- `nano_sdk`：与 broker/runtime 交互（注册回调、发布、日志、文件追加等）

通常插件会同时包含二者：

- 用 `nano_sdk` 接 broker 事件与输出能力；
- 用 `nano_skill` 做中间处理和聚合。
