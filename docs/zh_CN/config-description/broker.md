# NanoMQ 基础配置项

本节介绍 NanoMQ 的基础配置项，包括任务队列和缓存。 

## 任务队列
### 配置示例

```hcl
system {
    num_taskq_thread = 0  # 任务队列线程数
    max_taskq_thread = 0  # 任务队列最大线程数
    parallel = 0          # 最大并行进程数
}
```

### 配置项

- `num_taskq_thread`：指定任务队列线程数。
  - 取值范围：1 ～ 255。如设为 0，系统将自动确定线程的数量。
- `max_taskq_thread`：最大任务线程数。
  - 取值范围：1 ～ 255。如设为 0，系统将自动确定最大任务线程数。
- `parallel`：系统一次性可以处理的未完成请求的数量。
  - 取值范围：1 ～ 255。如设为 0，系统将自动确定最大并行线程数。

## 缓存 

NanoMQ 使用 SQLite 实现 MQTT 数据桥的缓存。开启NanoMQ的缓存，可以实现`retain`消息的持久化。

### 配置示例

```hcl
sqlite {
    disk_cache_size = 102400  # 最大缓存消息数
    mounted_file_path="/tmp/" # 数据库文件存储路径
    flush_mem_threshold = 100 # 内存缓存消息数阈值
    resend_interval = 5000    # 故障恢复后的重发时间间隔 (ms)
}
```

### 配置项

- `disk_cache_size`：最大缓存消息数。
  - 取值范围 1 ～ ∞，如设为0，则不生效。
  - 缺省值：102400。
- `mounted_file_path`：数据库文件存储路径。
  - 缺省值：NanoMQ 的运行路径。
- `flush_mem_threshold`：内存缓存消息数阈值，达到阈值后消息将会写入到 SQLite 表中。
  - 取值范围：1 ～ ∞ 。
  - 缺省值：100。
- `resend_interval`：故障恢复后的重发时间间隔，单位：ms。注意: **该参数只对 Broker 有效**
  - 缺省值：5000。