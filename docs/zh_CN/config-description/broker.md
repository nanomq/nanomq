# NanoMQ 基础配置项

本节介绍 NanoMQ 的基础配置项，包括任务队列线程数、最大并发任务数、缓存。 

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

- `num_taskq_thread`：指定任务队列线程数；取值范围： 1 ～ 255 ；如设为 0，系统将自动确定线程的数量。
- `max_taskq_thread`：最大任务线程数。取值范围： 1 ～ 255 ；如设为 0，系统将自动确定最大任务线程数。
- `parallel`：系统一次可以处理的未完成请求的最大数量。取值范围： 1 ～ 255 ；如设为 0，系统将自动确定最大并行线程数。

## 缓存 

NanoMQ 使用 SQLite 实现 MQTT 数据桥的缓存。

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

- `disk_cache_size`：最大缓存消息数，缺省为 102400，可选值：
  - 0:  不生效
  - 1 - infinity
- `mounted_file_path`：数据库文件存储路径，缺省为 NanoMQ 的运行路径。
- `flush_mem_threshold`：内存缓存消息数阈值，达到阈值后再写入 SQLite 表中，取值范围：1-infinity，缺省为  `100`。
- `resend_interval`：故障恢复后的重发时间间隔，单位： ms；缺省为`5000`。注意: **该参数只对 Broker 有效** <!--@jaylin 这里不太理解-->