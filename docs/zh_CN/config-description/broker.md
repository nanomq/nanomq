# NanoMQ 基础配置项

本节介绍 NanoMQ 的基础配置项，包括任务队列和缓存。 

## MQTT Actor 配置
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
  - 取值范围：uint32, 1 - Core * 2。如设为 0，系统将自动确定线程的数量。
- `max_taskq_thread`：最大任务线程数。
  - 取值范围：uint32, 1 - Core * 2。如设为 0，系统将自动确定最大任务线程数。
- `parallel`：系统一次性可以处理的未完成请求的数量。
  - 取值范围：uint32, Core * 4。如设为 0，系统将自动确定最大并行线程数。

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

## 预设会话配置
使用预设会话，您可以向尚未连接的无效客户端发布消息。QoS 1/2 消息将像会话保持一样被缓存。但是，新的客户端仍然需要自行订阅目标主题。

### 配置示例

```hcl
preset.session.1 {
	clientid = "example"
	topic = [
		{
			qos = 2
			remote_topic = "msg1/#"
		},
		{
			qos = 1
			remote_topic = "msg2/#"
		}
	]
}
preset.session.2 {
    ......
}
```

每个部分都是一个非连接客户端的预设会话，指定订阅的主题、QoS 和客户端 ID。一旦（真实）客户端连接成功，预设会话将被接管，之后的所有工作都将由 MQTT 持久会话管理。

### 配置项

- `clientid`：预设会话的客户端 ID。
  - 必须有, 必须为 UTF-8 字符串。
- `remote_topic`：预设会话客户端订阅的主题。
  - 与普通主题一样，进入这些主题的 QoS 消息将被缓存。
- `qos`：订阅对应的 QOS
  - 必须为 1 或 2。