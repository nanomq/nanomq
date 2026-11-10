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
    disk_cache_size = 102400       # 最大缓存消息数
    mounted_file_path="/tmp/"      # 数据库文件存储路径
    flush_mem_threshold = 100      # 内存缓存消息数阈值
    retain_flush_threshold = 1000  # retain 消息批量写入的触发阈值
    flush_interval = 5000          # 缓冲中的 retain 消息最长等待时间 (ms)
    resend_interval = 5000         # 故障恢复后的重发时间间隔 (ms)
}
```

### 配置项

- `disk_cache_size`：最大缓存消息数。作用于 QoS 消息存储以及客户端与桥接的离线缓存；**不约束** retain 表——retain 表每个 topic 保留一行，直到该 topic 被清除或消息过期。
  - 取值范围 1 ～ ∞，如设为0，则不生效。
  - 缺省值：102400。
- `mounted_file_path`：数据库文件存储路径。
  - 缺省值：NanoMQ 的运行路径。
- `flush_mem_threshold`：内存缓存消息数阈值，达到阈值后消息将会写入到 SQLite 表中。该参数作用于客户端与桥接的离线消息缓存；Broker 的 retain 消息缓存由 `retain_flush_threshold` 与 `flush_interval` 控制。
  - 取值范围：1 ～ ∞ 。
  - 缺省值：100。
- `retain_flush_threshold`：retain 消息批量写入的触发阈值，待写条目达到该数量即提交一批。这是**触发器而非上限**——若把它设成小于等于并发写入的 topic 数，它会在一个 flush 窗口中途触发，收益会大幅流失。应保持明显大于并发发布 retain 的 topic 数，让 `flush_interval` 决定提交时机。
  - 取值范围：0 ～ ∞，设为 0 则关闭批量写入，retain 消息逐条同步落盘。
  - 缺省值：1000。
- `flush_interval`：缓冲区中的 retain 消息最长等待多久后被提交，单位：ms。`retain_flush_threshold` 与 `flush_interval` 谁先满足就触发 flush。该参数是秒级的：低于约 1000 时 flush 触发过于频繁，相对逐条同步写几乎没有收益。
  - 取值范围：1000 ～ ∞ 。
  - 缺省值：5000。
- `resend_interval`：故障恢复后的重发时间间隔，单位：ms。注意: **该参数只对 Broker 有效**
  - 缺省值：5000。

因此 retain 消息不再在发布的瞬间落盘：一批提交后该写入才算持久化，正常退出时残留的批次也会被提交。只有被强杀或崩溃才会丢失仍在缓冲区中的 retain 写入；其损失受两个提交触发条件限制——最多 `retain_flush_threshold` 条，且最多 `flush_interval` 毫秒内产生的写入。若一条 retain 消息在提交前就被新值取代或被清除，则完全不会写入磁盘。

`retain_flush_threshold` 与 `flush_interval` 在配置 reload 时会重新读取并作用于运行中的 broker；打开或关闭批处理（即 `retain_flush_threshold = 0` 的情况）需要重启。

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
