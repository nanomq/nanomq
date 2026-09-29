# NanoMQ Broker

 The system configuration provides settings to control the number of task queue threads, the maximum number of concurrent tasks, and cache settings in NanoMQ broker.

## Task Queue
### Example Configuration

```hcl
system {
    num_taskq_thread = 0  # Use a specified number of task queue threads
    max_taskq_thread = 0  # Use a specified maximum number of task queue threads
    parallel = 0          # Handle a specified maximum number of outstanding requests
}
```

### Configuration Item

- `num_taskq_thread`: Specifies the number of task queue threads to use. 
  - Acceptable range: uint32, Recommend 1 - Core * 2. If the value is set to 0, the system automatically determines the number of threads.
- `max_taskq_thread`: Specifies the maximum number of task queue threads to use.
  - Acceptable range: uint32, Recommend 1 - Core * 2. If the value is set to 0, the system automatically determines the maximum number of threads.
- `parallel`: Specifies the maximum number of outstanding requests that the system can handle at once.
  - Acceptable range: uint32, Recommend Core * 4. No upper limit, however, too much parallel context actually hurt performance. If the value is set to 0, the system automatically determines the number of parallel tasks.

## Cache 

NanoMQ uses SQLite to cache MQTT data bridge.

### Example Configuration

```hcl
sqlite {
    disk_cache_size = 102400       # Max number of messages for caching
    mounted_file_path="/tmp/"      # Mounted file path 
    flush_mem_threshold = 100      # The threshold number of flushing messages to flash
    retain_flush_threshold = 1000  # Batch trigger for retained messages
    flush_interval = 5000          # Longest a buffered write may wait (ms)
    resend_interval = 5000         # Resend interval (ms)
}
```

### Configuration Items

- `disk_cache_size`: Specifies the maximum number of messages that can be cached in the SQLite database.
  - Value range: 1 - infinity. If the value is set to 0, then cache for messages is ineffecitve.
  - default: 102400.
- `mounted_file_path`: Specifies the file path where SQLite database file is mounted.
  -  default: `nanomq running path`
- `flush_mem_threshold`: Specifies the threshold for flushing messages to the SQLite database. When the number of messages reaches the threshold, they will be flushed to the SQLite database. Applies to the client and bridge offline cache; the broker's retained-message cache is governed by `retain_flush_threshold` and `flush_interval` instead.
  -  Value range: 1 - infinity
  -  default: 100.
- `retain_flush_threshold`: Trigger for the retained-message write-behind batch: the batch is committed once this many entries are pending. This is a **trigger, not a cap** — set at or below the number of topics being written concurrently, it fires in the middle of a flush window and most of the saving is lost. Keep it well above the number of concurrently published retained topics, so that `flush_interval` normally decides when the batch is committed.
  -  Value range: 0 - infinity. Setting it to 0 disables batching and writes retained messages synchronously.
  -  default: 1000.
- `flush_interval`: The longest a buffered retained-message write may wait before it is committed, in milliseconds. Whichever of `retain_flush_threshold` and `flush_interval` is reached first triggers the flush. This is a second-scale setting: below roughly 1000 the flush fires often enough that it is barely cheaper than writing each message synchronously.
  -  Value range: 1000 - infinity
  -  default: 5000.
- `resend_interval`: (Currently not implemented) Specifies the interval, in milliseconds, for resending the messages after a failure is recovered. This is unrelated to the trigger for the resend operation. Note:  **Only work for the NanoMQ broker to resend cached messages to local client, not for bridging connections**.
  -  default: 5000. 

Retained messages are therefore no longer written to disk the instant they are published: a retained write becomes durable when its batch is committed, or when the broker exits normally — the pending batch is committed on the way out. Only an abrupt stop (a kill or a crash) loses up to `retain_flush_threshold` entries or `flush_interval` milliseconds of retained writes, whichever is smaller. A retained message that is superseded or cleared before the batch is committed never reaches disk at all.

## Preset Sessions

With preset sessions, You can publish messages to a void client, that is not connected yet. QoS messages will be cached just like session keeping
However, the new coming client still need to subscribe to the target topics by itself.

### Example Configuration

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

Each section is a preset session of a non-connected client, specifying the subscribed topics, QoS, and client ID. Once the (real) client is connected, the preset session will be taken over, all the following works are governed by MQTT persist session then.

### Configuration Items

- `clientid`：the client ID of preset session.
  - must to have, UTF-8 String.
- `remote_topic`：Subscribed topic of preset session client.
  - As same as normal topics, QoS messages went into these topics will be cached.
- `qos`：Corresponding QOS of subscription
  - must be 1 or 2.
