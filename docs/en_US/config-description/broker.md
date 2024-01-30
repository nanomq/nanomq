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
  - Acceptable range: 1 - 255. If the value is set to 0, the system automatically determines the number of threads.
- `max_taskq_thread`: Specifies the maximum number of task queue threads to use.
  - Acceptable range: 1 - 255. If the value is set to 0, the system automatically determines the maximum number of threads.
- `parallel`: Specifies the maximum number of outstanding requests that the system can handle at once.
  - Acceptable range: 1 - 255. If the value is set to 0, the system automatically determines the number of parallel tasks.

## Cache 

NanoMQ uses SQLite to cache MQTT data bridge.

### Example Configuration

```hcl
sqlite {
    disk_cache_size = 102400  # Max number of messages for caching
    mounted_file_path="/tmp/" # Mounted file path 
    flush_mem_threshold = 100 # The threshold number of flushing messages to flash
    resend_interval = 5000    # Resend interval (ms)
}
```

### Configuration Items

- `disk_cache_size`: Specifies the maximum number of messages that can be cached in the SQLite database.
  - Value range: 1 - infinity. If the value is set to 0, then cache for messages is ineffecitve.
  - default: 102400.
- `mounted_file_path`: Specifies the file path where SQLite database file is mounted.
  -  default: `nanomq running path`
- `flush_mem_threshold`: Specifies the threshold for flushing messages to the SQLite database. When the number of messages reaches the threshold, they will be flushed to the SQLite database.
  -  Value range: 1 - infinity
  -  default: 100.
- `resend_interval`: (Currently not implemented) Specifies the interval, in milliseconds, for resending the messages after a failure is recovered. This is unrelated to the trigger for the resend operation. Note:  **Only work for the NanoMQ broker to resend cached messages to local client, not for bridging connections**.
  -  default: 5000. 
