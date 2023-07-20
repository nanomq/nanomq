# NanoMQ Broker

 The system configuration provides settings to control the number of task queue threads and the maximum number of concurrent tasks in the NanoMQ broker.

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

- `num_taskq_thread`: Specifies the number of task queue threads to use. The acceptable range is between 1 and 255. If the value is set to 0, the system automatically determines the number of threads.
- `max_taskq_thread`: Specifies the maximum number of task queue threads to use. The acceptable range is between 1 and 255. If the value is set to 0, the system automatically determines the maximum number of threads.
- `parallel`: Specifies the maximum number of outstanding requests that the system can handle at once. The acceptable range is between 1 and 255. If the value is set to 0, the system automatically determines the number of parallel tasks.

## Cache 

NanoMQ uses SQLite to implement the caching for MQTT data bridges. 

### Example Configuration

```hcl
sqlite {
    disk_cache_size = 102400  # Max message limitation for caching
    mounted_file_path="/tmp/" # Mounted file path 
    flush_mem_threshold = 100 # The threshold of flushing messages to flash
    resend_interval = 5000    # Resend interval (ms)
}
```

### Configuration Items

- `disk_cache_size`: Specifies the maximum number of messages that can be cached in the SQLite database. A value of 0 indicates no limit.
- `mounted_file_path`: Specifies the file path where the SQLite database file is mounted.
- `flush_mem_threshold`: Specifies the threshold for flushing messages to the SQLite database. When the number of messages reaches this threshold, they are flushed to the SQLite database.
- `resend_interval`: Specifies the interval, in milliseconds, for resending the messages after a failure is recovered. This is not related to the trigger for the resend operation.