# Batch Resend for QoS Messages

## Overview

NanoMQ introduces a **batch resend** feature for MQTT QoS 1 (QoS-At-Most-Once) and QoS 2 (QoS-Exactly-Once) messages that are cached in the local nano_qos_db. This feature optimizes message delivery by allowing multiple cached messages to be resent efficiently when the broker detects network issues or client disconnections.

## Background

MQTT QoS levels guarantee reliable message delivery:
- **QoS 0**: At most once - Best effort, no acknowledgment required
- **QoS 1**: At least once - Requires PUBACK confirmation
- **QoS 2**: Exactly once - Requires PUBLISH/PUBREC/PUBREL/PUBCOMP handshake

When a QoS message fails to deliver (due to network issues, client disconnects, etc.), NanoMQ caches the message in `nano_qos_db` and retries delivery. The traditional approach resends messages one by one when individual ACKs are not received, which can be inefficient under high load or frequent disconnections.

## How Batch Resend Works

### Traditional Single-Message Retry (Before)

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Client A   │   │    Broker   │   │  Client B   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       │ QoS1 PUBLISH    │                 │
       │────────────────►│                 │
       │                 │ Cache in DB      │
       │                 │◄─────────────────│
       │                 │ PUBACK           │
       │                 │──────────────────│
```

When individual messages need retry, each message is processed separately through the QoS pipeline:
1. Timer triggers per-pipe retry (based on `qos_duration`)
2. Message fetched from `nano_qos_db` one at a time
3. Sent to client with duplicate flag set

### Batch Resend Mode (After)

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Client A   │   │    Broker   │   │  Client B   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       │ QoS1 PUBLISH    │                 │
       │────────────────►│                 │
       │                 │ Cache in DB      │
       │                 │◄─────────────────│
       │                 │ PUBACK           │
       │                 │──────────────────│

┌─────────────────────────────────────────────────────┐
│                  Batch Resend                        │
├─────────────────────────────────────────────────────┤
│ When batch_resend = true and PUBACK received:        │
│ 1. Broker queries nano_qos_db for ALL pending messages│
│    (get_one() iterates through cache)                │
│ 2. All eligible messages are queued for resend         │
│ 3. Messages are resent in a batch when pipe is free     │
│ 4. Each message gets its own packet ID and DUP flag     │
└─────────────────────────────────────────────────────┘
```

### Key Algorithm Components

1. **Configuration Check**: Batch resend only activates when `batch_resend = true` in the broker configuration

2. **Trigger Points**: 
   - PUBACK/PUBCOMP received (QoS 1/2 acknowledgment)
   - QoS timer interval expires (`qos_duration * 1000ms`)

3. **Message Retrieval** (`tcptran_pipe_getopt`):
   ```c
   // Iterate through all cached messages
   while (1) {
       msg = nni_qos_db_get_one(is_sqlite, qos_db, pipe_id, &pid);
       
       if (msg == NULL) break;  // No more messages
       
       // Check expiry conditions:
       // 1. Message expired by MESSAGE_EXPIRY_INTERVAL property
       // 2. Retry timeout exceeded (qos_duration * 1250ms)
       
       if (!expired && !timeout_exceeded) {
           req->msg = msg;
           return 0;  // Return first eligible message
       }
   }
   ```

4. **Duplicate Flag**: All resent messages have `DUPLICATE` flag set via `nano_msg_set_dup()`

5. **Pipe Synchronization**: Only sends when pipe is not busy (`!p->busy`) to avoid contention

6. **Message Cleanup**: 
   - Expired messages are removed from cache
   - Successfully acknowledged messages are automatically cleaned up by the QoS DB

## Configuration

### Enabling Batch Resend

Add or modify in your broker configuration file:

```hocon
listeners.tcp {
    bind = "0.0.0.0:1883"
    
    mqtt {
        # Control QoS message resend behavior
        batch_resend = true
        
        # Retry interval for individual QoS messages (seconds)
        qos_duration = 10
    }
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `batch_resend` | boolean | false | Enable batch resend mode. When true, multiple cached QoS messages are resent together instead of individually. |
| `qos_duration` | integer (seconds) | 10 | The retry interval for individual QoS messages in each pipe. Also controls the timer interval for the QoS cache cleanup loop. |

### Hot Update Support

Both parameters support **hot update** - you can change them without restarting NanoMQ:

```bash
# Example using IPC command line
echo "set mqtt.batch_resend=true" > /var/run/nanomq/ipc.sock
echo "set mqtt.qos_duration=20" > /var/run/nanomq/ipc.sock
```

## When Batch Resend Is Useful

### Scenarios Where Batch Resend Helps

1. **High Message Rate**: When many QoS messages are in-flight simultaneously, batch resend reduces the overhead of multiple timer triggers and individual lookups.

2. **Frequent Disconnections**: In unstable network conditions where clients disconnect frequently, batch resend can clear multiple stale cached messages more efficiently.

3. **Resource-Constrained Systems**: Reduces CPU usage by batching operations instead of processing each message separately through the QoS pipeline.

4. **Bridge Scenarios**: Particularly useful when bridging to other brokers or systems that may have intermittent connectivity.

### Trade-offs and Considerations

| Aspect | Single Message Retry (batch_resend=false) | Batch Resend (batch_resend=true) |
|--------|-------------------------------------------|----------------------------------|
| Memory Usage | Lower (messages processed individually) | Higher (multiple messages held in pipeline) |
| CPU Overhead | Higher per message (timer + lookup per msg) | Lower overall (batched operations) |
| Latency | Predictable, immediate retry | Slight delay waiting for batch to assemble |
| Network Efficiency | May send bursts of individual PUBLISH packets | More efficient packet batching possible |
| Complexity | Simpler failure isolation | More complex state tracking |

## Implementation Details

### Where It's Implemented

The batch resend feature is implemented in the MQTT broker transport layer:

1. **`nng/src/sp/protocol/mqtt/nmq_mqtt.c`**: 
   - CMD_PUBACK handler (line 1215) - Triggers batch resend on PUBACK
   - Uses `batch_resend` flag to determine if batch mode is active

2. **`nng/src/sp/transport/mqtt/broker_tcp.c`**:
   - `tcptran_pipe_getopt()` function (lines 1630-1704) - Retrieves messages from QoS DB for resend
   - Implements the expiry and timeout logic for batch message selection

3. **Message Storage** (`nng/src/sp/transport/mqtt/broker_tcp.c`):
   - Lines 1082-1110: Messages are stored in `nano_qos_db` keyed by (pipe_id, packet_id)
   - Duplicate detection and cache management at line 1093-1110

### Data Structures

```c
// Request structure for QoS message retrieval
typedef struct {
    uint16_t packet_id;
    nni_msg *msg;
} nmq_req;
```

### Cache Management

The `nano_qos_db` uses SQLite (when enabled) or in-memory hash tables:
- **SQLite mode**: Messages stored as rows with pipe_id and packet_id index
- **Hash table mode**: In-memory lookup for faster access
- Maximum cache size controlled by `qos_duration * 1250ms` timeout

### Message Expiry Logic

Messages can be removed from the cache in two ways:

1. **MESSAGE_EXPIRY_INTERVAL Property** (MQTT v5):
   - If message has this property, check if `(current_time > publish_time + expiry_interval)`
   - Expired messages are automatically deleted

2. **Retry Timeout**:
   - After `qos_duration * 1250ms` without ACK, message is returned for resend attempt
   - This timeout prevents indefinite caching

## Usage Examples

### Basic Configuration

```hocon
mqtt {
    batch_resend = true
    qos_duration = 15
}
```

This configuration enables batch resend with a 15-second retry interval.

### With SQLite Persistence

For persistent message storage across broker restarts:

```hocon
mqtt {
    sqlite {
        enable = true
        user_path = "/var/lib/nanomq"
        db_name = "mqtt.db"
    }
    
    batch_resend = true
    qos_duration = 10
}
```

### Bridge Mode with Batch Resend

When bridging to another MQTT broker:

```hocon
bridges.bridge_to_another_broker {
    remote_url = "tcp://broker.example.com:1883"
    
    mqtt {
        batch_resend = true  # Efficiently handle bridge disconnections
        qos_duration = 5     # Faster retry for bridged connections
    }
}
```

## Monitoring and Debugging

### Log Messages

When batch resend is active, you'll see logs like:

```
INFO: resending qos msg id X to pipe Y
```

This indicates a QoS message is being resent from the cache.

### Performance Metrics

To monitor batch resend effectiveness:

1. **Check `nano_qos_db` size**: Should decrease as messages are acknowledged or expire
2. **Monitor retry rate**: Lower retry rate with batch_resend=true under stable conditions
3. **CPU utilization**: May see slight CPU increase during message storms, but better overall efficiency

### Troubleshooting

If you don't see expected behavior:

1. **Verify configuration**: `batch_resend` must be true for the effect to manifest
2. **Check pipe busy state**: Messages won't resend if the pipe is currently processing other work
3. **Review expiry settings**: MESSAGE_EXPIRY_INTERVAL may cause messages to expire before retry
4. **Log level**: Set log_level=debug for detailed QoS cache operations

## Related Features

- **[QoS Duration](https://docs.nanomq.io/)**: Controls the timing of message retries and cache cleanup
- **[SQLite Persistence](https://docs.nanomq.io/)**: Enables message storage across broker restarts
- **[Message Expiry Property](https://docs.nanomq.io/)**: MQTT v5 property for per-message TTL

## Future Enhancements

Potential future improvements could include:

1. **Configurable batch size**: Allow specifying maximum messages per batch instead of all-at-once
2. **Priority queuing**: Process higher-priority cached messages first in a batch
3. **Adaptive batching**: Dynamically adjust batch behavior based on network conditions
4. **Batch statistics**: Expose metrics about batch operations for observability

## References

- [MQTT QoS Specification](https://docs.oasis-open.org/mqtt/mqtt/v1.2/os/mqtt-v1.2-os.html#_Toc39875206)
- [NanoMQ MQTT Broker Documentation](./index.md)
- `nng/src/supplemental/mqtt/mqtt_qos_db_api.h` (NNG QoS database API)
