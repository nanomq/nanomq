# Batch Resend Quick Reference

## What is Batch Resend?

Batch resend is an optimization feature that allows NanoMQ to efficiently resend multiple cached QoS 1 and QoS 2 messages at once, rather than resending them individually. This improves performance especially under high message rates or frequent network disconnections.

## How to Enable

```hocon
listeners.tcp {
    bind = "0.0.0.0:1883"
    
    mqtt {
        batch_resend = true  # Enable batch resend mode
        qos_duration = 10    # Retry interval in seconds (default: 10)
    }
}
```

## Key Points

| Feature | Description |
|---------|-------------|
| **When it works** | Only when `batch_resend = true` and PUBACK/PUBCOMP received for QoS messages |
| **Message types** | QoS 1 (At least once) and QoS 2 (Exactly once) only |
| **Cache location** | nano_qos_db (SQLite or in-memory hash table) |
| **Hot updatable** | Yes - can be enabled/disabled without restart using IPC commands |

## Configuration Options

### `batch_resend` (boolean)
- Default: false
- Set to `true` to enable batch resend mode
- When true, multiple cached QoS messages are resent together in batches

### `qos_duration` (integer seconds)
- Default: 10
- Controls retry interval and timer loop frequency
- Messages timeout after `qos_duration * 1250ms` without acknowledgment

## Use Cases

**Enable batch_resend when:**
- You have high message throughput rates
- Your network is unstable with frequent disconnections  
- You're running on resource-constrained hardware (edge devices)
- Bridging to other brokers or systems with intermittent connectivity

**Keep disabled when:**
- Predictable, stable network conditions
- Messages must be resent immediately upon failure
- Memory usage is a primary concern

## Hot Update Commands

```bash
# Enable batch resend without restart
echo "set mqtt.batch_resend=true" > /var/run/nanomq/ipc.sock

# Adjust retry interval without restart  
echo "set mqtt.qos_duration=20" > /var/run/nanomq/ipc.sock
```

## Monitoring

Enable debug logging to see batch resend activity:

```hocon
log {
    level = debug
}
```

Watch for these log messages:
- `INFO: resending qos msg id X to pipe Y` - Message being resent from cache

## Related Documentation

- [Full Batch Resend Guide](./batch_resend.md) - Detailed explanation of how it works
- [MQTT QoS Documentation](https://docs.nanomq.io/) - Understanding MQTT message delivery guarantees
