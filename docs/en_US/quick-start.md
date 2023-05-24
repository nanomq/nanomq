# QuickStart

## Start MQTT Broker

```bash
nanomq start
```

Currently, NanoMQ supports MQTT 3.1.1 & 5.0, MQTT 3.1 is not included

## MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
