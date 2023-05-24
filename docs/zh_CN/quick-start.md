# 快速开始


## 启动 MQTT Broker

```bash
nanomq start &
```

目前，NanoMQ完整支持MQTT 3.1.1和部分MQTT 5.0协议。

## 使用MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
