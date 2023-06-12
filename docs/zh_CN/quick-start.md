# 快速开始



## 启动 MQTT Broker

```bash
nanomq start &
```

目前， NanoMQ 完整支持 MQTT 3.1.1 和部分 MQTT 5.0 协议（暂不支持s [Auth](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901217) 和 [Server Redirection](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901255)）。

## 使用 MQTT Client

```bash
# Publish
nanomq_cli pub --url <url> -t <topic> -m <message> [--help]

# Subscribe
nanomq_cli sub --url <url> -t <topic> [--help]

# Connect*
nanomq_cli conn --url <url> [--help]
```
