# Windows

This section will guide you on installing and starting NanoMQ on Windows with a zip file.

::: tip

This page takes v0.18.2 as an example, if you'd like to work with the other version, you may refer to the [NanoMQ Download](https://nanomq.io/downloads?os=Windows) page.

:::

1. Download [nanomq-0.18.2-windows-x86_64.zip](https://www.emqx.com/en/downloads/nanomq/0.18.2/nanomq-0.18.2-windows-x86_64.zip), and unzip it.

2. To start NanoMQ, run:

   ```
   nanomq start  
   ```

 **Features supported in Window**

|        Features         | Support |                 Note                 |
| ----------------------- | ------- | ------------------------------------ |
| MQTT Broker             | ✅      | MQTT ver3.1 3.1.1 5.0 are supported  |
| TLS/SSL                 | ✅      | lib mbedtls is required              |
| WebSocket               | ✅      |                                      |
| QUIC                    | ❌      |                                      |
| MQTT over TCP Bridging  | ✅      |                                      |
| HTTP APIs               | ✅      |                                      |
| Rule engine             | ✅      | only repub is supported              |
| Webhook                 | ✅      |                                      |
| CLI client tool         | ✅      |                                      |
| Bench basic test tool   | ❌      |                                      |
  