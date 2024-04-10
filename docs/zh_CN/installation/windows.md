# Windows

本章节将指导您如何在 Windows 系统中通过 zip 的形式下载安装并启动 NanoMQ。

::: tip

本页将以安装 NanoMQ 0.18.2 为例进行演示，如希望使用其他版本，可参考 [NanoMQ 下载](https://nanomq.io/zh/downloads?os=Windows) 页面.

:::

1. 下载 [nanomq-0.18.2-windows-x86_64.zip](https://www.emqx.com/zh/downloads/nanomq/0.18.2/nanomq-0.18.2-windows-x86_64.zip) 并解压缩。

2. 通过以下命令启动 NanoMQ：

   ```
   nanomq start  
   ```

**Window支持功能**

|        功能         | 支持 |         说明          |
| ------------------ | ---- | -------------------- |
| MQTT Broker功能     |  ✅  | 支持3.1、3.1.1、5.0   |
| TLS/SSL            |  ✅  | 需要手动安装mbedtls   |
| WebSocket          |  ✅  |                      |
| QUIC               |  ❌  |                      |
| MQTT over TCP桥接   | ✅  |                       |
| HTTP APIs          |  ✅  |                      |
| 规则引擎             |  ✅ |   目前只支持repub      |
| webhook            |  ✅  |                      |
| CLI客户端工具        |  ✅  |                      |
| Bench 基准测试工具   |  ❌  |                      |
