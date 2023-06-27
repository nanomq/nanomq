# MQTT 数据桥接

您可通过桥接连接多个 MQTT 代理。本节介绍 MQTT over TCP 数据桥接和 MQTT over QUIC 数据桥接。

## MQTT over TCP 桥接
本节将介绍 MQTT over TCP 数据桥接相关的配置参数，并将包含一个典型的 `nanomq.conf` 文件配置。本节还将介绍如何通过指定的配置文件运行 NanoMQ 以及如何对桥接进行测试。

## MQTT over QUIC 桥接 
针对较难集成 MQTT over QUIC 数据桥接的场景，NanoMQ 创新性地引入了 MQTT over QUIC 数据桥接。QUIC 最初由 Google 开发，后来被互联网工程任务组（IETF）采纳为全球标准。它是一种新的传输协议，提供更快的连接建立速度。通过 MQTT over QUIC 数据桥接，我们可以充分发挥 QUIC 协议在 IoT 场景中的优势。