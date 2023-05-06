# NanoMQ 介绍

[NanoMQ](https://nanomq.io/zh)是于2021年初发布的边缘计算开源项目，是面向物联网边缘计算场景的下一代轻量级高性能**MQTT**消息服务器。

Github仓库地址: https://github.com/emqx/nanomq

IoT 时代数据是第一生产力，而边缘则是数据诞生的地方。在边缘复杂的网络环境中对数据进行快速汇聚分发，一个高实时、高吞吐的边缘消息总线至关重要。然而由于产业链条长和各垂直行业的历史原因，使得边缘存在协议碎片化和多种消息模式，而且嵌入式环境的算力和功耗也有严格限制。这些问题都对边缘消息总线提出了新的要挑战。
[NanoMQ](https://nanomq.io/zh) 致力于解决这些问题，提供一个能够在边缘端统一数据流动的轻量级高性能消息总线。同时提供极佳的拓展性和可移植性，适配各类嵌入式平台。让分散在边缘的碎片数据能够被轻松管理和获取。



**NanoMQ**与**NNG**深度合作，**NanoMQ**基于**NNG**异步IO和多线程模型面向**MQTT**协议深度优化后诞生。依靠**NNG**出色的网络API设计，**NanoMQ**自身可以专注于MQTT服务器性能和更多的拓展功能。目标为边缘设备和MEC提供更好的SMP支持和极高的性能性价比。

目前**NanoMQ**具有的功能和特性有：

- 完整支持*MQTT 3.1.1*和*MQTT 5.0*
- 多种桥接方式，包括 MQTT/QUIC/nanomsg/ZeroMQ/DDS 等，与云端和其他服务进行数据同步。
- 支持WebSocket和TLS加密连接。
- 嵌入式规则引擎 + Webhook插件，无缝集成。
- 内置数据持久化，断网缓存自动续传。
- 支持nanomsg/nng和ZeroMQ协议转换。
- 丰富的HTTP REST API，支持云边协同。

*不支持的 MQTT 5.0 特性*

- Auth https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901217
- Server Redirection https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901255

![img](./images/NanoMQ-introduction.png)

[功能特性](./features.md)

[快速开始](./quick-start.md)

[配置说明](./config-description/v014.md)

[编译选项](./build-options.md)

[HTTP APIs](./http-api/v4.md)

[Web Hook](./web-hook.md)

[SOME/IP 网关](./someip-gateway.md)

[工具集](./toolkit.md)

[MQTT 桥接](./bridges/tcp-bridge.md)

[Docker](./docker.md)

[DDS](./dds.md)

[测试报告](./test-report.md)

[ZMQ 网关](./zmq-gateway.md)

