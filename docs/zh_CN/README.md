# NanoMQ 介绍

[NanoMQ](https://nanomq.io/)是于2020年7月开始开发的边缘计算开源项目，是面向物联网边缘计算场景的下一代轻量级高性能**MQTT**消息服务器。

Github仓库地址: https://github.com/emqx/nanomq

[NanoMQ](https://nanomq.io/)目标致力于为不同的边缘计算平台交付简单且强大的消息中心服务；站在物联网的十字路口，努力弥和硬件开发与云计算的隔阂；从开源社区出发，连接物理世界和数字智能；从而普及边缘计算应用，助力万物互联愿景。

**NanoMQ**与**NNG**深度合作，**NanoMQ**基于**NNG**异步IO和多线程模型面向**MQTT**协议深度优化后诞生。依靠**NNG**出色的网络API设计，**NanoMQ**自身可以专注于MQTT服务器性能和更多的拓展功能。目标为边缘设备和MEC提供更好的SMP支持和极高的性能性价比。

目前**NanoMQ**具有的功能和特性有：

- 完整支持**MQTT 3.1.1**协议。 

- 由于项目只依赖原生**POSIX API**， 纯C/C++开发，从而具有极高兼容性和高度可移植性。
- **NanoMQ**内部为全异步IO和多线程并行，所以对SMP有良好支持，同时做到了低延时和高吞吐。
- 对于资源利用具有高性价比，适用于各类边缘计算平台。

[功能特性](./features.md)

[快速开始](./quick-start.md)

[配置说明](./config-description.md)

[编译选项](./build-options.md)

[HTTP APIs](./http-api.md)

[Web Hook](./web-hook.md)

[工具集](./toolkit.md)

[测试报告](./test-report.md)

