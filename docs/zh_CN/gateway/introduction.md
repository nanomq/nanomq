# 多协议网关

本节介绍多通信协议网关，包括 ZeroMQ (也称为 ØMQ、0MQ 或 ZMQ) 网关、SOME/IP 网关和 DDS 网关。

## [ZeroMQ 网关](./zmq-gateway.md)
**ZeroMQ**（也写作**ØMQ**，**0MQ **或 **ZMQ **)是一个为可伸缩的分布式或并发应用程序设计的高性能异步消息库，是一种高性能、低延迟的消息传递机制。与面向消息的中间件不同，ZeroMQ 的运行不需要专门的消息代理。

NanoMQ 通过 ZMQ 网关实现了对 ZeroMQ 消息队列的数据传输与路由。

## [SOME/IP 网关](./someip-gateway.md)

**SOME/IP** 是一种针对汽车以太网电子/电气系统的中间件解决方案。在软件定义汽车的趋势下，SOME/IP 在处理来自车内各种来源数据方面表现出高效和安全的特性。它既能与传统的 TSP 平台对接，还能联系 ADAS 等新一代应用服务完成计算卸载转移。

NanoMQ 现已通过 SOME/IP 网关支持基于 AUTOSAR 标准的 SOME-IP 数据通信方式，可以部署在车内中央网关中完成汇聚和与 TSP 平台的对接工作，并通过MQTT over QUIC/TCP + TLS 加密连接保证网关的安全性。

## [DDS 网关](./dds.md)

**Data Distribution Service（DDS）** 是新一代分布式实时通信中间件协议，采用发布/订阅体系架构，强调以数据为中心，提供丰富的 QoS 服务质量策略，以保障数据进行实时、高效、灵活地分发，可满足各种分布式实时通信应用需求。 [Cyclone DDS](https://cyclonedds.io/) 是一款基于 OMG （ Object Management Group ） DDS 规范的开源 DDS 实现，用于发布/订阅消息的实时系统。NanoMQ 的 DDS 网关基于 Cyclone DDS 实现，负责将指定 Topic 的 MQTT 和 DDS 消息相互转发到对方。