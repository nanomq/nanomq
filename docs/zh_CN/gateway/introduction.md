# 多协议网关

本节介绍多通信协议网关，包括 ZeroMQ (也称为 ØMQ、0MQ 或 zmq) 网关、SOME/IP 网关和 DDS 网关。

## [ZeroMQ 网关](./zmq-gateway.md)
NanoMQ 通过 ZeroMQ 网关实现了 ZMQ 和 MQTT 代理之间的数据转换，为用户提供了一种高性能、低延迟的消息传递机制。

## [SOME/IP 网关](./someip-gateway.md)

SOME/IP 是一种针对汽车以太网电子/电气系统的中间件解决方案，SOME/IP 网关负责 MQTT 消息和 SOME/IP 消息之间的数据转换。

## [DDS 网关](./dds.md)

Data Distribution Service（DDS） 是新一代分布式实时通信中间件协议，采用发布/订阅体系架构，强调以数据为中心，提供丰富的 QoS 服务质量策略，以保障数据进行实时、高效、灵活地分发，可满足各种分布式实时通信应用需求。 [Cyclone DDS](https://cyclonedds.io/) 是一款基于 OMG （ Object Management Group ） DDS 规范的开源 DDS 实现，用于发布/订阅消息的实时系统。NanoMQ 的 DDS 网关基于 Cyclone DDS 实现，负责将指定 Topic 的 MQTT 和 DDS 消息相互转发到对方。