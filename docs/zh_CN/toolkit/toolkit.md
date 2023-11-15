# NanoMQ Toolkit

本章介绍如何通过 NanoMQ 的命令行界面使用 NanoMQ 提供的各项功能。如何利用内置的 Bench 工具进行MQTT 性能测试，以及如何利用内置的nftp工具进行文件传输。

## [命令行界面](command-line.md)

本节主要介绍如何通过 NanoMQ 的命令行界面使用 NanoMQ 的消息代理功能、客户端工具以及创建规则：

- **Broker**: Broker 部分提供了与连接、HTTP 服务、MQTT、TLS 及日志相关的一系列命令参数。 
- **Client**: Client 部分介绍了与客户端的 Publish、Subscribe 和 Conn 相关的一系列命令参数。
- **Rule**：Rule 部分介绍了如何通过命令行界面创建和管理规则。

## [Bench](bench.md)

Bench 是使用 NanoSDK 编写的简洁强大的 MQTT 协议性能测试工具。用户可通过 Bench 进行全面性能测试，如消息的发布和订阅、创建连接等，以便更好地理解系统性能、限制和瓶颈。

## [NFTP](nftp.md)

nftp 是基于MQTT的轻量级的文件传输工具。nftp支持一对一、多对一、一对多传输，支持异步传输，支持断点续传。
