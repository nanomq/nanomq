# HTTP API

NanoMQ 提供了 HTTP API 以实现与外部系统的集成，例如查询 broker 统计信息、客户端信息、发布消息，订阅主题信息和远程修改配置/重启等。

NanoMQ 的 HTTP API 服务默认监听 8081 端口。可通过 `etc/nanomq.conf` 配置文件修改监听端口，所有 API 调用均以 `api/v1` 或 `api/v4` 开头。

## 接口安全

NanoMQ 的 HTTP API 使用 [Basic 认证](https://en.wikipedia.org/wiki/Basic_access_authentication)或 [JWT 认证](../access-control/jwt.md)方式。`username` 和 `password` 须分别填写。 默认的`username` 和 `password` 是：`admin/public`。 可通过 `etc/nanomq.conf` 配置文件修改 `username` 和 `password` 。

