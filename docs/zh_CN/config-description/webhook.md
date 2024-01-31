# WebHook

NanoMQ 提供了可拓展的事件驱动型 WebHook 功能，用户可通过规则配置 WebHook 的触发事件或消息主题。借助 WebHook，您可以轻松将 NanoMQ 与其他服务集成，构建复杂的事件驱动架构。

## **配置示例**

```hcl
webhook = {
  url = "http://127.0.0.1:80"        # WebHook 将向此 URL 发送 HTTP 请求
  headers.content-type = "application/json" # HTTP请求头的内容类型
  body.encoding = "plain"            # Payload 编码方式
  pool_size = 32                     # 连接池大小
  events = [
    {
      event = "on_message_publish"   # 事件类型
      topic = "a/b/c"                # 此事件适用的主题
    }
    {
      event = "on_client_connack"    
    }
  ]
}
```

## **配置项**

- `url`： Webhook 要发送 HTTP 请求的地址。该地址必须是可以正确处理 HTTP 请求的端点。
- `headers.content-type`: HTTP请求头的内容类型，如，"application/json"，表示 HTTP 请求的 Payload 将被格式化为 JSON 对象。
- `body.encoding`：HTTP 请求中 Payload 字段的编码格式。此字段仅对 `on_message_publish` 和 `on_message_delivered` 事件有效。有效值：`plain`、`base64` 或 `base62`。
- `pool_size`：连接进程池的大小，即 WebHook 可以与 `url` 指定的端点维持的并发连接数量。默认值：32。
- `events`：事件对象的数组，每个对象指定一个将触发 WebHook 的事件：
  - `event`: 将触发 WebHook 的事件的类型，取值：
    - `on_client_connack`
    - `on_client_disconnected`
    - `on_message_publish`
  - `topic`(可选项)：对于 `on_message_publish` 事件，可以指定触发主题，即只有向此主题发布的消息才会触发 WebHook。

## 功能预告

**TLS**

在接下来的版本中，NanoMQ 将支持与 HTTP 身份验证相关的 TLS 配置项，敬请期待。

```
tls {
   	keyfile="/etc/certs/key.pem"
  	certfile="/etc/certs/cert.pem"
  	cacertfile="/etc/certs/cacert.pem"
}
```

**事件**

在接下来的版本中，NanoMQ 将支持更多的事件类型：

- `on_client_connect`
- `on_client_connected`
- `on_client_subscribe`
- `on_client_unsubscribe`
- `on_session_subscribed`
- `on_session_unsubscribed`
- `on_session_terminated`
- `on_message_delivered`
- `on_message_acked`
