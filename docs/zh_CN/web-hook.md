# WebHook



## 配置项

Webhook 的配置文件位于 `etc/nanomq_web_hook.conf`, 具体配置项可查看[配置说明](./config-description.md).

**启用Webhook**

```bash
web.hook.enable=true
```

## 触发规则

在 etc/nanomq_web_hook.conf 可配置触发规则，其配置的格式如下：

```bash
## 格式示例
web.hook.rule.<Event>.<Number>=<Rule>

## 示例值
web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2={"action": "on_message_publish", "topic": "foo/#"}
```

### Event 触发事件

目前支持以下事件：

| 名称                | 说明         | 执行时机                     |
| ------------------- | ------------ | ---------------------------- |
| client.connack      | 下发连接应答 | 服务端准备下发连接应答报文时 |
| client.disconnected | 连接断开     | 客户端连接层在准备关闭时     |
| message.publish     | 消息发布     | 服务端在发布（路由）消息前   |

### Number

同一个事件可以配置多个触发规则，配置相同的事件应当依次递增。

### Rule

触发规则，其值为一个 JSON 字符串，其中可用的 Key 有：

- action：字符串，取固定值
- topic：字符串，表示一个主题过滤器，操作的主题只有与该主题匹配才能触发事件的转发

例如，我们只将与 a/b/c 和 foo/# 主题匹配的消息转发到 Web 服务器上，其配置应该为：

```bash
web.hook.rule.message.publish.1 = {"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}
```

这样 Webhook 仅会转发与 a/b/c 和 foo/# 主题匹配的消息，例如 foo/bar 等。

## Webhook 事件参数

事件触发时 Webhook 会按照配置将每个事件组成一个 HTTP 请求发送到 url 所配置的 Web 服务器上。其请求格式为：

```bash
URL: <url>      # 来自于配置中的 `url` 字段
Method: POST    # 固定为 POST 方法

Body: <JSON>    # Body 为 JSON 格式字符串
```

对于不同的事件，请求 Body 体内容有所不同，下表列举了各个事件中 Body 的参数列表：

**client.connack**

| Key       | 类型    | 说明                                        |
| --------- | ------- | ------------------------------------------- |
| action    | string  | 事件名称 固定为："client_connack"           |
| clientid  | string  | 客户端 ClientId                             |
| username  | string  | 客户端 Username，不存在时该值为 "undefined" |
| keepalive | integer | 客户端申请的心跳保活时间                    |
| proto_ver | integer | 协议版本号 （3 ｜ 4 ｜ 5）                  |
| conn_ack  | string  | "success" 表示成功，其它表示失败的原因      |

**client.disconnected**

| Key      | 类型   | 说明                                        |
| -------- | ------ | ------------------------------------------- |
| action   | string | 事件名称 固定为："client_disconnected"      |
| clientid | string | 客户端 ClientId                             |
| username | string | 客户端 Username，不存在时该值为 "undefined" |
| reason   | string | 错误原因                                    |

**message.publish**

| Key            | 类型    | 说明                                        |
| -------------- | ------- | ------------------------------------------- |
| action         | string  | 事件名称 固定为："message_publish"          |
| from_client_id | string  | 发布端 ClientId                             |
| from_username  | string  | 发布端 Username，不存在时该值为 "undefined" |
| topic          | string  | 取消订阅的主题                              |
| qos            | enum    | QoS 等级，可取 0 1 2                        |
| retain         | bool    | 是否为 Retain 消息                          |
| payload        | string  | 消息 Payload                                |
| ts             | integer | 消息的时间戳(毫秒)                          |