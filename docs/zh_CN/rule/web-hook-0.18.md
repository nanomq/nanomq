# WebHook

<<<<<<< Updated upstream
NanoMQ 提供了可拓展到事件驱动型 WebHook 接口，用户可通过规则配置 WebHook 的触发事件或消息主题。Webhook 的配置文件位于 `etc/nanomq.conf`，具体配置项可查看[配置说明](../config-description/v018.md)。
=======
NanoMQ 提供了可拓展到事件驱动型 WebHook 接口，用户可通过规则配置 WebHook 的触发事件或消息主题。Webhook 的配置文件位于 `etc/nanomq.conf`。NanoMQ 提供了三个版本的配置文件，您可根据需要及部署版本选择：

- NanoMQ 0.18 版本及以上：[HOCON](../config-description/v018.md)，弃用 `enable` 选项，如希望启用相关功能，只需将模块加入配置文件即可。

- NanoMQ 0.14 - 0.17 版本：[HOCON](../config-description/v014.md)，需设置 `webhook.enable = true` 启用相关功能。

- NanoMQ 0.13 版本及以下：[旧版本配置（不推荐）](../config-description/v013.md)

- ## 启用 Webhook

:::: tabs type:card

::: tab HOCON 格式配置（NanoMQ 0.14 及以上）
>>>>>>> Stashed changes

添加 webhook 对应的选项到 `etc/nanomq.conf` 即可, 如下：

```bash
webhook {
    ......
}
```
**📢 注意**：对于 0.14~0.17 版本用户，仍需通过 `webhook.enable = true` 启用 WebHook 功能。

:::

::: tab 旧版本配置

```bash
web.hook.enable=true
```

:::

::::

## WebHook 触发规则

:::: tabs type:card

::: tab HOCON 格式配置（NanoMQ 0.14 及以上）

Webhook 支持两个配置参数：

- `event` ：字符串，取固定值
- `topic` ：字符串，主题过滤器，只有当消息主题与规则中指定的主题匹配时，才会触发消息的转发动作。

**语法**

```bash
## 格式示例
webhook.events = [
    ## 此处可以添加多条规则
    {
        <Rule>
    }
]
```

**示例**

我们希望将 `a/b/c` 和 `foo/#` 主题下的消息转发到 Web 服务器上，其配置应该为：

```bash
webhook.events = [
	{ 
		event = "on_message_publish"
		topic = "a/b/c"
	}
	{
		event = "on_message_publish"
		topic = "foo/#"
	}
]
```

:::

::: tab 旧版本配置

触发规则，其值为一个 JSON 字符串，其中可用的 Key 有：

- action ：字符串，取固定值
- topic ：字符串，表示一个主题过滤器，操作的主题只有与该主题匹配才能触发事件的转发

语法：

```bash
## 格式示例
web.hook.rule.<Event>.<Number>=<Rule>


## 示例值
web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2={"action": "on_message_publish", "topic": "foo/#"}
```

例如，我们只将与 a/b/c 和 foo/# 主题匹配的消息转发到 Web 服务器上，其配置应该为：

```bash
web.hook.rule.message.publish.1 = {"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}
```

其中，

`Number` 指同一个事件可以多次配置同一类触发规则，并通过编号区分。

:::

::::

## 触发事件

Naono目前支持三类触发事件：

| 事件名称 (0.13 版本及以下) | 事件名称 (0.14 版本及以上)     | 说明         | 执行时机                     |
| ------------------------------| ------------ | ---------------------------- | ---------------------------- |
| client.connack | on_client_connack | 下发连接应答  | 服务端准备下发连接应答报文时 |
| client.disconnected | on_client_disconnected | 连接断开     | 客户端连接层在准备关闭时     |
| message.publish | on_message_publish | 消息发布     | 服务端在发布（路由）消息前   |

## 事件参数

当某个事件被触发时，WebHook 会将该事件封装成一个 HTTP 请求，并将该请求发送到一个由预设 URL 确定的网络服务器上，其请求格式为：

```bash
URL: <url>      # 来自于配置中的 `url` 字段
Method: POST    # 固定为 POST 方法

Body: <JSON>    # Body 为 JSON 格式字符串
```

对于不同的事件，请求 Body 体内容有所不同，下表列举了各个事件中 Body 的参数列表：

**on_client_connack/client.connack**

| Key       | 类型    | 说明                                        |
| --------- | ------- | ------------------------------------------- |
| action    | string  | 事件名称 固定为："client_connack"           |
| clientid  | string  | 客户端 ClientId                             |
| username  | string  | 客户端 Username，不存在时该值为 "undefined" |
| keepalive | integer | 客户端申请的心跳保活时间                    |
| proto_ver | integer | 协议版本号 （ 3 ｜ 4 ｜ 5 ）                |
| conn_ack  | string  | "success" 表示成功，其它会返回失败的原因    |

**on_client_disconnected/client.disconnected**

| Key      | 类型   | 说明                                        |
| -------- | ------ | ------------------------------------------- |
| action   | string | 事件名称 固定为："client_disconnected"      |
| clientid | string | 客户端 ClientId                             |
| username | string | 客户端 Username，不存在时该值为 "undefined" |
| reason   | string | 错误原因                                    |

**on_message_publish/message.publish**

| Key            | 类型    | 说明                                        |
| -------------- | ------- | ------------------------------------------- |
| action         | string  | 事件名称 固定为："message_publish"          |
| from_client_id | string  | 发布端 ClientId                             |
| from_username  | string  | 发布端 Username，不存在时该值为 "undefined" |
| topic          | string  | 取消订阅的主题                              |
| qos            | enum    | QoS 等级，可取 0、1、2                      |
| retain         | bool    | 是否为保留消息                              |
| payload        | string  | 消息 Payload                                |
| ts             | integer | 消息的时间戳 (毫秒)                         |

## 配置多条触发规则（0.14 及以上）

```bash
webhook.events = [
	url = "http://127.0.0.1:80"
	headers.content-type = "application/json"
	body.encoding = plain
	pool_size = 32

	{ 
		event = "on_message_publish"
		topic = "a/b/c"
	}
	{
		event = "on_client_connack"
	}
]
```

**📢 注意**：对于 0.14~0.17 版本用户，仍需通过 `webhook.enable = true` 启用 WebHook 功能。

其中，

`event`：WebHook 触发事件，类型为 string，支持的事件包括：

- `on_client_connack`：客户端建立连接
- `on_client_disconnected`：客户端断开连接
- `on_message_publish`：消息发布

`topic`：消息的发布主题，类型为 string