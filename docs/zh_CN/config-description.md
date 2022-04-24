# 配置说明

## 简介

NanoMQ 的配置文件通常以 .conf 作为后缀名，你可以在 etc 目录找到这些配置文件，主要配置文件包括：

| 配置文件                      | 说明                   |
| ----------------------------- | ---------------------- |
| etc/nanomq.conf               | NanoMQ 配置文件        |
| etc/nanomq_bridge.conf        | NanoMQ桥接配置文件     |
| etc/nanomq_auth_username.conf | NanoMQ用户密码配置文件 |
| etc/nanomq_web_hook.conf      | NanoMQ WebHook配置文件 |

## 参数说明

### nanomq.conf

| 参数名                  | 数据类型    | 参数说明                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| url              | String  | 监听url。                                                    |
| num_taskq_thread | Integer | 任务线程数。 |
| max_taskq_thread | Integer | 最大任务线程数。 |
| parallel |Long  | 并行数。 |
| property_size |Integer  | 最大属性长度。 |
| msq_len | Integer | 队列长度。 |
| qos_duration | Integer | QOS消息定时间隔时间。 |
| allow_anonymous | Boolean | 允许匿名登录。 |
| tls.enable | Boolean | 启动TLS监听（*默认false*）。 |
| tls.url |String  | TLS监听URL。 |
| tls.key | String | TLS私钥数据。 |
| tls.keypass | String | TLS私钥密码。 |
| tls.cert |String  | TLS Cert证书数据。 |
| tls.cacert | String | TLS CA证书数据。|
| tls.verify_peer | Boolean | 验证客户端证书。 |
| tls.fail_if_no_peer_cert | Boolean | 拒绝无证书连接，与*tls.verify_peer*配合使用。 |
| websocket.enable | Boolean | 启动websocket监听（*默认true*）。 |
| websocket.url | String  | Websocket监听URL。 |
| websocket.tls_url |  String | TLS over Websocket监听URL。 |
| http_server.enable| Boolean | 启动Http服务监听（*默认false*)。 |
| http_server.port | Integer | Http服务端监听端口。 |
| http_server.username | String | 访问Http服务用户名。 |
| http_server.password | String | 访问Http服务密码。 |
| http_server.auth_type | Enum | Http鉴权方式。（*默认 basic*） |
| http_server.jwt.public.keyfile | String |*JWT* 公钥文件. |
| http_server.jwt.private.keyfile | String |*JWT* 私钥文件. |

### nanomq_bridge.conf

| 参数名                  | 数据类型    | 参数说明                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| bridge.mqtt.bridge_mode | Boolean | 启动桥接功能（*默认`false`不启用*）。 |
| bridge.mqtt.address | String | 桥接目标broker地址URL。 |
| bridge.mqtt.proto_ver | String | 桥接客户端MQTT版本（3｜4｜5）。 |
| bridge.mqtt.clientid | String | 桥接客户端ID（*默认NULL为自动生成随机ID*）。 |
| bridge.mqtt.keepalive | Integer | 保活间隔时间。 |
| bridge.mqtt.clean_start | Boolean | 清除会话。 |
| bridge.mqtt.parallel | Long | 桥接客户端并发数。 |
| bridge.mqtt.username | String | 登录用户名。 |
| bridge.mqtt.password | String | 登录密码。 |
| bridge.mqtt.forwards | Array[String] | 转发Topic数组, 使用逗号`,`分隔多个`Topic`。 |
| bridge.mqtt.subscription.1.topic | String | 第1个订阅`Topic`。                               |
| bridge.mqtt.subscription.1.qos | Integer | 第1个订阅`Qos`。                       |
| bridge.mqtt.subscription.2.topic | String        | 第2个（*以此类推*）订阅`Topic`。             |
| bridge.mqtt.subscription.2.qos   | Integer       | 第2个（*以此类推*）订阅`Qos`。 |

### nanomq_auth_username.conf

| 参数名          | 数据类型 | 参数说明                        |
| --------------- | -------- | ------------------------------- |
| auth.1.login    | String   | 第1个登录用户名。               |
| auth.1.password | String   | 第1个登录密码。                 |
| auth.2.login    | String   | 第2个（*以此类推*）登录用户名。 |
| auth.2.password | String   | 第2个（*以此类推*）登录密码。   |

### nanomq_web_hook.conf

| Name                                     | Type    | Description                                                  |
| ---------------------------------------- | ------- | ------------------------------------------------------------ |
| web.hook.enable                          | Boolean | 启动WebHook (默认: `false`)                                  |
| web.hook.url                             | String  | *Webhook URL*                                                |
| web.hook.headers.\<Any\>                 | String  | *HTTP Headers*<br>*Example:*<br>*1. web.hook.headers.content-type=application/json*<br> *2. web.hook.headers.accept=\** |
| web.hook.body.encoding_of_payload_field  | Enum    | *Payload编码方式*<br>Options: <br>plain \| base64 \| base62  |
| web.hook.ssl.cacertfile                  | String  | *TLS CA证书文件*.                                            |
| web.hook.ssl.certfile                    | String  | *TLS Cert证书文件*                                           |
| web.hook.ssl.keyfile                     | String  | *TLS 私钥文件.*                                              |
| web.hook.ssl.verify                      | Boolean | *验证客户端证书。*  (默认: `false`).                         |
| web.hook.ssl.server_name_indication      | Boolean | *验证服务端名*  (默认: `false`).                             |
| web.hook.pool_size                       | Integer | *连接池大小 （默认: 32）*.                                   |
| web.hook.rule.client.connack.\<No\>      | String  | 示例: <br>*web.hook.rule.client.connack.1={"action": "on_client_connack"}* |
| web.hook.rule.client.disconnected.\<No\> | String  | *示例: <br/>web.hook.rule.client.disconnected.1={"action": "on_client_disconnected"}* |
| web.hook.rule.message.publish.\<No\>     | String  | 示例: <br/>*web.hook.rule.message.publish.1={"action": "on_message_publish"}* <br>*web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "topic/1/2"}* <br>*web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}* |

