# 经典 KV 格式配置说明
此处内容介绍经典 KV 格式配置文件。

## 基本配置参数

| 参数名                  | 数据类型    | 参数说明                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| url              | String  | 监听 url。                                                    |
| num_taskq_thread | Unsigned Integar 32 (Long) | 任务线程数。 |
| max_taskq_thread | Unsigned Integar 32 (Long) | 最大任务线程数。 |
| parallel |Long  | 并行执行的线程数。 |
| property_size |Integer  | 最大属性长度。 |
| msq_len | Integer | 队列长度。 |
| qos_duration | Integer | QoS 消息定时间隔时间 + 全局定时器最小颗粒度时间。 |
| allow_anonymous | Boolean | 允许匿名登录。 |
| tls.enable | Boolean | 启动 TLS 监听（*默认 false*）。 |
| tls.url |String  | TLS 监听 URL。 |
| tls.key | String | TLS 私钥数据。 |
| tls.keypass | String | TLS 私钥密码。 |
| tls.cert |String  | TLS Cert 证书数据。 |
| tls.cacert | String | TLS CA 证书数据。|
| tls.verify_peer | Boolean | 验证客户端证书。 |
| tls.fail_if_no_peer_cert | Boolean | 拒绝无证书连接，与*tls.verify_peer*配合使用。 |
| websocket.enable | Boolean | 启动 websocket 监听（*默认 true*）。 |
| websocket.url | String  | Websocket 监听 URL。 |
| websocket.tls_url |  String | TLS over Websocket 监听 URL。 |
| http_server.enable| Boolean | 启动 Http 服务监听（*默认 false*)。 |
| http_server.port | Integer | Http 服务端监听端口。 |
| http_server.username | String | 访问 Http 服务用户名。 |
| http_server.password | String | 访问 Http 服务密码。 |
| http_server.auth_type | Enum | Http 鉴权方式。（*默认 basic*） |
| http_server.jwt.public.keyfile | String |*JWT* 公钥文件 . |
| http_server.jwt.private.keyfile | String |*JWT* 私钥文件 . |
| log.to | Array[Enum] |日志输出类型数组，使用逗号`,`分隔多种类型<br>支持*文件，控制台， Syslog 输出*，对应参数: <br>*file, console, syslog* |
| log.level | Enum |日志等级： trace, debug, info, warn, error, fatal |
| log.dir | String |日志文件存储路径 (输出文件时生效) |
| log.file | String |日志文件名(输出文件时生效) |
| log.rotation.size | Integer | 每个日志文件的最大占用空间; <br>支持单位: `KB | MB | GB`;<br> 默认: `10MB` |
| log.rotation.count | Integer | 轮换的最大日志文件数; <br>默认: `5` |

## 标准 MQTT 桥接配置参数

> 支持多组桥接配置， NAME 为用户定义的桥接组名，不同桥接组名字不可重复 .

| 参数名                                        | 数据类型      | 参数说明                                                     |
| --------------------------------------------- | ------------- | ------------------------------------------------------------ |
| bridge.mqtt.{NAME}.bridge_mode                | Boolean       | 启动桥接功能（*默认`false`不启用*）。                        |
| bridge.mqtt.{NAME}.address                    | String        | 桥接目标 broker 地址 URL。                                   |
| bridge.mqtt.{NAME}.proto_ver                  | String        | 桥接客户端 MQTT 版本（ 3 ｜ 4 ｜ 5 ）。                      |
| bridge.mqtt.{NAME}.clientid                   | String        | 桥接客户端 ID （*默认 NULL 为自动生成随机 ID*）。            |
| bridge.mqtt.{NAME}.keepalive                  | Integer       | 保活间隔时间。                                               |
| bridge.mqtt.{NAME}.clean_start                | Boolean       | 清除会话。                                                   |
| bridge.mqtt.{NAME}.parallel                   | Long          | 桥接客户端并发数。                                           |
| bridge.mqtt.{NAME}.username                   | String        | 登录用户名。                                                 |
| bridge.mqtt.{NAME}.password                   | String        | 登录密码。                                                   |
| bridge.mqtt.{NAME}.forwards                   | Array[String] | 转发 Topic 数组, 使用逗号`,`分隔多个`Topic`。                |
| bridge.mqtt.{NAME}.subscription.1.topic       | String        | 第 1 个订阅`Topic`。                                         |
| bridge.mqtt.{NAME}.subscription.1.qos         | Integer       | 第 1 个订阅`Qos`。                                           |
| bridge.mqtt.{NAME}.subscription.2.topic       | String        | 第 2 个（*以此类推*）订阅`Topic`。                           |
| bridge.mqtt.{NAME}.subscription.2.qos         | Integer       | 第 2 个（*以此类推*）订阅`Qos`。                             |
| bridge.mqtt.{NAME}..connector.conn_properties | Object        | Connector 的 MQTT V5 属性(见下表)                            |
| bridge.mqtt.{NAME}.connector.ssl.enable       | Boolean       | 启动 TLS 监听（_默认 false_）。                              |
| bridge.mqtt.{NAME}.connector.ssl.key_password | String        | TLS 私钥密码。                                               |
| bridge.mqtt.{NAME}.connector.ssl.keyfile      | String        | TLS 私钥数据。                                               |
| bridge.mqtt.{NAME}.connector.ssl.certfile     | String        | TLS Cert 证书数据。                                          |
| bridge.mqtt.{NAME}.connector.ssl.cacertfile   | String        | TLS CA 证书数据。                                            |
| bridge.mqtt.{NAME}.quic_keepalive             | Duration      | Quic 传输层保活时间, （_默认 120s_ )                         |
| bridge.mqtt.{NAME}.quic_idle_timeout          | Duration      | Quic 连接最大过期时间 （_默认 120s_ )                        |
| bridge.mqtt.{NAME}.quic_discon_timeout        | Duration      | Quic 等待连接 ACK 最大时间 （_默认 20s_ )                    |
| bridge.mqtt.{NAME}.quic_handshake_timeout     | Duration      | QUIC 握手最大超时时间（_默认 60s_ )                          |
| bridge.mqtt.{NAME}.hybrid_bridging            | Boolean       | 混合桥接模式开关，(_默认 `false` 不启用_), 如果想最大利用 QUIC ，建议启用 |
| bridge.mqtt.{NAME}.qsend_idle_timeout         | Duration      | QUIC 传输层重置拥塞控制算法的等待超时时间 (*默认`60 s`*)     |
| bridge.mqtt.{NAME}.qinitial_rtt_ms            | Duration      | 初始 RTT 预估时间 (*默认 800ms*)                             |
| bridge.mqtt.{NAME}.qmax_ack_delay_ms          | Duration      | 发送 ACK 之前接收数据后等待时长(默认`100ms`)                 |
| bridge.mqtt.{NAME}.quic_qos_priority          | Boolean       | 高优先级发送 QOS 1 或 2 的消息(*默认 `true`*)                |
| bridge.mqtt.{NAME}.quic_0rtt                  | Boolean       | 0RTT 是 QUIC 协议的一个特性，用于快速重新建立连接 (*默认 `true`*) |
| bridge.mqtt.{NAME}.multi_stream               | Boolean       | Multiple stream 开关，（_默认`false`不启用_）                |
| bridge.mqtt.{NAME}.parallel                   | Long          | 桥接客户端并发数。                                           |
| bridge.mqtt.{NAME}.sub_properties             | Object        | Subscription 的 MQTT V5 属性(见下表)                         |
| bridge.mqtt.{NAME}.max_send_queue_len         | Integer       | 最大发送队列长度                                             |
| bridge.mqtt.{NAME}.max_recv_queue_len         | Integer       | 最大接收队列长度                                             |

*以 Quic 前缀命名的配置项只针对 QUIC 传输层生效*

### MQTT V5 属性配置参数

`Connector`属性:`bridge.mqtt.{NAME}.connector.conn_properties`

| 参数名                      | 数据类型            | 参数说明                                      |
| --------------------------- | ------------------- | --------------------------------------------- |
| maximum_packet_size         | Integer             | *最大报文长度<br>* *Value: 1 ~ 4294967295*    |
| receive_maximum             | Integer             | *接收最大数量*<br>*Value: 1 ~ 65535*          |
| topic_alias_maximum         | Integer             | *主题别名最大长度*<br>*Value: 0 ~ 65535*      |
| request_problem_infomation  | Integer             | *请求问题信息*<br>Default: 1<br>Value: 0 \| 1 |
| request_response_infomation | Integer             | *请求响应信息*<br>Default: 0<br>Value: 0 \| 1 |
| session_expiry_interval     | Integer             | *会话过期间隔*<br>*Value: 0 ~ 4294967295*     |
| user_property               | Map[String, String] | 用户属性 Map[key(String) - value(String)]*     |

`Subscription`属性: `bridge.mqtt.{NAME}.sub_properties`

| 参数名        | 数据类型            | 参数说明                                                |
| ------------- | ------------------- | ------------------------------------------------------- |
| identifier    | Integer             | *订阅标识符*<br>*Value: 1 ~ 268,435,455*                |
| user_property | Map[String, String] | *用户属性*<br>*Value: Map[key(String) - value(String)]* |



## Aws IoT Core MQTT 桥接配置参数

| 参数名                           | 数据类型      | 参数说明                                          |
| -------------------------------- | ------------- | ------------------------------------------------- |
| bridge.mqtt.bridge_mode          | Boolean       | 启动桥接功能（*默认 `false`不启用*）。            |
| bridge.mqtt.host                 | String        | AWS IoT Core 服务地址。                           |
| bridge.mqtt.port                 | Integer       | AWS IoT Core MQTT 端口。                          |
| bridge.mqtt.clientid             | String        | 桥接客户端 ID （*默认 NULL 为自动生成随机 ID*）。 |
| bridge.mqtt.keepalive            | Integer       | 保活间隔时间。                                    |
| bridge.mqtt.clean_start          | Boolean       | 清除会话。                                        |
| bridge.mqtt.parallel             | Long          | 桥接客户端并发数。                                |
| bridge.mqtt.username             | String        | 登录用户名。                                      |
| bridge.mqtt.password             | String        | 登录密码。                                        |
| bridge.mqtt.forwards             | Array[String] | 转发 Topic 数组, 使用逗号`,`分隔多个`Topic`。     |
| bridge.mqtt.subscription.1.topic | String        | 第 1 个订阅 `Topic`。                             |
| bridge.mqtt.subscription.1.qos   | Integer       | 第 1 个订阅 `Qos`。                               |
| bridge.mqtt.subscription.2.topic | String        | 第 2 个（*以此类推*）订阅 `Topic`。               |
| bridge.mqtt.subscription.2.qos   | Integer       | 第 2 个（*以此类推*）订阅 `Qos`。                 |

## 用户登陆验证配置

| 参数名          | 数据类型 | 参数说明                        |
| --------------- | -------- | ------------------------------- |
| auth.1.login    | String   | 第 1 个登录用户名。               |
| auth.1.password | String   | 第 1 个登录密码。                 |
| auth.2.login    | String   | 第 2 个（*以此类推*）登录用户名。 |
| auth.2.password | String   | 第 2 个（*以此类推*）登录密码。   |

## WebHook 配置

| 参数名                                    | 数据类型 | 参数说明                                                    |
| ---------------------------------------- | ------- | ------------------------------------------------------------ |
| web.hook.enable                          | Boolean | 启动 WebHook (默认: `false`)                                  |
| web.hook.url                             | String  | *Webhook URL*                                                |
| web.hook.headers.\<Any\>                 | String  | *HTTP Headers*<br>*Example:*<br>*1. web.hook.headers.content-type=application/json*<br> *2. web.hook.headers.accept=\** |
| web.hook.body.encoding_of_payload_field  | Enum    | *Payload 编码方式*<br>Options: <br>plain \| base64 \| base62  |
| web.hook.ssl.cacertfile                  | String  | *TLS CA 证书文件*.                                            |
| web.hook.ssl.certfile                    | String  | *TLS Cert 证书文件*                                           |
| web.hook.ssl.keyfile                     | String  | *TLS 私钥文件 .*                                              |
| web.hook.ssl.verify                      | Boolean | *验证客户端证书。*  (默认: `false`).                         |
| web.hook.ssl.server_name_indication      | Boolean | *验证服务端名*  (默认: `false`).                             |
| web.hook.pool_size                       | Integer | *连接池大小 （默认: 32 ）*.                                   |
| web.hook.rule.client.connack.\<No\>      | String  | 示例: <br>*web.hook.rule.client.connack.1={"action": "on_client_connack"}* |
| web.hook.rule.client.disconnected.\<No\> | String  | *示例: <br/>web.hook.rule.client.disconnected.1={"action": "on_client_disconnected"}* |
| web.hook.rule.message.publish.\<No\>     | String  | 示例: <br/>*web.hook.rule.message.publish.1={"action": "on_message_publish"}* <br>*web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "topic/1/2"}* <br>*web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}* |

## HTTP 身份验证配置

| 参数名                              | 数据类型 | 参数说明                                                     | 默认                                                         |
| ----------------------------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth.http.enable                    | Boolean  | 启动 HTTP 认证                                               | `false`                                                      |
| auth.http.auth_req.url              | String   | 认证请求的目标 URL。                                         | `http://127.0.0.1:80/mqtt/auth`                              |
| auth.http.auth_req.method           | Enum     | 认证请求的请求方法。<br>(`POST`  , `GET`)                    | `POST`                                                       |
| auth.http.auth_req.headers.\<Any\>  | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。<br> | `auth.http.auth_req.headers.content-type = application/x-www-form-urlencoded` <br/>`auth.http.auth_req.headers.accept = */*` |
| auth.http.auth_req.params           | String   | 指定认证请求中携带的数据。<br>以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br> 使用 **GET** 方法时 `auth.http.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth.http.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br>`%u: 用户名`<br>`%c: MQTT Client ID`<br>`%a: 客户端的网络 IP 地址`<br>`%r: 客户端使用的协议，可以是： mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br>`%P: 密码`<br>`%p: 客户端连接的服务端端口`<br>`%C: 客户端证书中的 Common Name`<br>`%d: 客户端证书中的 Subject` | `clientid=%c,username=%u,password=%P`                        |
| auth.http.super_req.url             | String   | 指定超级用户认证请求的目标 URL。                             | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth.http.super_req.method          | String   | 指定超级用户认证请求的请求方法。<br>(`POST`  , `GET`)        | `POST`                                                       |
| auth.http.super_req.headers.\<Any\> | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth.http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http.super_req.headers.accept = */*` |
| auth.http.super_req.params          | String   | 指定超级用户认证请求中携带的数据。<br>使用 **GET** 方法时 `auth.http.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth.http.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符同 `auth.http.auth_req.params`。 | `clientid=%c,username=%u`                                    |
| auth.http.acl_req.url               | String   | 指定 ACL 验证请求的目标 URL。                                | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth.http.acl_req.method            | String   | 指定 ACL 验证请求的请求方法。(`POST`  , `GET`)               | `POST`                                                       |
| auth.http.acl_req.headers.\<Any\>   | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth.http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http.super_req.headers.accept = */*` |
| auth.http.acl_req.params            | String   | 指定 ACL 验证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br/> 使用 **GET** 方法时 `auth.http.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br/>使用 **POST** 方法时 `auth.http.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br/>`%A: 需要验证的权限， 1 表示订阅， 2 表示发布`<br>`%u: 用户名`<br/>`%c: MQTT Client ID`<br/>`%a: 客户端的网络 IP 地址`<br/>`%r: 客户端使用的协议，可以是： mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br/>`%m: 挂载点`<br>`%t: 主题` | `access=%A,username=%u,clientid=%c,ipaddr=%a,topic=%t,mountpoint=%m` |
| auth.http.timeout                   | Integer  | HTTP 请求超时时间。任何等价于 `0s` 的设定值都表示永不超时。  | `5s`                                                         |
| auth.http.connect_timeout           | Integer  | HTTP 请求的连接超时时间。任何等价于 `0s` 的设定值都表示永不超时。 | `5s`                                                         |
| auth.http.ssl.cacertfile            | String   | CA 证书文件路径。                                            | `etc/certs/ca.pem`                                           |
| auth.http.ssl.certfile              | String   | 客户端证书文件路径。                                         | `etc/certs/client-cert.pem`                                  |
| auth.http.ssl.keyfile               | String   | 客户端私钥文件路径。                                         | `etc/certs/client.key.pem`                                   |


## 规则引擎配置

| 参数名                         | 数据类型 | 参数说明                                                                           |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule_option                   | Enum    | 规则引擎开关, 当时用规则引擎进行持久化，必须设置该选项为 ON。                              |
| rule_option.sqlite            | Enum    | 规则引擎插件开关 (enable/disable)                                                   |
| rule_option.repub             | Enum    | 规则引擎 repub 选项 (enable/disable)                                               |
| rule_option.mysql             | Enum    | 规则引擎 mysql 选项 (enable/disable)                                               |

### SQLite 规则配置

| 参数名                         | 数据类型 | 参数说明                                                                           |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.sqlite.path              | String  | 规则引擎 SQLite3 数据库路径, 默认是 /tmp/rule_engine.db                              |
| rule.sqlite.%d.table          | String  | 规则引擎 SQLite3 数据库表名, '%d' 是占位符                                            |
| rule.sqlite.event.publish.%d.sql     | String  | 规则引擎 sql 语句, '%d' 是占位符                                                     |

### MySQL 规则配置

| 参数名                         | 数据类型 | 参数说明                                                                           |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.mysql.name               | String  | 规则引擎 mysql 数据库名字, 默认是 mysql_rule_db                                      |
| rule.mysql.%d.table           | String  | 规则引擎 mysql 数据库表名字, '%d' 是占位符                                            |
| rule.mysql.%d.host            | String  | 规则引擎 mysql 数据库主机名 '%d' 是占位符                                             |
| rule.mysql.%d.username        | String  | 规则引擎 mysql 数据库用户名, '%d' 是占位符                                            |
| rule.mysql.%d.password        | String  | 规则引擎 mysql 数据库密码, '%d' 是占位符                                              |
| rule.mysql.event.publish.%d.sql     | String  | 规则引擎 sql 语句, '%d' 是占位符                                                     |


### Repub 规则配置

| 参数名                         | 数据类型 | 参数说明                                                                           |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.repub.%d.address         | String  | 规则引擎重新发布地址 (mqtt-tcp://host:port), '%d' 是占位符                            |
| rule.repub.%d.topic           | String  | 规则引擎重新发布主题, '%d' 是占位符                                                   |
| rule.repub.%d.username        | String  | 规则引擎重新发布用户名, '%d' 是占位符                                                 |
| rule.repub.%d.password        | String  | 规则引擎重新发布密码, '%d' 是占位符                                                   |
| rule.repub.%d.proto_ver       | Integer | 规则引擎重新发布协议版本, 默认是 4, '%d' 是占位符                                       |
| rule.repub.%d.clientid        | String  | 规则引擎重新发布客户端标识符, '%d' 是占位符                                             |
| rule.repub.%d.keepalive       | Integer | 规则引擎重新发布保活时间, 默认值是 60, '%d' 是占位符                                     |
| rule.repub.%d.clean_start     | Boolean | 规则引擎重新发布 clean_start 标志, 默认是 true ，'%d' 是占位符                           |
| rule.repub.event.publish.%d.sql     | String  | 规则引擎 sql 语句, '%d' 是占位符                                                     |
