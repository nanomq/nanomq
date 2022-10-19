# 配置说明

## 简介

NanoMQ 的配置文件格式是 HOCON 。 HOCON（Human-Optimized Config Object Notation）是一个JSON的超集，非常适用于易于人类读写的配置数据存储。你可以在 etc 目录找到这些配置文件，主要配置文件包括：

| 配置文件                | 说明                |
| ----------------------- | ------------------- |
| etc/nanomq.conf         | NanoMQ 配置文件     |
| etc/nanomq_gateway.conf | NanoMQ 网关配置文件 |

## 配置文件语法
在配置文件中，值可以被记为类似JSON的对象，例如

```
websocket {
     enable=false
     url="nmq-ws://0.0.0.0:8083/mqtt"
     tls_url="nmq-wss://0.0.0.0:8084/mqtt"
}
```

另一种等价的表示方法是扁平的，例如

```
websocket.enable = false
websocket.url="nmq-ws://0.0.0.0:8083/mqtt"
websocket.tls_url="nmq-wss://0.0.0.0:8084/mqtt"
```

这种扁平格式几乎与NanoMQ的配置文件格式向后兼容（所谓的'cuttlefish'格式）。

它并不是完全兼容，因为HOCON经常要求字符串两端加上引号。
而cuttlefish把`=`符右边的所有字符都视为值。

例如，cuttlefish：`websocket.url = nmq-ws://0.0.0.0:8083/mqtt`，HOCON：`websocket.url = "nmq-ws://0.0.0.0:8083/mqtt"`。
### 配置重载规则
HOCON的值是分层覆盖的，普遍规则如下：

- 在同一个文件中，后（在文件底部）定义的值，覆盖前（在文件顶部）到值。
- 当按层级覆盖时，高层级的值覆盖低层级的值。

结下来的文档将解释更详细的规则。

合并覆盖规则。在如下配置中，最后一行的 `debug` 值会覆盖覆盖原先 `level` 字段的 `error` 值，但是 `to` 字段保持不变。
```
log {
    to=["file","console"]
    level="error"
}

## 控制台日志打印先定义为 `error` 级别，后被覆写成 `debug` 级别

log.level="debug"
```



## 参数说明

### nanomq.conf

#### 基本配置参数

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
| http_server.auth_type | String | Http鉴权方式。（*默认 basic*） |
| http_server.jwt.public.keyfile | String |*JWT* 公钥文件. |
| http_server.jwt.private.keyfile | String |*JWT* 私钥文件. |
| log.to | Array[String] |日志输出类型数组，使用逗号`,`分隔多种类型<br>支持*文件，控制台，Syslog输出*，对应参数: <br>*file, console, syslog* |
| log.level | String |日志等级：trace, debug, info, warn, error, fatal |
| log.dir | String |日志文件存储路径 (输出文件时生效) |
| log.file | String |日志文件名(输出文件时生效) |
| log.rotation.size | String | 每个日志文件的最大占用空间; <br>支持单位: `KB | MB | GB`;<br> 默认: `10MB` |
| log.rotation.count | Integer | 轮换的最大日志文件数; <br>默认: `5` |

#### 标准MQTT桥接配置参数

| 参数名                  | 数据类型    | 参数说明                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| bridge.mqtt.nodes[0].name | String | 节点名字。 |
| bridge.mqtt.nodes[0].enable | Boolean | 启动桥接功能（*默认`false`不启用*）。 |
| bridge.mqtt.nodes[0].address | String | 桥接目标broker地址URL。 |
| bridge.mqtt.nodes[0].proto_ver | Integer | 桥接客户端MQTT版本（3｜4｜5）。 |
| bridge.mqtt.nodes[0].clientid | String | 桥接客户端ID（*默认NULL为自动生成随机ID*）。 |
| bridge.mqtt.nodes[0].keepalive | Integer | 保活间隔时间。 |
| bridge.mqtt.nodes[0].clean_start | Boolean | 清除会话。 |
| bridge.mqtt.nodes[0].parallel | Long | 桥接客户端并发数。 |
| bridge.mqtt.nodes[0].username | String | 登录用户名。 |
| bridge.mqtt.nodes[0].password | String | 登录密码。 |
| bridge.mqtt.nodes[0].forwards | Array[String] | 转发Topic数组, 使用逗号`,`分隔多个`Topic`。 |
| bridge.mqtt.nodes[0].subscription[0].topic | String | 第1个订阅`Topic`。                               |
| bridge.mqtt.nodes[0].subscription[0].qos | Integer | 第1个订阅`Qos`。                       |
| bridge.mqtt.nodes[0].tls.enable | Boolean | 启动TLS监听（*默认false*）。 |
| bridge.mqtt.nodes[0].tls.key_password | String | TLS私钥密码。 |
| bridge.mqtt.nodes[0].tls.keyfile | String | TLS私钥数据。 |
| bridge.mqtt.nodes[0].tls.certfile |String  | TLS Cert证书数据。 |
| bridge.mqtt.nodes[0].tls.cacertfile | String | TLS CA证书数据。|


#### Aws IoT Core MQTT桥接配置参数

| 参数名                           | 数据类型      | 参数说明                                     |
| -------------------------------- | ------------- | -------------------------------------------- |
| bridge.aws.nodes[0].name | Boolean | 节点名字。 |
| bridge.aws.nodes[0].enable               | Boolean       | 启动桥接功能（*默认`false`不启用*）。        |
| bridge.aws.nodes[0].host                 | String        | AWS IoT Core服务地址。                       |
| bridge.aws.nodes[0].port                 | Integer       | AWS IoT Core MQTT端口。                      |
| bridge.aws.nodes[0].clientid             | String        | 桥接客户端ID（*默认NULL为自动生成随机ID*）。 |
| bridge.aws.nodes[0].keepalive            | Integer       | 保活间隔时间。                               |
| bridge.aws.nodes[0].clean_start          | Boolean       | 清除会话。                                   |
| bridge.aws.nodes[0].parallel             | Long          | 桥接客户端并发数。                           |
| bridge.aws.nodes[0].username             | String        | 登录用户名。                                 |
| bridge.aws.nodes[0].password             | String        | 登录密码。                                   |
| bridge.aws.nodes[0].forwards             | Array[String] | 转发Topic数组, 使用逗号`,`分隔多个`Topic`。  |
| bridge.aws.nodes[0].subscription[0].topic | String | 第1个订阅`Topic`。                               |
| bridge.aws.nodes[0].subscription[0].qos | Integer | 第1个订阅`Qos`。                       |
| bridge.aws.nodes[0].tls.enable | Boolean | 启动TLS监听（*默认false*）。 |
| bridge.aws.nodes[0].tls.key_password | String | TLS私钥密码。 |
| bridge.aws.nodes[0].tls.keyfile | String | TLS私钥数据。 |
| bridge.aws.nodes[0].tls.certfile |String  | TLS Cert证书数据。 |
| bridge.aws.nodes[0].tls.cacertfile | String | TLS CA证书数据。|

#### 用户登陆验证配置

| 参数名          | 数据类型 | 参数说明                        |
| --------------- | -------- | ---------------------------- |
| auth[0].login    | String   | 登录用户名。                  |
| auth[0].password | String   | 登录密码。                    |

#### WebHook配置

| 参数名                                    | 数据类型 | 参数说明                                                    |
| ---------------------------------------- | ------- | ------------------------------------------------------------ |
| webhook.enable                          | Boolean | 启动WebHook (默认: `false`)                                  |
| webhook.url                             | String  | *Webhook URL*                                                |
| webhook.headers.\<Any\>                 | String  | *HTTP Headers*<br>*Example:*<br>*1. webhook.headers.content-type=application/json*<br> *2. webhook.headers.accept=\** |
| webhook.body.encoding                   | String  | *Payload编码方式*<br>Options: <br>plain \| base64 \| base62  |
| webhook.pool_size                       | Integer | *连接池大小 （默认: 32）*.                                   |
| webhook.rule.client.connack.\<No\>      | String  | 示例: <br>*webhook.rule.client.connack=[{"action": "on_client_connack"}]* |
| webhook.rule.client.disconnected.\<No\> | String  | *示例: <br/>webhook.rule.client.disconnected=[{"action": "on_client_disconnected"}]* |
| webhook.rule.message.publish.\<No\>     | String  | 示例: <br/>*webhook.rule.message.publish=[{"action": "on_message_publish"}]* <br>*webhook.rule.message.publish=[{"action": "on_message_publish"}, {"topic": "topic/1/2"}]* <br>*webhook.rule.message.publish = [{"action": "on_message_publish"}, {"topic": "foo/#"}]* |

#### HTTP身份验证配置

| 参数名                              | 数据类型 | 参数说明                                                     | 默认                                                         |
| ----------------------------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth_http.enable                    | Boolean  | 启动HTTP认证                                                 | `false`                                                      |
| auth_http.auth_req.url              | String   | 认证请求的目标 URL。                                         | `http://127.0.0.1:80/mqtt/auth`                              |
| auth_http.auth_req.method           | String     | 认证请求的请求方法。<br>(`POST`  , `GET`)                    | `POST`                                                       |
| auth_http.auth_req.headers.\<Any\>  | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。<br> | `auth_http.auth_req.headers.content-type = application/x-www-form-urlencoded` <br/>`auth_http.auth_req.headers.accept = */*` |
| auth_http.auth_req.params        | Array[Object]  | 指定认证请求中携带的数据。<br>以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br> 使用 **GET** 方法时 `auth_http.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth_http.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br>`%u: 用户名`<br>`%c: MQTT Client ID`<br>`%a: 客户端的网络 IP 地址`<br>`%r: 客户端使用的协议，可以是：mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br>`%P: 密码`<br>`%p: 客户端连接的服务端端口`<br>`%C: 客户端证书中的 Common Name`<br>`%d: 客户端证书中的 Subject` | `auth_http.auth_req.params = {clientid= "%c", username= "%u", password= "%P"}`                        |
| auth_http.super_req.url             | String   | 指定超级用户认证请求的目标 URL。                             | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth_http.super_req.method          | String   | 指定超级用户认证请求的请求方法。<br>(`POST`  , `GET`)        | `POST`                                                       |
| auth_http.super_req.headers.\<Any\> | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth_http.super_req.headers.accept = */*` |
| auth_http.super_req.params          |Array[Object]    | 指定超级用户认证请求中携带的数据。<br>使用 **GET** 方法时 `auth_http.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth_http.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符同 `auth_http.auth_req.params`。 | `auth_http.super_req.params = {clientid= "%c", username= "%u", password= "%P"}`                                    |
| auth_http.acl_req.url               | String   | 指定 ACL 验证请求的目标 URL。                                | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth_http.acl_req.method            | String   | 指定 ACL 验证请求的请求方法。(`POST`  , `GET`)               | `POST`                                                       |
| auth_http.acl_req.headers.\<Any\>   | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth_http.super_req.headers.accept = */*` |
| auth_http.acl_req.params            | Array[Object]   | 指定 ACL 验证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br/> 使用 **GET** 方法时 `auth_http.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br/>使用 **POST** 方法时 `auth_http.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br/>`%A: 需要验证的权限，1 表示订阅，2 表示发布`<br>`%u: 用户名`<br/>`%c: MQTT Client ID`<br/>`%a: 客户端的网络 IP 地址`<br/>`%r: 客户端使用的协议，可以是：mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br/>`%m: 挂载点`<br>`%t: 主题` | `auth_http.acl_req.params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}` |
| auth_http.timeout                   | Integer  | HTTP 请求超时时间。任何等价于 `0s` 的设定值都表示永不超时。  | `5s`                                                         |
| auth_http.connect_timeout           | Integer  | HTTP 请求的连接超时时间。任何等价于 `0s` 的设定值都表示永不超时。 | `5s`                                                         |


#### 规则引擎配置

| 参数名                         | 数据类型 | 参数说明                                                      |
| ------------------------------| ------- | ----------------------------------------------------------- |
| rule.option                   | String  | 规则引擎开关, 当时用规则引擎进行持久化，必须设置该选项为 ON。         |

#### SQLITE规则配置

| 参数名                         | 数据类型 | 参数说明                                                       |
| ------------------------------| ------- | ------------------------------------------------------------ |
| rule.sqlite.path              | String  | 规则引擎 SQLite3 数据库路径, 默认是 /tmp/rule_engine.db          |
| rule.sqlite.enabled           | Boolen  | 规则引擎 SQLite3 数据库开关状态, 默认是 true                      |
| rule.sqlite.rules[0].enabled  | Boolen  | 规则引擎 SQLite3 数据库当前规则开关状态, 默认是 true               |
| rule.sqlite.rules[0].table    | String  | 规则引擎 SQLite3 数据库表名                                     |
| rule.sqlite.rules[0].sql      | String  | 规则引擎 sql 语句                                              |

#### MYSQL规则配置

| 参数名                         | 数据类型 | 参数说明                                               |
| ------------------------------| ------- | ---------------------------------------------------- |
| rule.mysql.name               | String  | 规则引擎 mysql 数据库名字, 默认是 mysql_rule_db          |
| rule.mysql.enabled            | Boolen  | 规则引擎 mysql 数据库开关状态, 默认是 true                |
| rule.mysql.rules[0].enabled   | Boolen  | 规则引擎 mysql 数据库当前规则开关状态, 默认是 true         |
| rule.mysql.rules[0].table     | String  | 规则引擎 mysql 数据库表名字                             |
| rule.mysql.rules[0].host      | String  | 规则引擎 mysql 数据库主机名                             |
| rule.mysql.rules[0].username  | String  | 规则引擎 mysql 数据库用户                               |
| rule.mysql.rules[0].password  | String  | 规则引擎 mysql 数据库密                                |
| rule.mysql.rules[0].sql       | String  | 规则引擎 sql 语句                                     |


#### Repub规则配置

| 参数名                            | 数据类型 | 参数说明                                                |
| ---------------------------------| ------- | ----------------------------------------------------- |
| rule.repub.enabled               | Boolen  | 规则引擎 repub 开关状态, 默认是 true                      |
| rule.repub.rules[0].enabled      | Boolen  | 规则引擎 repub 当前规则开关状态, 默认是 true               |
| rule.repub.rules[0].address      | String  | 规则引擎重新发布地址 (mqtt-tcp://host:port)              |
| rule.repub.rules[0].topic        | String  | 规则引擎重新发布主题                                     |
| rule.repub.rules[0].username     | String  | 规则引擎重新发布用户名                                    |
| rule.repub.rules[0].password     | String  | 规则引擎重新发布密码                                     |
| rule.repub.rules[0].proto_ver    | Integer | 规则引擎重新发布协议版本, 默认是 4 .                       |
| rule.repub.rules[0].clientid     | String  | 规则引擎重新发布客户端标识符                               |
| rule.repub.rules[0].keepalive    | Integer | 规则引擎重新发布保活时间, 默认值是 60                       |
| rule.repub.rules[0].clean_start  | Boolean | 规则引擎重新发布 clean_start 标志, 默认是 true             |
| rule.repub.rules[0].sql          | String  | 规则引擎 sql 语句                                       |


### nanomq_gateway.conf

| 参数名                             | 数据类型  | 参数说明                                                |
| --------------------------------- | ------- | ------------------------------------------------------ |
| gateway.mqtt.address                   | String  | 远端 Broker 地址。                                  |
| gateway.mqtt.proto_ver                 | Integer | MQTT 客户端版本（3｜4｜5)。                          |
| gateway.mqtt.clientid                  | String  | MQTT 客户端标识符。                                  |
| gateway.mqtt.keepalive                 | Integer | 保活间隔时间。                                       |
| gateway.mqtt.clean_start               | Boolean | 清除会话标志。                                       |
| gateway.mqtt.parallel                  | Integer | 并行的 mqtt 客户端数量。                              |
| gateway.mqtt.username                  | String  | 登陆的用户名。                                       |
| gateway.mqtt.password                  | String  | 登陆的密码。                                         |
| gateway.mqtt.forward                   | String  | 转发的主题。                                         |
| gateway.mqtt.sub_topic                | String  | 订阅的 Mqtt 主题。                                   |
| gateway.mqtt.sub_qos                  | Integer | 订阅的 Mqtt 服务级别。                                |
| gateway.zmq.sub_address               | String  | 远端的 ZMQ 服务订阅地址。                              |
| gateway.zmq.pub_address               | String  | 远端的 ZMQ 服务发布地址。                              |
| gateway.zmq.sub_pre                   | String  | 远端的 ZMQ 服务订阅前缀。                              |
| gateway.zmq.pub_pre                   | String  | 远端的 ZMQ 服务发布前缀。                              |

