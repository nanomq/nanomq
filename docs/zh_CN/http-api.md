# HTTP API

NanoMQ 提供了 HTTP API 以实现与外部系统的集成，例如查询 broker 统计信息、客户端信息、发布消息，订阅主题信息和远程修改配置/重启等。

NanoMQ 的 HTTP API 服务默认监听 8081 端口。可通过 `etc/nanomq.conf` 配置文件修改监听端口，所有 API 调用均以 `api/v1` 开头。

## 接口安全

NanoMQ 的 HTTP API 使用 [Basic 认证](https://en.wikipedia.org/wiki/Basic_access_authentication)或[JWT 认证](https://jwt.io/introduction)方式。`username` 和 `password` 须分别填写。 默认的`username` 和 `password` 是：`admin/public`。 可通过 `etc/nanomq.conf` 配置文件修改 `username` 和 `password` 。



## 响应码

### HTTP 状态码 (status codes)

NanoMQ 接口在调用成功时总是返回 200 OK，响应内容则以 JSON 格式返回。

可能的状态码如下：

| Status Code | Description                                              |
| ----------- | -------------------------------------------------------- |
| 200         | 成功，返回的 JSON 数据将提供更多信息                     |
| 400         | 客户端请求无效，例如请求体或参数错误                     |
| 401         | 客户端未通过服务端认证，使用无效的身份验证凭据可能会发生 |
| 404         | 找不到请求的路径或者请求的对象不存在                     |
| 500         | 服务端处理请求时发生内部错误                             |

### 返回码 (result codes)

NanoMQ 接口的响应消息体为 JSON 格式，其中总是包含返回码 `code`。

可能的返回码如下：

| Return Code | Description                |
| ----------- | -------------------------- |
| 0           | 成功                       |
| 101         | RPC 错误                   |
| 102         | 未知错误                   |
| 103         | 用户名或密码错误           |
| 104         | 空用户名或密码             |
| 105         | 用户不存在                 |
| 106         | 管理员账户不可删除         |
| 107         | 关键请求参数缺失           |
| 108         | 请求参数错误               |
| 109         | 请求参数不是合法 JSON 格式 |
| 110         | 插件已开启                 |
| 111         | 插件已关闭                 |
| 112         | 客户端不在线               |
| 113         | 用户已存在                 |
| 114         | 旧密码错误                 |
| 115         | 不合法的主题               |
| 116         | Token已过期               |



## API Endpoints 

### GET /api/v4

返回 EMQX 支持的所有 Endpoints。

**Parameters:** 无

**Success Response Body (JSON):**

| Name             | Type    | Description    |
| ---------------- | ------- | -------------- |
| code             | Integer | 0              |
| data             | Array   | Endpoints 列表 |
| - data[0].path   | String  | Endpoint       |
| - data[0].name   | String  | Endpoint 名    |
| - data[0].method | String  | HTTP Method    |
| - data[0].descr  | String  | 描述           |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4"

{"code":0,"data":[{"path":"/brokers/","name":"list_brokers","method":"GET","descr":"A list of brokers in the cluster"},{"path":"/nodes/","name":"list_nodes","method":"GET","descr":"A list of nodes in the cluster"},{"path":"/clients/","name":"list_clients","method":"GET","descr":"A list of clients on current node"},{"path":"/clients/:clientid","name":"lookup_client","method":"GET","descr":"Lookup a client in the cluster"},{"path":"/clients/username/:username","name":"lookup_client_via_username","method":"GET","descr":"Lookup a client via username in the cluster"},{"path":"/subscriptions/","name":"list_subscriptions","method":"GET","descr":"A list of subscriptions in the cluster"},{"path":"/subscriptions/:clientid","name":"lookup_client_subscriptions","method":"GET","descr":"A list of subscriptions of a client"},{"path":"/topic-tree/","name":"list_topic-tree","method":"GET","descr":"A list of topic-tree in the cluster"},{"path":"/configuration/","name":"get_broker_configuration","method":"GET","descr":"show broker configuration"},{"path":"/configuration/","name":"set_broker_configuration","method":"POST","descr":"set broker configuration"},{"path":"/ctrl/:action","name":"ctrl_broker","method":"POST","descr":"Control broker stop or restart"}]}
```



## Broker 基本信息

### GET /api/v4/brokers

返回Broker的基本信息。

**Success Response Body (JSON):**

| Name                 | Type                    | Description                                            |
| -------------------- | ----------------------- | ------------------------------------------------------ |
| code                 | Integer                 | 0                                                      |
| data                 | Object/Array of Objects | 返回所有节点的信息*(只有一个节点，nanomq暂不支持集群)* |
| data.datetime        | String                  | 当前时间，格式为 "YYYY-MM-DD HH:mm:ss"                 |
| data.node_status     | String                  | 节点状态                                               |
| data.sysdescr        | String                  | 软件描述                                               |
| data.uptime          | String                  | NanoMQ运行时间，格式为 "H hours, m minutes, s seconds" |
| data.version         | String                  | NanoMQ 版本                                            |

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/brokers"

{"code":0,"data":[{"datetime":"2022-06-07 10:02:24","node_status":"Running","sysdescr":"NanoMQ Broker","uptime":"15 Hours, 1 minutes, 38 seconds","version":"0.7.9-3"}]}
```



## 节点

### GET /api/v4/nodes

返回节点的状态。

**Success Response Body (JSON):**

| Name                       | Type                    | Description                                                  |
| -------------------------- | ----------------------- | ------------------------------------------------------------ |
| code                       | Integer                 | 0                                                            |
| data                       | Object/Array of Objects | node 参数存在时返回指定节点信息， 不存在时以 Array 形式返回所有节点的信息 |
| data.connections           | Integer                 | 当前接入此节点的客户端数量                                   |
| data.node_status           | String                  | 节点状态                                                     |
| data.uptime                | String                  | NanoMQ 运行时间                                              |
| data.version               | String                  | NanoMQ 版本                                                  |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/nodes"

{"code":0,"data":[{"connections":0,"node_status":"Running","uptime":"15 Hours, 22 minutes, 4 seconds","version":"0.8.1"}]}
```



## 客户端

### GET /api/v4/clients

支持多条件查询，其包含的查询参数有：

| Name                     | Type        | Required  | Description                                                  |
| ------------------------ | ----------- | --------- | ------------------------------------------------------------ |
| clientid                 | String      | False     | 客户端标识符                                                 |
| username                 | String      | False     | 客户端用户名                                                 |
| conn_state               | Enum        | False     | 客户端当前连接状态， 可取值有：connected,idle,disconnected   |
| clean_start              | Bool        | False     | 客户端是否使用了全新的会话                                   |
| proto_name               | Enum        | False     | 客户端协议名称， 可取值有：MQTT,CoAP,LwM2M,MQTT-SN           |
| proto_ver                | Integer     | False     | 客户端协议版本                                               |

**Success Response Body (JSON):**

| Name                          | Type             | Description                                                  |
| ----------------------------- | ---------------- | ------------------------------------------------------------ |
| code                          | Integer          | 0                                                            |
| data                          | Array of Objects | 所有客户端的信息                                             |
| data[0].clientid              | String           | 客户端标识符                                                 |
| data[0].username              | String           | 客户端连接时使用的用户名                                     |
| data[0].proto_name            | String           | 客户端协议名称 *(MQTT,CoAP,LwM2M,MQTT-SN)*                   |
| data[0].proto_ver             | Integer          | 客户端使用的协议版本                                         |
| data[0].port                  | Integer          | 客户端的端口                                                 |
| data[0].connected             | Boolean          | 客户端是否处于连接状态                                       |
| data[0].keepalive             | Integer          | 保持连接时间，单位：秒                                       |
| data[0].clean_start           | Boolean          | 指示客户端是否使用了全新的会话                               |
| data[0].send_msg              | Integer          | 发送的 PUBLISH 报文数量                                      |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients"

{"code":0,"data":[{"client_id":"nanomq-f6d6fbfb","username":"alvin","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5,"recv_msg":3},{"client_id":"nanomq-bdf61d9b","username":"nanomq","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5,"recv_msg":0}]}
```

### GET /api/v4/clients/{clientid}

返回指定客户端的信息

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| clientid | String | True     | ClientID    |

**Success Response Body (JSON):**

| Name | Type             | Description                                                  |
| ---- | ---------------- | ------------------------------------------------------------ |
| code | Integer          | 0                                                            |
| data | Array of Objects | 客户端的信息，详细请参见 *GET /api/v4/clients* |

**Examples:**

查询指定客户端

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients/nanomq-29978ec1"

{"code":0,"data":[{"client_id":"nanomq-29978ec1","username":"","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5}]}
```



### GET /api/v4/clients/username/{username}

通过 Username 查询客户端的信息。由于可能存在多个客户端使用相同的用户名的情况，所以可能同时返回多个客户端信息。

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| username | String | True     | Username    |

**Success Response Body (JSON):**

| Name | Type             | Description                                    |
| ---- | ---------------- | ---------------------------------------------- |
| code | Integer          | 0                                              |
| data | Array of Objects | 客户端的信息，详细请参见 *GET /api/v4/clients* |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients/username/user001"

{"code":0,"data":[{"client_id":"nanomq-56baa74d","username":"user001","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5}]}
```



## 订阅信息

### GET /api/v4/subscriptions

支持多条件查询：

| Name             | Type       | Description           |
| ---------------- | ---------- | --------------------- |
| clientid         | String     | 客户端标识符          |
| topic            | String     | 主题，全等查询        |
| qos              | Enum       | 可取值为：`0`,`1`,`2` |
| share            | String     | 共享订阅的组名称      |

**Success Response Body (JSON):**

| Name             | Type             | Description              |
| ---------------- | ---------------- | ------------------------ |
| code             | Integer          | 0                        |
| data             | Array of Objects | 所有订阅信息             |
| data[0].clientid | String           | 客户端标识符             |
| data[0].topic    | String           | 订阅主题                 |
| data[0].qos      | Integer          | QoS 等级                 |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/subscriptions"

{"code":0,"data":[{"clientid":"nanomq-29978ec1","topic":"topic123","qos":2},{"clientid":"nanomq-3020ffac","topic":"topic123","qos":2}]}
```



### GET /api/v4/subscriptions/{clientid}

返回指定客户端的订阅信息。

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| clientid | String | True     | ClientID    |

**Success Response Body (JSON):**

| Name          | Type       | Description  |
| ------------- | ---------- | ------------ |
| code          | Integer    | 0            |
| data          | Object     | 所有订阅信息 |
| data.clientid | String     | 客户端标识符 |
| data.topic    | String     | 订阅主题     |
| data.qos      | Integer    | QoS 等级     |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/subscriptions/123"

{"data":[{"topic":"a/b/c","qos":1,"clientid":"123"}],"code":0}
```



## 主题树结构

### GET /api/v4/topic-tree

**Success Response Body (JSON):**

| Name             | Type             | Description      |
| ---------------- | ---------------- | ---------------- |
| code             | Integer          | 0                |
| data             | Array of Objects | 所有订阅信息     |
| data[0].clientid | Array of String  | 客户端标识符数组 |
| data[0].topic    | String           | 订阅主题         |
| data[0].cld_cnt  | Integer          | 子节点个数       |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/topic-tree"

{"code":0,"data":[[{"topic":"","cld_cnt":1}],[{"topic":"topic123","cld_cnt":1,"clientid":["nanomq-3a4a0956"]}],[{"topic":"123","cld_cnt":1,"clientid":["nanomq-0cfd69bb"]}],[{"topic":"456","cld_cnt":0,"clientid":["nanomq-26971dc8"]}]]}
```



## 获取当前配置

### GET /api/v4/configuration

 返回当前broker所有配置参数。

**Success Response Body (JSON):**

| Name                              | Type          | Description                                                  |
| ---------------------             | -------       | ------------------------------------------------------------ |
| code                              | Integer       | 0                                                            |
| seq                               | Integer       | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |
| rep                               | Integer       | rep 是 11 作为 req 11 的响应。                               |
| data.url                          | String        | 监听url。                                                    |
| data.num_taskq_thread             | Integer       | 任务线程数。 |
| data.max_taskq_thread             | Integer       | 最大任务线程数。 |
| data.parallel                     | Long          | 并行数。 |
| data.property_size                | Integer       | 最大属性长度。 |
| data.msq_len                      | Integer       | 队列长度。 |
| data.qos_duration                 | Integer       | QOS消息定时间隔时间。 |
| data.allow_anonymous              | Boolean       | 允许匿名登录。 |
| data.tls.enable                   | Boolean       | 启动TLS监听。 |
| data.tls.url                      | String        | TLS监听URL。 |
| data.tls.key                      | String        | TLS私钥数据。 |
| data.tls.keypass                  | String        | TLS私钥密码。 |
| data.tls.cert                     | String        | TLS Cert证书数据。 |
| data.tls.cacert                   | String        | TLS CA证书数据。|
| data.tls.verify_peer              | Boolean       | 验证客户端证书 |
| data.tls.fail_if_no_peer_cert     | Boolean       | 拒绝无证书连接，与_.tls.verify_peer_配合使用。 |
| data.websocket.enable             | Boolean       | 启动websocket监听。 |
| data.websocket.url                | String        | Websocket监听URL。 |
| data.websocket.tls_url            | String        | TLS over Websocket监听URL。 |
| data.http_server.enable           | Boolean       | 启动Http服务监听。 |
| data.http_server.port             | Integer       | Http服务端监听端口。 |
| data.http_server.username         | String        | 访问Http服务用户名。 |
| data.http_server.password         | String        | 访问Http服务密码。 |
| data.bridge.bridge_mode           | Boolean       | 启动桥接功能。  |
| data.bridge.address               | String        | 桥接目标broker地址。|
| data.bridge.proto_ver             | String        | 桥接客户端MQTT版本（3｜4｜5）。 |
| data.bridge.clientid              | String        | 桥接客户端ID。（NULL为自动生成随机ID） |
| data.bridge.keepalive             | Integer       | 保活间隔时间。 |
| data.bridge.clean_start           | Boolean       | 清除会话。 |
| data.bridge.parallel              | Long          | 桥接客户端并发数。 |
| data.bridge.username              | String        | 登录用户名。 |
| data.bridge.password              | String        | 登录密码。 |
| data.bridge.forwards              | Array[String] | 转发Topic数组。 |
| data.bridge.forwards[0]           | String        | 转发Topic。 |
| data.bridge.subscription          | Array[Object] | 订阅信息数组。                                               |
| data.bridge.subscription[0].topic | String        | 订阅Topic。                                                  |
| data.bridge.subscription[0].qos   | Integer       | 订阅消息质量Qos。 |

**Examples:**

```shell
$ curl -i --basic -u admin:public -X GET 'http://127.0.0.1:8081/api/v4/configuration' 
{
    "code": 0,
    "data": {
        "url": "nmq-tcp://0.0.0.0:1883",
        "num_taskq_thread": 4,
        "max_taskq_thread": 4,
        "parallel": 32,
        "property_size": 32,
        "msq_len": 64,
        "allow_anonymous": true,
        "daemon": false,
        "tls": {
            "enable": false,
            "url": "tls+nmq-tcp://0.0.0.0:8883",
            "key_password": null,
            "key": null,
            "cert": null,
            "cacert": null,
            "verify_peer": false,
            "fail_if_no_peer_cert": false
        },
        "websocket": {
            "enable": true,
            "url": "nmq-ws://0.0.0.0:8083/mqtt",
            "tls_url": "nmq-wss://0.0.0.0:8084/mqtt"
        },
        "http_server": {
            "enable": true,
            "port": 8081,
            "username": "admin",
            "password": "public",
            "auth_type": "basic"
        },
        "bridge": {
            "bridge_mode": false,
            "address": "mqtt-tcp://broker.emqx.io:1883",
            "proto_ver": 4,
            "clientid": "bridge_client",
            "clean_start": true,
            "username": "username",
            "password": "passwd",
            "keepalive": 60,
            "parallel": 2,
            "forwards": [
                "topic1/#",
                "topic2/#"
            ],
            "subscription": [
                {
                    "topic": "cmd/topic1",
                    "qos": 1
                },
                {
                    "topic": "cmd/topic2",
                    "qos": 2
                }
            ]
        }
    }
}
```



## 设置配置参数

### POST /api/v4/configuration

设置broker配置参数。

**Parameters (json):**

| Name | Type   | Required | Value | Description                           |
| ---- | ------ | -------- | ----- | ------------------------------------- |
| data | Object | Required |       | 同获取配置一致[data](#获取当前配置)。 |

**Success Response Body (JSON):**

| Name | Type    | Description |
| ---- | ------- | ----------- |
| code | Integer | 0           |

**Examples:**

```shell
$ curl -i --basic -u admin:public -X POST 'http://localhost:8081/api/v4/configuration' -d \
'{
   "data": {
        "url": "nmq-tcp://0.0.0.0:1883",
        "num_taskq_thread": 8,
        "max_taskq_thread": 4,
        "parallel": 32,
        "property_size": 32,
        "msq_len": 64,
        "allow_anonymous": true,
        "daemon": false,
        "tls": {
            "enable": false,
            "url": "nmq-tls://0.0.0.0:8883",
            "key_password": null,
            "key": null,
            "cert": null,
            "cacert": null,
            "verify_peer": false,
            "fail_if_no_peer_cert": false
        },
        "websocket": {
            "enable": true,
            "url": "nmq-ws://0.0.0.0:8083/mqtt",
            "tls_url": "nmq-wss://0.0.0.0:8084/mqtt"
        },
        "http_server": {
            "enable": true,
            "port": 8081,
            "username": "admin",
            "password": "public",
            "auth_type": "basic"
        },
        "bridge": {
            "bridge_mode": false,
            "address": "127.0.0.1:1883",
            "proto_ver": 4,
            "clientid": "bridge_client",
            "clean_start": true,
            "username": "user",
            "password": "passwd",
            "keepalive": 60,
            "parallel": 1,
            "forwards": [
                "topic1/#",
                "topic2/#"
            ],
            "subscription": [
                {
                    "topic": "cmd/topic1",
                    "qos": 1
                }
            ]
        }
    }
}'

{"code":0}
```



## Broker控制

### POST /api/v4/ctrl/{action}

控制broker停止或重启（通常应用在修改配置后）

**Path Parameters:**

| Name     | Type   | Required | Description             |
| -------- | ------ | -------- | ----------------------- |
| clientid | String | True     | 可取值:  stop,  restart |

**Success Response Body (JSON):**

| Name | Type    | Description |
| ---- | ------- | ----------- |
| code | Integer | 0           |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X POST 'http://localhost:8081/api/v4/restart'

{"code":0}
```
