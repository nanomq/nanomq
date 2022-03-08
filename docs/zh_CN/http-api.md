# HTTP API

NanoMQ 提供了 HTTP API 以实现与外部系统的集成，例如查询 broker 统计信息、客户端信息、发布消息，订阅主题信息和远程修改配置/重启等。

NanoMQ 的 HTTP API 服务默认监听 8081 端口。可通过 `etc/nanomq.conf` 配置文件修改监听端口，所有 API 调用均以 `api/v1` 开头。

## 接口安全

NanoMQ 的 HTTP API 使用 [Basic 认证](https://en.wikipedia.org/wiki/Basic_access_authentication)方式。`username` 和 `password` 须分别填写。 默认的`username` 和 `password` 是：`admin/public`。 可通过 `etc/nanomq.conf` 配置文件修改 `username` 和 `password` 。

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

## API Endpoints | POST /api/v1

### NanoMQ 统计信息

返回 NanoMQ 的统计信息.

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 2      | req 是 2 调用 NanoMQ 获取统计信息的接口。                    |
| seq  | Integer | Required | unique | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |

**Success Response Body (JSON):**

| Name              | Type    | Description                                                  |
| ----------------- | ------- | ------------------------------------------------------------ |
| code              | Integer | 0                                                            |
| seq               | Integer | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |
| rep               | Integer | rep 是 2 作为 req 2 的响应。                                 |
| data.client_size  | Integer | 订阅客户端的数量。                                           |
| data.message_in   | Integer | NanoMQ 流入的消息数量。                                      |
| data.message_out  | Integer | NanoMQ 流出的消息数量。                                      |
| data.message_drop | Integer | NanoMQ 丢弃的消息数量。                                      |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 2,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":2,"data":{"client_size":1,"message_in":4,"message_out":0,"message_drop":4}}
```

### 主题信息

返回客户端标识符对应的主题和 qos 信息。

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 4      | req 是 4 调用 NanoMQ 获取主题信息的接口。                    |
| seq  | Integer | Required | unique | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |

**Success Response Body (JSON):**

| Name                           | Type    | Description                                                  |
| ------------------------------ | ------- | ------------------------------------------------------------ |
| code                           | Integer | 0                                                            |
| seq                            | Integer | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |
| rep                            | Integer | rep 是 4 作为 req 4 的响应。                                 |
| data[0].client_id              | String  | 客户端订阅标识符。                                           |
| data[0].subscriptions[0].topic | String  | 订阅的主题。                                                 |
| data[0].subscriptions[0].qos   | Integer | 订阅的 qos                                                   |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 4,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":4,"data":[{"client_id":"nanomq-ebd54382","subscriptions":[{"topic":"a/b/c","qos":0}]}]}
```

#### 客户端信息

返回所有的客户端信息。

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 5      | req 是 5 调用 NanoMQ 获取客户端信息的接口。                  |
| seq  | Integer | Required | unique | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |

**Success Response Body (JSON):**

| Name                    | Type    | Description                                                  |
| ----------------------- | ------- | ------------------------------------------------------------ |
| code                    | Integer | 0                                                            |
| seq                     | Integer | seq 是全局唯一的，请求/响应信息都会携带该信息，可以通过该值确定对应的请求响应。 |
| rep                     | Integer | rep 是 5 作为 req 5 的响应。                                 |
| data[0].client_id       | String  | 客户端订阅标识符。                                           |
| data[0].username        | String  | 用户名。                                                     |
| data[0].keepalive       | Integer | 保活。                                                       |
| data[0].protocol        | Integer | 协议版本。                                                   |
| data[0].connect_status  | Integer | 连接状态。                                                   |
| data[0].message_receive | Integer | 该客户端接受的消息。                                         |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 5,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":5,"data":[{"client_id":"nanomq-ebd54382","username":"nanmq","keepalive":60,"protocol":4,"connect_status":1,"message_receive":0}]
```

