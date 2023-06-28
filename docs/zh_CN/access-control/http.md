# HTTP 认证

NanoMQ 同时支持 HTTP 认证。本页将给出相关的配置项以及一个配置示例。

## 配置项

| 参数名                              | 数据类型 | 参数说明                                                     | 默认                                                         |
| ----------------------------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth.http_auth.enable                    | Boolean  | 启动 HTTP 认证                                                 | `false`                                                      |
| auth.http_auth.auth_req.url              | String   | 认证请求的目标 URL。                                         | `http://127.0.0.1:80/mqtt/auth`                              |
| auth.http_auth.auth_req.method           | String     | 认证请求的请求方法。<br>(`POST`  , `GET`)                    | `POST`                                                       |
| auth.http_auth.auth_req.headers.\<Any\>  | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。<br> | `auth.http_auth.auth_req.headers.content-type = application/x-www-form-urlencoded` <br/>`auth.http_auth.auth_req.headers.accept = */*` |
| auth.http_auth.auth_req.params        | Array[Object]  | 指定认证请求中携带的数据。<br>以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br> 使用 **GET** 方法时 `auth.http_auth.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth.http_auth.auth_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br>`%u: 用户名`<br>`%c: MQTT Client ID`<br>`%a: 客户端的网络 IP 地址`<br>`%r: 客户端使用的协议，可以是： mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br>`%P: 密码`<br>`%p: 客户端连接的服务端端口`<br>`%C: 客户端证书中的 Common Name`<br>`%d: 客户端证书中的 Subject` | `auth.http_auth.auth_req.params = {clientid= "%c", username= "%u", password= "%P"}`                        |
| auth.http_auth.super_req.url             | String   | 指定超级用户认证请求的目标 URL。                             | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth.http_auth.super_req.method          | String   | 指定超级用户认证请求的请求方法。<br>(`POST`  , `GET`)        | `POST`                                                       |
| auth.http_auth.super_req.headers.\<Any\> | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth.http_auth.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http_auth.super_req.headers.accept = */*` |
| auth.http_auth.super_req.params          |Array[Object]    | 指定超级用户认证请求中携带的数据。<br>使用 **GET** 方法时 `auth.http_auth.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br>使用 **POST** 方法时 `auth.http_auth.super_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符同 `auth.http_auth.auth_req.params`。 | `auth.http_auth.super_req.params = {clientid= "%c", username= "%u", password= "%P"}`                                    |
| auth.http_auth.acl_req.url               | String   | 指定 ACL 验证请求的目标 URL。                                | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth.http_auth.acl_req.method            | String   | 指定 ACL 验证请求的请求方法。(`POST`  , `GET`)               | `POST`                                                       |
| auth.http_auth.acl_req.headers.\<Any\>   | String   | 指定 HTTP 请求头部中的数据。`<Key>` 指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。`<Key>` 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。 | `auth.http_auth.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http_auth.super_req.headers.accept = */*` |
| auth.http_auth.acl_req.params            | Array[Object]   | 指定 ACL 验证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。<br/> 使用 **GET** 方法时 `auth.http_auth.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。<br/>使用 **POST** 方法时 `auth.http_auth.acl_req.params` 的值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。所有的占位符都会被运行时数据所替换，可用的占位符如下：<br/>`%A: 需要验证的权限， 1 表示订阅， 2 表示发布`<br>`%u: 用户名`<br/>`%c: MQTT Client ID`<br/>`%a: 客户端的网络 IP 地址`<br/>`%r: 客户端使用的协议，可以是： mqtt, mqtt-sn, coap, lwm2m 以及 stomp`<br/>`%m: 挂载点`<br>`%t: 主题` | `auth.http_auth.acl_req.params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}` |
| auth.http_auth.timeout                   | Integer  | HTTP 请求超时时间。任何等价于 `0s` 的设定值都表示永不超时。  | `5s`                                                         |
| auth.http_auth.connect_timeout           | Integer  | HTTP 请求的连接超时时间。任何等价于 `0s` 的设定值都表示永不超时。 | `5s`                                                         |

例子:
- 如果需要使用 `http_auth`，可按着下面事例的格式修改，然后将 `http_auth` 的配置放到配置 `auth {}` 内。

```bash
http_auth = {
  auth_req {
    url = "http://127.0.0.1:80/mqtt/auth"
    method = post
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", password = "%p"}
  }

  super_req {
    url = "http://127.0.0.1:80/mqtt/superuser"
    method = "post"
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", password = "%p"}
  }

  acl_req {
    url = "http://127.0.0.1:8991/mqtt/acl"
    method = "post"
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}
  }

  timeout = 5s
  connect_timeout = 5s
  pool_size = 32
}
```
