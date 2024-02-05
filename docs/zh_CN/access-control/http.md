# HTTP 认证

NanoMQ 同时支持 HTTP 认证。HTTP 认证功能支持用户使用外部 HTTP 服务进行客户端行为的授权。当 NanoMQ 从 MQTT 客户端接收 `CONNECT` 数据包时，NanoMQ 将按照配置为目标 HTTP 服务器的格式发送 HTTP POST 请求，并依靠 HTTP POST 的返回码进行客户端授权决定是否允许其连接。

::: tip

目前，HTTP Authorization 仅支持 `MQTT CONNECT`，将来将添加对 `PUBLISH` 和 `SUBSCRIB` 的支持。如果您急需进一步的支持，请在 Github 发布 Feature Request。

:::

## 配置示例

:::: tabs type:card

::: tab HOCON 配置格式

如果需要使用 `http_auth`，可按着下面示例的格式修改，然后将 `http_auth` 的配置放到配置文件 `nanomq.conf` 文件的 `auth {}` 内。相关设置将在 NanoMQ 重启后生效。

- 完成的配置项列表，可参考[配置说明](../config-description/acl.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)


```bash
auth {
  ...
  http_auth = {
    auth_req {
      url = "http://127.0.0.1:80/mqtt/auth"
      method = "POST"
      headers.content-type = "application/x-www-form-urlencoded"
      params = {clientid = "%c", username = "%u", password = "%P"}
    }

    super_req {
      url = "http://127.0.0.1:80/mqtt/superuser"
      method = "POST"
      headers.content-type = "application/x-www-form-urlencoded"
      params = {clientid = "%c", username = "%u", password = "%P"}
    }

    acl_req {
      url = "http://127.0.0.1:8991/mqtt/acl"
      method = "POST"
      headers.content-type = "application/x-www-form-urlencoded"
      params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}
    }

    timeout = 5s
    connect_timeout = 5s
    pool_size = 32
  }
  ...
}
```

:::

::: tab KV 配置格式

如希望使用 KV 配置格式，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考[经典 KV 格式配置说明](../config-description/v013.md)

```bash
auth.http.enable=<Your Value>

auth.http.auth_req.url="http://127.0.0.1:80/mqtt/auth"
auth.http.auth_req.method="POST"
auth.http.auth_req.headers.<Any>=<Your Value>

auth.http.auth_req.params.clientid="%c"
auth.http.auth_req.params.username="%u"
auth.http.auth_req.params.password="%p"

auth.http.super_req.url="http://127.0.0.1:80/mqtt/superuser"
auth.http.super_req.method="POST"
auth.http.super_req.headers.<Any>=<Your Value>

auth.http.super_req.params.clientid="%c"
auth.http.super_req.params.username="%u"
auth.http.super_req.params.password="%p"

auth.http.acl_req.url="http://127.0.0.1:8991/mqtt/acl"
auth.http.acl_req.method="POST"
auth.http.acl_req.headers.<Any>=<Your Value>

auth.http.acl_req.params.clientid="%c"
auth.http.acl_req.params.username="%u"
auth.http.acl_req.params.access="%A"
auth.http.acl_req.params.ipaddr="%a"
auth.http.acl_req.params.topic="%t"
auth.http.acl_req.params.mountpoint="%m"

auth.http.timeout="5s"
auth.http.connect_timeout="5s"
auth.http.ssl.cacertfile=<Your Value>
auth.http.ssl.certfile=<Your Value>
auth.http.ssl.keyfile=<Your Value>
```

:::

::::

## 启动 NanoMQ

启动 NanoMQ 并指定配置文件

```bash
$ nanomq start --conf path/to/nanomq.conf
```

如使用 KV 格式配置文件，可通过如下格式启动 NanoMQ

```bash
$ nanomq start --old_conf path/to/nanomq_old.conf
```

