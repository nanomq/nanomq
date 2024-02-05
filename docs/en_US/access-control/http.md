# HTTP Authorization Configuration

HTTP Authorization provides yet another method for authorization. NanoMQ will send an HTTP POST request in the format as configured to the target HTTP server when receiving `CONNECT` packets from MQTT clients, and relies on the return code of HTTP POST for the client's authorization. It enables extensive authorization with external HTTP service.

::: tip

For now, HTTP Authorization only supports `MQTT CONNECT`, will add support for `PUBLISH` & `SUBSCRIBE` in the future. Please post an issue if you need further support urgently.

:::

## Configuration Example

:::: tabs type:card

::: tab HOCON

If you need to use `http_auth`, you can modify it in the format of the following example, and then put the configuration of `http_auth` into the `auth {}` configuration. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description](../config-description/acl.md)
- For users of NanoMQ versions 0.14 ~ 0.18, please refer to [Configuration Description - v0.14](../config-description/v014.md)

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

::: tab KV format

Users wishing to use the KV configuration format can refer to the following structure and write their configurations into the `nanomq_old.conf` file. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description - v013](../config-description/v013.md)

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

## Start NanoMQ

Start NanoMQ and specify the path to the configuration path.

```bash
$ nanomq start --conf path/to/nanomq.conf
```

If you are using the KV format, start NanoMQ with the command below:

```bash
$ nanomq start --old_conf path/to/nanomq_old.conf
```

