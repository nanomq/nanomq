# 访问控制

身份认证是物联网应用的重要组成部分，可以有效阻止非法客户端的连接。授权是指对 MQTT 客户端的发布和订阅操作进行权限控制。在 NanoMQ 中，认证和授权通过验证用户的身份并确保他们有必要的权限来执行各种操作，从而保证系统的完整性和安全性。

本章将介绍 NanoMQ 中采用的各种认证和授权机制：包括用户登录授权，访问控制列表（ACL），以及 HTTP 授权。

## 认证配置

在 NanoMQ 中，[以 HOCON 格式](../config-description/acl.md)为例，认证通过以下结构进行配置：

:::tip

NanoMQ 同时支持经典的 KV 配置格式，具体可参考[经典 KV 格式配置说明](../config-description/v013.md)

:::

```bash
auth {
  allow_anonymous = true
  no_match = allow
  deny_action = ignore
  cache {
    max_size = 1024
    duration = 1m
  }
  password = {include "/etc/nanomq_pwd.conf"}
  acl = {include "/etc/nanomq_acl.conf"}
}
```

其中，

- `allow_anonymous`： 数据类型为 `boolean`, 缺省值为 `true`，即允许匿名登录。
- `no_match`：如果当前客户端操作无法匹配到任何规则，将基于此规则决定允许或拒绝操作。
- `deny_action`：如果当前客户端的操作被拒绝，后续应执行的操作,可选项为`ignore`或`disconnect`。
- `cache`：缓存的相关配置，包含以下可选配置项：
  - `cache.max_size`： 默认值 `32`。此配置规定每个客户端允许缓存的 ACL 规则数量。当超过上限时，老的记录将会被删掉。
  - `cache.ttl`： 默认 `1m`（一分钟）。 该配置规定 ACL 规则缓存有效时间。
- `password`： 指定密码文件路径，具体参考[登录认证](./login.md)。
- `acl`： 指定访问规则文件路径，具体参考[访问控制列表](./acl.md)。