# 登录认证
此功能遵守 MQTT 协议中的 用户名/密码认证规范，可参考 [5.4.1 Authentication of Clients by the Server](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Security) 此部分规范提供了 MQTT Broker 一种对客户端进行鉴权的方法。此处使用此方法进行登录验证。

登录认证将基于用户名和密码进行验证登录用户的身份。

## 配置项目

| 配置项     | 类型   | 描述 |
| ---------- | ------ | ---- |
| `username` | 字符串 | 帐号 |
| `password` | 字符串 | 密码 |

请按照以下格式将用户名和密码写入 `nanomq_pwd.conf` 文件：
```shell
username:password
```
**示例**

```
# # Write "username":"password" in this way.
admin: public
client: public
```

::: tip
用户名应按照 MQTT 标准，为 UTF-8 格式。

:::

其中：

`admin` 和 `client`，密码均为 `public`，当 `allow_anonymous = false` 时， 只有用户 `admin` 和 `client` 可访问 NanoMQ。

并在 `nanomq.conf` 中 `include`，可参照 [访问控制介绍](./introduction.md)。
示例：

```
password = {include "/etc/nanomq_pwd.conf"}
```

## 通过 KV 格式配置

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

```bash
username=admin
password=public
```
