# 登录认证

登录认证将基于用户名和密码进行验证登录用户的身份。

## 配置项目

| 配置项     | 类型   | 描述 |
| ---------- | ------ | ---- |
| `username` | 字符串 | 帐号 |
| `password` | 字符串 | 密码 |

请以以下格式将用户名和密码写入 `nanomq_pwd.conf` 文件：
```shell
username:password
```
并在 `nanomq.conf` 中 `include`，可参照 [访问控制介绍](./introduction.md)。
## 配置示例

```bash
# # Write "username":"password" in this way.
admin: public
client: public
```

其中

`admin` 和 `client` ，密码均为 `public`，当 `allow_anonymous = false` 时， 只有用户 `admin` 和 `client` 可访问 NanoMQ。