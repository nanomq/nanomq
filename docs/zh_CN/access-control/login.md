# 登录认证

登录认证将基于用户名和密码进行验证登录用户的身份。

## 配置项目

| 配置项     | 类型   | 描述 |
| ---------- | ------ | ---- |
| `username` | 字符串 | 帐号 |
| `password` | 字符串 | 密码 |

## 配置示例

```bash
authorization {
	no_match = allow
	deny_action = ignore
	cache = {
		enable = false
		max_size = 32
		ttl = 1m
	}
	sources = [
		{
			type = simple
			enable = false
			users = [
				{
					username = "admin"
					password = "public"
				}
				{
					username = "client"
					password = "public"
				}
			]
		}
  ]
}
```

其中

- `no_match` 和 `deny_action` 分别被设置为 `allow` 和 `ignore`。
- `cache` 被禁用。
- `sources` 定义了可访问的用户列表， `admin` 和 `client` ，密码均为 `public`。

基于以上设定，用户 `admin` 和 `client` 可访问 NanoMQ。