# 访问控制

身份认证是物联网应用的重要组成部分，可以帮助有效阻止非法客户端的连接。授权是指对 MQTT 客户端的发布和订阅操作进行权限控制。在 NanoMQ 中，认证和授权通过验证用户的身份并确保他们有必要的权限来执行各种操作，从而保证系统的完整性和安全性。

本章将介绍 NanoMQ 中采用的各种认证和授权机制：包括用户登录授权，访问控制列表（ACL），以及 HTTP 授权。

## 认证配置

在 NanoMQ 中，认证通过以下结构进行配置：

```bash
authorization {
  sources = [
    { ...   },
    { ...   }
  ]
  no_match = allow
  deny_action = ignore
  cache {
    enable = true
    max_size = 1024
    ttl = 1m
  }
}
```

其中，

- `sources`（可选）：带顺序的数组，用于配置认证检查器的数据源。<!--带顺序吗？-->
- `no_match`：如果当前客户端操作无法匹配到任何规则，将基于此规则决定允许或拒绝操作。
- `deny_action`：如果当前客户端的操作被拒绝，后续应执行的操作。
- `cache`：缓存的相关配置。

## 授权配置

在 NanoMQ 中，授权通过以下结构进行配置：

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
        type = file
        enable = false

        rules = [
          {"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}
          {"permit": "allow", "ipaddr": "127.0.0.1", "action": "pubsub", "topics": ["$SYS/#", "#"]}
          {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}
          {"permit": "allow"}
        ]
      }
	]
}
```

 其中，

- `no_match`：如当前客户端操作无法匹配到任何规则，将基于此规则决定允许或拒绝操作。
- `deny_action`：如当前客户端的操作被拒绝，后续应执行的操作。
- `cache`：授权缓存的相关配置。
- `sources`（可选）：带顺序的数组，用于配置授权检查器的数据源。<!--带顺序吗？-->