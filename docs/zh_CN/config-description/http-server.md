# HTTP 服务器

本节将介绍如何配置 HTTP 服务器，包括服务器端口、连接限制、认证类型以及 JWT 认证。

## 配置示例

```hcl
http_server = {
  port = 8081               # HTTP 服务器端口
  ip_addr = "0.0.0.0"       # HTTP 服务器 Address
  limit_conn = 32           # NanoMQ 可以处理的最大未完成请求数
  users = [                 # Basic 认证凭据列表
    { username = "admin", password = "public" }
    { username = "ops",   password = "s3cret" }
  ]
  # username = "admin"      # 兼容写法，新配置推荐 users
  # password = "public"     # 兼容写法，新配置推荐 users
  max_body = 65535          # 最大 HTTP Body
  auth_type = "basic"       # 认证类型
  jwt = {
    public.keyfile = "/etc/certs/jwt/jwtRS256.key.pub"   # JWT公钥文件路径
  }
}
```

## 配置项

- `port`：HTTP 服务器的监听端口。取值范围：0 ~ 65535。
- `limit_conn`：服务器一次可以处理的最大未完成请求数量。值范围：1 ~  infinity。
- `users`：Basic 认证凭据列表，每个元素形如
  `{ username = "...", password = "..." }`。配置里出现的凭据都有效，任意一组
  匹配即可通过。该配置只在 HOCON 配置格式下支持。缺字段、空字符串、用户名中
  含 `:` 的条目会被跳过并打印告警，重复用户名保留第一条。如果写了 `users`
  但没有有效条目，又没有配置 `username`/`password`，则所有请求返回 401。
- `username`：**兼容写法**，仍完全支持；新配置推荐用 `users`。只要写在配置里
  就仍然有效，并且与 `users` 里的每一条构成并集。
- `password`：**兼容写法**，仍完全支持；新配置推荐用 `users`。见 `username`。
- `max_body`：HTTP 服务器一次可以处理的最大 HTTP body.
- `auth_type`：HTTP 服务器使用的认证类型：
  - "basic"
  - "jwt"：如使用 `"jwt"`，请确保已启用 JWT 功能 （ `-DENABLE_JWT=ON`），具体步骤，见[源码编译安装](../installation/build-options.md)。
- `jwt.public.keyfile`：用于 JWT 认证的公钥文件的路径，仅在 `http_server.auth_type` 设为 `jwt` 时生效。 
