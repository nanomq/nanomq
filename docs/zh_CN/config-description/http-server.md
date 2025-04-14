# HTTP 服务器

本节将介绍如何配置 HTTP 服务器，包括服务器端口、连接限制、认证类型以及 JWT 认证。

## 配置示例

```hcl
http_server = {
  port = 8081               # HTTP 服务器端口
  ip_addr = "0.0.0.0"       # HTTP 服务器 Address
  limit_conn = 32           # NanoMQ 可以处理的最大未完成请求数
  username = "admin"        # 用户名
  password = "public"       # 密码
  max_body = 65535          # 最大 HTTP Body
  auth_type = "jwt# 认证类型
  jwt = {
    public.keyfile = "/etc/certs/jwt/jwtRS256.key.pub"   # JWT公钥文件路径
  }
}
```

## 配置项

- `port`：HTTP 服务器的监听端口。取值范围：0 ~ 65535。
- `limit_conn`：服务器一次可以处理的最大未完成请求数量。值范围：1 ~  infinity。
- `username`：与 HTTP 服务器进行身份验证所需的用户名。
- `password`：与 HTTP 服务器进行身份验证所需的密码。
- `max_body`：HTTP 服务器一次可以处理的最大 HTTP body.
- `auth_type`：HTTP 服务器使用的认证类型：
  - "basic"
  - "jwt"：如使用 `"jwt"`，请确保已启用 JWT 功能 （ `-DENABLE_JWT=ON`），具体步骤，见[源码编译安装](../installation/build-options.md)。
- `jwt.public.keyfile`：用于 JWT 认证的公钥文件的路径，仅在 `http_server.auth_type` 设为 `jwt` 时生效。 