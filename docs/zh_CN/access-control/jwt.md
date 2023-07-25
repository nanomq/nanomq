# 启用 JWT 身份验证
JWT 身份验证提供了一个安全的方式来使用 NanoMQ 的 HTTP 服务。

## 编译

NanoMQ 中 JWT 作为扩展特性，默认不加入编译目标。可通过设置编译选项 `-DENABLE_JWT=ON `启用 JWT。具体步骤，可参考[源码编辑安装](../installation/build-options.md)。

```bash
$ cmake -DENABLE_JWT=ON ..
$ make
```

## 生成公私钥

签发 JWT 前需要生成一对公私钥, 并注意根据需要修改公钥文件名 (**文件名会被自动设置为 Token 载荷中**`iss`**字段的值**)；

使用 OpenSSL 命令行工具生成 RSA 密钥：

```bash
# 生成私钥
$ openssl genrsa -out nanomq.key 2048
# 生成公钥
$ openssl rsa -in nanomq.key -out nanomq.pub -pubout
```

## 配置

NanoMQ 的 HTTP 身份验证方式默认使用 `Basic` 认证，需要在配置文件 `nanomq.conf` 中修改 `auth_type` 为 `JWT`，并指定 `JWT` 公钥文件的路径:

:::: tabs type:card

::: tab HOCON 配置格式

希望使用 HOCON 配置格式的用户，可参考以下格式，将配置写入 `nanomq.conf`文件，相关设置将在 NanoMQ 重启后生效。

- 完整的配置项列表，可参考[配置说明](../config-description/http-server.md)

- NanoMQ 0.14 ~ 0.18 版本用户，可参考 [配置说明 - v0.14](../config-description/v014.md)

```c
http_server {
    # # http server port
    # #
    # # Value: 0 - 65535
    port = 8081
    # # parallel for http server
    # # Handle a specified maximum number of outstanding requests
    # #
    # # Value: 1-infinity
    parallel = 32
    # # http server username
    # #
    # # Value: String
    username = admin
    # # http server password
    # #
    # # Value: String
    password = public
    # # http server auth type
    # # If set auth_type=jwt, make sure you have built JWT dependency with `-DENABLE_JWT=ON` first.
    # #
    # # Value: String basic | jwt
    auth_type = jwt
    jwt {
        # # http server jwt public key file
        # # Used together with 'http_server.auth_type=jwt',
        # # Path to the file containing the user's private key.
        # #
        # # Value: File
        public.keyfile = "/etc/certs/jwt/nanomq.pub"
    }
}
```

:::

::: tab KV 配置格式

希望使用 KV 配置格式的用户，可参考以下格式，将配置写入 `nanomq_old.conf `文件，相关设置将在 NanoMQ 重启后生效。

完整的配置项列表，可参考[经典 KV 格式配置说明](../config-description/v013.md)

```bash
http_server.port=8081
http_server.parallel=32
http_server.username=admin
http_server.password=public
http_server.auth_type=jwt
http_server.jwt.public.keyfile="/etc/certs/jwt/nanomq.pub"
```

:::

::::

## 启动 NanoMQ

启动 NanoMQ 并指定配置文件

```bash
$ nanomq start --conf ./nanomq.conf
```

如使用 KV 格式配置文件，可通过如下格式启动 NanoMQ

```bash
$ nanomq start --conf ./nanomq_old.conf
```

## Token 规则

使用 HTTP 客户端访问 NanoMQ HTTP 服务端前需先生成 Token;

NanoMQ 中所需要的 JWT 结构如下:

```bash
header
{
    "alg": "RS256",
    "typ": "JWT"
}

payload
{
    "iss": "nanomq.pub",
    "iat": "1683281256",
    "exp": "1683283256",
    "bodyEncode": "0"
}
```

### 头部

- 令牌类型（typ）：使用 JWT
- 使用的算法（alg）：使用 RS256

### 载荷

- 签发者（iss）：根据需求定义，但要确保与生成的公钥文件名称一致。例如，生成 nanomq.pub 的公钥文件, 则 iss 设置为 "nanomq.pub"
- 签发时间（iat）：签发时间
- 过期时间（exp）：签发过期时间

## 生成 Token

使用 [JWT 官网](https://jwt.io/)工具生成。在 Decoded 中填写：

- Algorithm：RS256
- Header：头部
- Payload：载荷
- Verify Signature：分别填入公私钥 `-----BEGIN PUBLIC KEY-----` 和 `-----BEGIN RSA PRIVATE KEY-----`



## 访问 NanoMQ HTTP Server

使用 curl 并填入以上生成的 token 访问 NanoMQ HTTP 服务:

```bash
$ curl --location 'http://127.0.0.1:8081/api/v4' \
--header 'Authorization: Bearer {TOKEN}'
```
