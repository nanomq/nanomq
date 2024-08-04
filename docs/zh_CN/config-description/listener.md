# 监听器（ Listener ） 

NanoMQ 支持四种监听器类型：TCP 监听器，SSL 监听器，WebSocket 监听器和 Secure WebSocket 监听器。

## MQTT/TCP 监听器 - 1883

### **配置示例**

```hcl
listeners.tcp {
  bind = "0.0.0.0:1883"     # 绑定 1883 端口
}

listeners.tcp.listener_1 {
  bind = "0.0.0.0:1884"     # 绑定 1884 端口
}

listeners.tcp.listener_2 {
  bind = "0.0.0.0:1885"     # 绑定 1885 端口
}
```
NanoMQ 现已支持多监听器。 

### **配置项**

- `bind`：指定监听器应绑定的 IP 地址和端口。格式：`<ip:port>`

## MQTT/SSL 监听器 - 8883

### **配置示例**

```hcl
listeners.ssl {
  bind = "0.0.0.0:8883"                # 绑定 8883 端口
  # key_password = <yourpass>          # 解密私钥文件所需的密码字符串
  keyfile = "/etc/certs/key.pem"       # 密钥文件路径
  certfile = "/etc/certs/cert.pem"     # 用户证书文件路径
  cacertfile = "/etc/certs/cacert.pem" # CA 证书文件路径
  verify_peer = false					  		   # 是否从客户端请求证书	
  fail_if_no_peer_cert = false			   # 如客户端未提供证书，是否拒绝连接
}
```

### **配置项**

- `bind`：指定监听器应绑定的 IP 地址和端口。
- `key_password`：包含解密私钥文件所需的密码字符串，只需在私钥文件已加密的情况下设置。 
- `keyfile`：经 PEM 格式编码的私钥文件路径。
- `certfile`：用户证书文件路径。
- `cacertfile`：经 PEM 格式编码 CA 证书文件路径。
- `verify_peer`: 是否验证客户端证书，可选值：
  - `true`：verify_peer
  - `false `：verify_none
- `fail_if_no_peer_cert`：是否拒绝无证书连接，仅在 `verify_peer` 设置为 true 的情况下生效，可选值：
  - `true`：如客户端发送空证书，拒绝连接。
  - `false`：仅当客户端发送无效证书时拒绝连接。

## MQTT/WebSocket 监听器 - 8083

### **配置示例**

```hcl
listeners.ws {
  bind = "0.0.0.0:8083/mqtt"			# 绑定 8083 端口
}
```

### **配置项**

- `bind`：指定监听器应绑定的 IP 地址和端口。

## MQTT/Secure WebSocket 监听器 - 8084

### **配置示例**

```hcl
listeners.wss {
  bind = "0.0.0.0:8084"           	# 绑定 8084 端口
}
```

### **配置项**

- `bind`：指定监听器应绑定的 IP 地址和端口。

::: tip

Secure WebSocket 监听器与 SSL 监听器共用 `keyfile`、`certfile` 和 `cacertfile` 配置。因此，如已在 SSL 监听器部分完成相应配置，则无需重复配置。 如尚未配置 SSL 监听器，则需要为 Secure WebSocket 监听器进行以下配置：

- `keyfile`
- `certfile`
- `cacertfile`

:::