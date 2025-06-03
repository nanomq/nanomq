# 访问控制

本部分介绍与认证和授权相关的一些配置项。

## **配置示例**

```hcl
auth {
	allow_anonymous = true # 允许匿名登录
	no_match = allow       # 没有 ACL 规则匹配情况下的默认操作
	deny_action = ignore   # ACL 检查拒绝情况下的默认操作

	cache = {
		max_size = 32        # 客户端可以缓存的最大 ACL 条目数量
		ttl = 1m             # ACL 规则缓存有效时间
	}
	
	password = {include "/etc/nanomq_pwd.conf"} # 密码存储文件路径
	acl = {include "/etc/nanomq_acl.conf"}       # ACL 配置文件路径
}
```

## **配置示例**

- `allow_anonymous`：数据类型为 `boolean`, 缺省值为 `true`，即允许匿名登录。
- `no_match`：可选值，可以设置为 `allow` 或 `deny`。缺省值是 `allow`。 当 NanoMQ 无法从认证链中为某个客户端匹配到任何规则时候，将会使用这个默认的规则。
- `deny_action`：可选值，指定当拒绝访问发生时，应该如何对待这个客户端的 MQTT 连接。 
  - `ignore` （缺省值）: 操作会被丢弃，例如，对于发布动作，消息会被丢弃；对于订阅操作，订阅请求会被拒绝。
  - `disconnect`：断开当前客户端连接。
- `cache`: 可选值，ACL 缓存的配置。
  - `max_size`：规定每个客户端允许缓存的 ACL 规则数量。当超过上限时，老的记录将会被删掉；缺省值：32
  - `ttl`：规定 ACL 规则缓存有效时间；缺省值：1m。

您可通过单独的配置文件配置用户名/密码（`nanomq_pwd.conf`）或访问规则（`nanomq_acl.conf`），并通过 `include` 语法在主配置文件 `nanomq.conf` 中引用：

```hcl
password = {include "/etc/nanomq_pwd.conf"} 
```



## nanomq_pwd.conf

您可按照 `username:password` 格式将用户名/密码写入 `nanomq_pwd.conf` 文件。

**示例**：

```hcl
"admin":"public"    # 管理员的用户名和密码
"client":"public"   # 客户端的用户名和密码
```

## nanomq_acl.conf

**示例**：

```hcl
rules = [
	# # 允许使用用户名 "dashboard" 的 MQTT 客户端订阅 "$SYS/#" 主题
	{"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}
	
	# # 拒绝"所有用户"订阅 "$SYS/#" "#" 主题
	# {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}
	
	# # 允许任何其他发布/订阅操作
	{"permit": "allow"}
]
```

**配置项：**

`rules`：ACL 规则数组。每个规则都可以包括以下属性对象：

- `permit`：允许（`allow`）或拒绝（`deny`）当前操作。
- `username`：指定规则适用的用户名。"`#`"表示所有用户。
- `action`：指定规则适用的 MQTT 操作（如 `publish`，`subscribe` 或 `pubsub`）。
- `topics`：指定规则适用的 MQTT 主题。
- `clientid`：指定规则适用的 ClientID。"`#`" 表示所有客户端 ID。
- `and`：与操作
- `or`：或操作

ACL 规则的匹配遵循自顶向下的顺序。当一个规则匹配到当前客户端时，规则允许或拒绝的动作就会生效，后面的规则不再继续检查。如果没有规则匹配，将按照 `no_match` 配置项进行操作。

**Tips:**

*   `@` 可用于匹配 *任何* 主题，而无需考虑通配符规则。例如：
	通过指定 `{"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "@#", "@client/+/msg"]}`，只会拒绝订阅主题 `#` 和
	`client/+/msg"`，而不是 `client/123/msg` 和任何其他主题，尽管它们也是
	根据通配符规则是匹配。
*   `${clientid}` 和 `${username}` 可以作为配置 ACL 主题的占位符，而无需提前知道客户端的用户名和 clientid。从 0.23.8 开始，它们可以和 '@' 符号同时使用。例如：
	通过指定 `{"permit": "deny", "username": "#", "action": "subscribe", "topics": ["@${clientid}/${username}/#"]}`，每次都会用客户端的 ID 和用户名替换主题内容，这禁止所有客户端订阅对应的包含其自己的ID、用户名和`#`的主题。（ID 为 `ab` 且用户名为 `cd` 的客户端被拒绝订阅主题 `ab/cd/#`）。

## HTTP 身份验证

本节概述 HTTP 身份验证的相关配置，NanoMQ 将基于该配置组对客户端的 HTTP 请求进行认证，包括身份验证（`auth_req`）、超级用户（`super_req`）和访问控制列表（`acl_req`）三部分。

### **配置示例**

```hcl
http_auth = {
	auth_req {
		url = "http://127.0.0.1:80/mqtt/auth"                       # Auth 请求的 HTTP URL API 路径
		method = "POST"                                               # Auth 请求的 HTTP 请求方法
		headers.content-type = "application/x-www-form-urlencoded"  # Auth 请求的 HTTP 请求头			
		params = {clientid = "%c", username = "%u", password = "%P"} # 请求体的构造参数
	}
	
	super_req {
		url = "http://127.0.0.1:80/mqtt/superuser"                   # SuperUser 请求的 HTTP URL API 路径
		method = "POST"                                              # SuperUser 请求的 HTTP 请求方法
		headers.content-type = "application/x-www-form-urlencoded"   # SuperUser 请求的 HTTP 请求头
		params = {clientid = "%c", username = "%u", password = "%P"} # 请求体的构造参数
	}
	
	acl_req {
		url = "http://127.0.0.1:8991/mqtt/acl"                       # ACL 请求的 HTTP URL API 路径
		method = "POST"                                              # ACL 请求的 HTTP 请求方法
		headers.content-type = "application/x-www-form-urlencoded"   # ACL 请求的 HTTP 请求头
		params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"} # 请求体的构造参数
	}
	
	auth.http.super_req.url = "http://127.0.0.1:80/mqtt/superuser" # SuperUser 请求的 HTTP URL API 路径

	
	timeout = 5s                                                   # 请求超时时间
	connect_timeout = 5s                                           # 连接超时时间
	pool_size = 32                                                 # 连接进程池大小
}
```

### **配置项**

#### `auth_req`

- `url`：认证请求的目标 URL。 例如：http://127.0.0.1:80/mqtt/auth

- `method`：认证请求的请求方法，可选值：`POST` , `GET`；缺省值：`POST`

- `headers.<Any>`：指定 HTTP 请求头部中的数据。\<Any> 是可以被 任意\<Key> 替换来指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。\<Key> 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。如以下两个示例：

- `headers.content-type`：指定 HTTP 请求头部中的数据。`content-type` 用于指示请求发送给服务器的资源的媒体类型。

- `headers.accept`：指定客户端期望接收的媒体类型。例如，"*/*" 表示接收所有媒体类型。

- `params`： 指定认证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。

  - 使用 **GET** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。
  
  - 使用 **POST** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。
  
   所有的占位符都会被运行时数据所替换，可用的占位符如下：
  
  - `%u`： 用户名
  - `%c`： MQTT Client ID
  - `%a`： 客户端的网络 IP 地址
  - `%r`： 客户端使用的协议，支持 mqtt、mqtt-sn、coap、lwm2m、stomp
  - `%P`： 密码
  - `%p`： 客户端连接的服务端端口
  - `%C`： 客户端证书中的 Common Name
  - `%d`： 客户端证书中的 Subject

#### `super_req` 

::: tip

超级用户（`super_req`）可以绕过越过其他控制链权限，除 HTTP URL 路径外，所有配置项与 `auth_req`  相同。

:::

- `url`：指定超级用户认证请求的目标 URL，例如 http://127.0.0.1:80/mqtt/superuser

- `method`：指定超级用户认证请求的请求方法；可选值：`POST` , `GET`

- `headers.<Any>`：指定 HTTP 请求头部中的数据。\<Any> 是可以被 任意\<Key> 替换来指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。\<Key> 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。如以下两个示例：
- `headers.content-type`：指定 HTTP 请求头部中的数据。`content-type` 用于指示请求发送给服务器的资源的媒体类型。

- `headers.accept`：指定客户端期望接收的媒体类型。例如，"*/*" 表示接收所有媒体类型。

- `params`： 指定认证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。
  - 使用 **GET** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。
  - 使用 **POST** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。
   所有的占位符都会被运行时数据所替换，可用的占位符可参考 [`auth_req`](#auth-req) 部分。


#### `acl_req`

- `url`：指定 ACL 验证请求的目标 URL。

- `method`：指定 ACL 验证请求的请求方法。可选值：`POST` , `GET`；缺省值： `post`
  
- `headers.<Any>`：指定 HTTP 请求头部中的数据。\<Any> 是可以被 任意\<Key> 替换来指定 HTTP 请求头部中的字段名，此配置项的值为相应的字段值。\<Key> 可以是标准的 HTTP 请求头部字段，也可以自定义的字段，可以配置多个不同的请求头部字段。如以下两个示例：
- `headers.content-type`： 指定 HTTP 请求头部中的数据。`content-type` 用于指示请求发送给服务器的资源的媒体类型。

- `headers.accept`：指定客户端期望接收的媒体类型。例如，"*/*" 表示接收所有媒体类型。

- `params`： 指定认证请求中携带的数据。以 `,` 分隔的 `k=v` 键值对，`v` 可以是固定内容，也可以是占位符。

  - 使用 **GET** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以查询字符串参数的形式发送。
  
  - 使用 **POST** 方法时，值将被转换为以 `&` 分隔的 `k=v` 键值对以 Request Body 的形式发送。
  
   所有的占位符都会被运行时数据所替换，可用的占位符如下：
  
  - `%A`： 需要验证的权限， 1 表示订阅， 2 表示发布
  - `%u`： 用户名
  - `%c`： MQTT Client ID
  - `%a`： 客户端的网络 IP 地址
  - `%r`：客户端使用的协议，支持 mqtt、mqtt-sn、coap、lwm2m 和 stomp
  - `%m`： 挂载点
  - `%t`： 主题

**其他 ACL 配置项**

`timeout`：HTTP 请求超时时间。 `0s` 表示永不超时。

`connect_timeout`： HTTP 请求的连接超时时间。`0s` 表示永不超时。

`pool_size`：连接进程池大小

## 功能预告

在接下里的版本中，NanoMQ 即将支持与 HTTP 身份验证相关的 TLS 配置项，敬请期待。

```hcl
tls {
   	keyfile="/etc/certs/key.pem"
  	certfile="/etc/certs/cert.pem"
  	cacertfile="/etc/certs/cacert.pem"
}
```

