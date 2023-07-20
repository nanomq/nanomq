# Authentication and Authorization

This section introduces authentication and authorization-related settings. 

**Example Configuration**

```hcl
auth {
	allow_anonymous = true # Allow clients to connect without providing username/password
	no_match = allow       # Default action if no ACL rules match
	deny_action = ignore   # Action to take if an ACL check rejects an operation

	cache = {
		max_size = 32        # Maximum number of ACL entries to cache for a client
		ttl = 1m             # Time after which an ACL cache entry will be deleted
	}
	
	password = {include "/etc/nanomq_pwd.conf"} # Path to the password configuration file
	acl = {include "/etc/nanomq_acl.conf"}       # Path to the ACL configuration file
}
```

**Configuration Items**

- `allow_anonymous`: Specifies whether clients are allowed to connect without providing a username and password.
- `no_match`: Specifies the default action (allow or deny) if no ACL rules match the client's operation.
- `deny_action`: Specifies the action to take if an ACL check rejects an operation. The options are 
  - `ignore`: do nothing
  - `disconnect`: disconnect the client
- `cache`: Contains settings related to the ACL cache:
  - `max_size`: Specifies the maximum number of ACL entries that can be cached for a client.
  - `ttl`: Specifies the time after which an ACL cache entry will be deleted.



ACL can use separate configuration files (specified by the `include` method). And below are the explanation of each configuration file.

### nanomq_pwd.conf

```hcl
admin: public # Username and password for the admin user
client: public # Username and password for a client user
```

### nanomq_acl.conf

```hcl
rules = [
	# # Allow MQTT client using username "dashboard"  to subscribe to "$SYS/#" topics
	{"permit": "allow", "username": "dashboard", "action": "subscribe", "topics": ["$SYS/#"]}
	
	# # Deny "All Users" subscribe to "$SYS/#" "#" Topics
	# {"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "#"]}
	
	# # Allow any other publish/subscribe operation
	{"permit": "allow"}
]
```

`rules`: An array of ACL rules. Each rule is an object with the following properties:

- `permit`: Specifies whether the operation is to `allow` or `deny`.
- `username`: Specifies the username to which the rule applies.
- `action`: Specifies the MQTT operation (like `publish` or `subscribe`) to which the rule applies.
- `topics`: Specifies the MQTT topics to which the rule applies.

Each rule is processed in order, and processing stops at the first match. If no rules match, the action specified by the `no_match` configuration item is applied.

## HTTP Authentication

This section outlines the configuration for HTTP authentication, which allows the MQTT broker to authenticate clients using HTTP requests. It includes settings for authentication requests (`auth_req`), superuser requests (`super_req`), and Access Control List (ACL) requests (`acl_req`).

**Example Configuration**

```hcl
http_auth = {
	auth_req {
		url = "http://127.0.0.1:80/mqtt/auth"                       # HTTP URL API path for Auth Request
		method = post                                               # HTTP Request Method for Auth Request
		headers.content-type = "application/x-www-form-urlencoded"  # HTTP Request Headers for Auth Request
		params = {clientid = "%c", username = "%u", password = "%p"} # Parameters to construct request body
	}
	
	super_req {
		url = "http://127.0.0.1:80/mqtt/superuser"                   # HTTP URL API path for SuperUser Request
		method = "post"                                              # HTTP Request Method for SuperUser Request
		headers.content-type = "application/x-www-form-urlencoded"   # HTTP Request Headers for SuperUser Request
		params = {clientid = "%c", username = "%u", password = "%p"} # Parameters to construct request body
	}
	
	acl_req {
		url = "http://127.0.0.1:8991/mqtt/acl"                       # HTTP URL API path for ACL Request
		method = "post"                                              # HTTP Request Method for ACL Request
		headers.content-type = "application/x-www-form-urlencoded"   # HTTP Request Headers for ACL Request
		params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"} # Parameters used to construct the request body
	}
	
	auth.http.super_req.url = "http://127.0.0.1:80/mqtt/superuser" # HTTP URL API path for SuperUser Request

	
	timeout = 5s                                                   # Time-out time for the request
	connect_timeout = 5s                                           # Connection time-out time
	pool_size = 32                                                 # Connection process pool size
}
```

**Configuration Items**

`auth_req` and `super_req` 

- `url`: Specifies the HTTP URL API path for the corresponding request.
- `method`: Specifies the HTTP request method for the corresponding request. This could be either `post` or `get`.
- `headers.content-type`: Specifies the HTTP request headers for the corresponding request. The content-type header is used to indicate the media type of the resource that the request sends to the server.
- `params`: Specifies the parameters used to construct the request body or query string parameters. These parameters can include variables like: 
  - `%u`: Username
  - `%c`: MQTT Client ID
  - `%a`: Client's network IP address
  - `%r`: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp
  - `%P`: Password
  - `%p`: Server port for client connection
  - `%C`: Common Name in client certificate
  - `%d`: Subject in client certificate <!--我觉得 https://nanomq.io/docs/en/latest/config-description/v019.html#http-authorization-configuration 这里的描述太过偏向后台实现了，用户不太需要知道，我先拿掉了-->

::: tip

Superuser need to be defined

:::

`acl_req`: 

- `params`: Specifies the parameters used to construct the request body or query string parameters. These parameters can include variables like: 

  - `%u`: Username

  - `%c`: MQTT Client ID

  - `%a`: Client's network IP address

  - `%r`: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp

  - `%P`: Password

  - `%p`: Server port for client connection

  - `%C`: Common Name in client certificate

  - `%d`: Subject in client certificate

- For the other configuration items, please refer to `auth_req`.

`timeout`: Specifies the time-out duration for the request. This is the maximum time that the server will wait for a response after sending the request.

`connect_timeout`: Specifies the connection time-out duration, which is the maximum time the client will wait while trying to establish a connection with the server.

`pool_size`: Specifies the size of the connection process pool, which is the maximum number of concurrent connections that can be established.