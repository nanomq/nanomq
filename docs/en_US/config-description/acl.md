# Access Control

This section introduces authentication and authorization-related settings. 

## **Example Configuration**

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

## **Configuration Items**

- `allow_anonymous`: Specifies whether clients are allowed to connect without providing a username and password. Default: `true`
- `no_match`: Specifies the default action (allow or deny) if no ACL rules match the client's operation. Default: `allow`
- `deny_action`: Specifies the action to take if an ACL check rejects an operation. Default: `ignore`; supported options are 
  - `ignore`: do nothing
  - `disconnect`: disconnect the client
- `cache` (optional): Contains settings related to the ACL cache:
  - `max_size`: Specifies the maximum number of ACL entries that can be cached for a client. Older records are evicted from the cache when the specified number is exceeded. Default: 32
  - `ttl`: Specifies the time after which an ACL cache entry will be deleted. Default: 1m

ACL can use separate configuration files (specified by the `include` method). And below are the explanation of each configuration file.

## nanomq_pwd.conf

Write the username and password in this format `username:password` and save it to the `nanomq_pwd.conf` file.

Example:

```hcl
"admin": "public"    # Username and password for the admin user
"client": "public"   # Username and password for a client user
```

## nanomq_acl.conf

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
- `username`: Specifies the username to which the rule applies.  "`#`" means all users
- `action`: Specifies the MQTT operation (like `publish`, `subscribe` or `pubsub`) to which the rule applies.
- `topics`: Specifies the MQTT topics to which the rule applies.
- `clientid`: Specifies the clientID to which the rule applies.  "`#`" means all client IDs.
- `and`: AND operation
- `or`: OR operation

Each rule is processed in order, and processing stops at the first match. If no rules match, the action specified by the `no_match` configuration item is applied.

**Tips:**

*   `@` can be used to match *any* topics without bothering by wildcards. For examples:
	By specifying `{"permit": "deny", "username": "#", "action": "subscribe", "topics": ["$SYS/#", "@#", "@client/+/msg"]}`, it will only deny subscription to topic `#` and
	`client/+/msg"`, not `client/123/msg` and any other topics although they are also matched in terms of wildcard rules.

*   `${clientid}` and `${username}` can be used as placeholder for configuring ACL topic without knowing the username and clientid of client ahead. They can work with `@` symbol together since 0.23.8. For examples:
	By specifying `{"permit": "deny", "username": "#", "action": "subscribe", "topics": ["@${clientid}/${username}/#"]}`, it will replace the topic with client's ID and username each time, which forbids all client subscribe to the corresponding topic that consists of its own ID, username and `#`. (Client with ID `ab` and username `cd` is denied to subscribe to topic `ab/cd/#`).
	

## HTTP Authentication

This section outlines the configuration for HTTP authentication, which allows the MQTT broker to authenticate clients using HTTP requests. It includes settings for authentication requests (`auth_req`), superuser requests (`super_req`), and Access Control List requests (`acl_req`).

### **Example Configuration**

```hcl
http_auth = {
	auth_req {
		url = "http://127.0.0.1:80/mqtt/auth"                       # HTTP URL API path for Auth Request
		method = "POST"                                               # HTTP Request Method for Auth Request
		headers.content-type = "application/x-www-form-urlencoded"  # HTTP Request Headers for Auth Request
		params = {clientid = "%c", username = "%u", password = "%P"} # Parameters to construct request body
	}
	
	super_req {
		url = "http://127.0.0.1:80/mqtt/superuser"                   # HTTP URL API path for SuperUser Request
		method = "POST"                                              # HTTP Request Method for SuperUser Request
		headers.content-type = "application/x-www-form-urlencoded"   # HTTP Request Headers for SuperUser Request
		params = {clientid = "%c", username = "%u", password = "%P"} # Parameters to construct request body
	}
	
	acl_req {
		url = "http://127.0.0.1:8991/mqtt/acl"                       # HTTP URL API path for ACL Request
		method = "POST"                                              # HTTP Request Method for ACL Request
		headers.content-type = "application/x-www-form-urlencoded"   # HTTP Request Headers for ACL Request
		params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"} # Parameters used to construct the request body
	}
	
	auth.http.super_req.url = "http://127.0.0.1:80/mqtt/superuser" # HTTP URL API path for SuperUser Request

	
	timeout = 5s                                                   # Time-out time for the request
	connect_timeout = 5s                                           # Connection time-out time
	pool_size = 32                                                 # Connection process pool size
}
```

### **Configuration Items**

#### `auth_req`

- `url`: Specifies the HTTP URL API path for the corresponding request. Example: http://127.0.0.1:80/mqtt/auth

- `method`: Specifies the HTTP request method for the corresponding request. This could be either `POST` or `GET`. Default: `POST`

- `headers.<Any>`: Specify the data in the HTTP request header. \<Key> Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. \<Key> can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. Example as follows:

- `headers.content-type`: Specifies the HTTP request headers for the corresponding request. The content-type header is used to indicate the media type of the resource that the request sends to the server.  You can keep specifying other headers of HTTP here as following `headers.accept`:

- `headers.accept`: Specifies the value for the `Accept` header in the HTTP request sent for authentication. Other headers like `cookie` and `date` follows same rule.

- `params`: Specifies the parameters used to construct the request body or query string parameters. 

  - When using the **GET** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. All placeholders will be replaced by run-time data.
  - When using the **POST** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data.

  Option values include:

  - `%u`: Username
  - `%c`: MQTT Client ID
  - `%a`: Client's network IP address
  - `%r`: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp
  - `%P`: Password
  - `%p`: Server port for client connection
  - `%C`: Common Name in client certificate
  - `%d`: Subject in client certificate

#### `super_req` 

::: tip

The `super_req` configuration refers to the Superuser, who has the privilege to bypass all other access control rules. It shares identical configuration items in their setups except the URL path. 

:::

- `url`: For example, http://127.0.0.1:80/mqtt/superuser

- `method`：Specifies the HTTP request method for the corresponding request. This could be either `POST` or `GET`. Default: `POST`

- `headers.<Any>`: Specify the data in the HTTP request header. \<Key> Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. \<Key> can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. Example as follows:

- `headers.content-type`：Specifies the HTTP request headers for the corresponding request. The content-type header is used to indicate the media type of the resource that the request sends to the server. You can keep specifying other headers of HTTP here as following `headers.accept`:

  - `headers.accept`: Specifies the value for the `Accept` header in the HTTP request sent for authentication. Accept header is used by HTTP clients to tell the server which type of content they expect/prefer as response.

- `params`: Specifies the parameters used to construct the request body or query string parameters. 

  - When using the **GET** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. All placeholders will be replaced by run-time data.
  - When using the **POST** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data.

  Option values are identical with the that in [`auth_req`](#auth-req)
  

#### `acl_req`

- `url`: Specifies the HTTP URL API path for the corresponding request.

- `method`: Specifies the HTTP request method for the corresponding request. This could be either `POST` or `GET`. Default: `POST`

- `headers.<Any>`: Specify the data in the HTTP request header. \<Key> Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. \<Key> can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. Example as follows:

- `headers.content-type: Specifies the HTTP request headers for the corresponding request. The content-type header is used to indicate the media type of the resource that the request sends to the server. You can keep specifying other headers of HTTP here as following `headers.accept`:

- `headers.accept`：Specifies the value for the `Accept` header in the HTTP request sent for authentication.

- `params`: Specifies the parameters used to construct the request body or query string parameters：

  - When using the **GET** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. 
  - When using the **POST** method, the value will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data ,

  These parameters can include variables like: 

  - `%A`: Permission to be verified: `1` for subscription and `2` for publish
  - `%u`: Username
  - `%c`: MQTT Client ID
  - `%a`: Client's network IP address
  - `%r`: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp
  - `%m`: Mount point
  - `%t`: Topic

**General ACL configuration items**

`timeout`: Specifies the time-out duration for the request. This is the maximum time that the server will wait for a response after sending the request. `0s` means never timeout.

`connect_timeout`: Specifies the connection time-out duration, which is the maximum time the client will wait while trying to establish a connection with the server.`0s` means never timeout.

`pool_size`: Specifies the size of the connection process pool, which is the maximum number of concurrent connections that can be established.

## Upcoming Features

TLS-related configuration items will be supported for HTTP authentication, including `acl_rep`, `super_req`, and `http_auth` in upcoming releases, please stay tuned. 

```
tls {
   	keyfile="/etc/certs/key.pem"
  	certfile="/etc/certs/cert.pem"
  	cacertfile="/etc/certs/cacert.pem"
}
```

