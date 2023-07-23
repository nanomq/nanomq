# HTTP Server

The following configuration sets up an HTTP server for NanoMQ, including the server port, connection limit, authentication type, and JWT public key file if JWT authentication is used.

## Example Configuration

```hcl
http_server = {
  port = 8081               # HTTP server port
  limit_conn = 32           # Maximum number of outstanding requests NanoMQ can handle
  username = "admin"        # Username
  password = "public"       # Password
  auth_type = "basic        # Authentication type, "basic" or "jwt"
  jwt = {
    public.keyfile = "/etc/certs/jwt/jwtRS256.key.pub"   # Path to the JWT public key file, used if auth_type is "jwt"
  }
}
```

## Configuration Items

- `port`: Specifies the port on which the HTTP server will listen. Value range: 0 ~ 65535.
- `limit_conn`: Specifies the maximum number of outstanding requests that the server can handle at once. Value range: 1 ~ infinity.
- `username`: Specifies the username required for authentication with the HTTP server.
- `password`: Specifies the password required for authentication with the HTTP server.
- `auth_type`: Specifies the type of authentication used by the HTTP server. Values:
  - "basic"
  - "jwt". If "jwt" is to be used, make sure JWT dependencies have been built with the `-DENABLE_JWT=ON` option. For details, see [Build from Source Code](../installation/build-options.md)
- `jwt.public.keyfile`: Specifies the path to the public key file used for JWT authentication, used if `http_server.auth_type` is set to `jwt`. 