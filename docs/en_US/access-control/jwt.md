# JWT Authorization
JWT Authorization provides a secure way of quering NanoMQ' HTTP APIs.

## Building

JWT is an extended feature in NanoMQ, it is disabled by default. To enable JWT with cmake option `-DENABLE_JWT=ON `:

```bash
$ cmake -DENABLE_JWT=ON ..
$ make
```

## Generate a public and private key file

Before issuing JWT, it's necessary to generate a pair of public and private keys. 

**Note: The public key file name is the issuing name**.

Generate RSA keys using OpenSSL command-line tools:

```bash
# generate private key
$ openssl genrsa -out nanomq.key 2048
# generate public key
$ openssl rsa -in nanomq.key -out nanomq.pub -pubout
```

## Configuration

The default authorization mode is `Basic`, you need to change the `auth_type ` to `JWT` in the configuration file and specify the path to  `JWT` public key file.

:::: tabs type:card

::: tab HOCON

Users wishing to use the HOCON configuration format can refer to the following structure and write their configurations into the `nanomq.conf` file. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description](../config-description/http-server.md)
- For users of NanoMQ versions 0.14 ~ 0.18, please refer to [Configuration Description - v0.14](../config-description/v014.md)

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

::: tab KV format

Users wishing to use the KV configuration format can refer to the following structure and write their configurations into the `nanomq_old.conf` file. The relevant settings will take effect after NanoMQ is restarted.

- For a complete list of configuration options, refer to [Configuration Description - v013](../config-description/v013.md)

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

## Start NanoMQ

Start NanoMQ and specify the path to the configuration path.

```bash
$ nanomq start --conf ./nanomq.conf
```

If you are using the KV format, start NanoMQ with the command below:

```
$ nanomq start --conf ./nanomq_old.conf
```

## Token rules

Generate a token for HTTP client;

The required JWT structure for NanoMQ is as follows: 

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

### Header

- typ: Using JWT
- alg: Using RS256

### Payload

- iss: Defined it according to the requirements, but ensure that it is consistent with the filename of the generated public key file. For example, if the file name is "nanomq.pub", the `iss` should be `nanomq.pub`.
- iat: Time of issuance.
- exp: Expiration time of issuance.

### Token generation

You can use [JWT official website tool](https://jwt.io/) to generate a JWT. Fill in the **Decoded** section as follows: 

- Algorithm: RS256
- Header: Header
- Payload: Payload
- Verify Signature: Fille in public and private key.

### Send Request to NanoMQ HTTP Server

Use `curl` to send a `GET` request with the generated token to NanoMQ HTTP Server : 

```bash
$ curl --location 'http://127.0.0.1:8081/api/v4' \
--header 'Authorization: Bearer {TOKEN}'
```