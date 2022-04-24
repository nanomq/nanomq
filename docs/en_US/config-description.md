# Configuration

## Introduction

The configuration files of NanoMQ Broker usually have the suffix .conf. You can find these configuration files in the etc directory.
| File                      | Description                   |
| ----------------------------- | ---------------------- |
| etc/nanomq.conf               | NanoMQ Configuration File        |
| etc/nanomq_bridge.conf        | NanoMQ Bridge File     |
| etc/nanomq_auth_username.conf | NanoMQ Authorization File  |
| etc/nanomq_web_hook.conf | NanoMQ Web Hook File  |

## Parameter Description

### nanomq.conf

| Name                  | Type    | Description                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| url              | String  | Url of listener.                        |
| num_taskq_thread | Integer | Number of taskq threads used. |
| max_taskq_thread | Integer | Maximum number of taskq threads used。 |
| parallel |Long  | Number of parallel.                                          |
| property_size |Integer  | Max size for a MQTT property. |
| msq_len | Integer | Queue length for resending messages. |
| qos_duration | Integer | The interval of the qos timer.                               |
| allow_anonymous | Boolean | Allow anonymous login.                                       |
| tls.enable | Boolean | Enable TLS listener(*default: false*).                                         |
| tls.url | String | URL of TLS listener. |
| tls.key | String | User's private PEM-encoded key. |
| tls.keypass | String | String containing the user's password. Only used if the private keyfile is password-protected. |
| tls.cert |String  | User certificate data.                                       |
| tls.cacert | String | User's PEM-encoded CA certificates.                          |
| tls.verify_peer | Boolean | Verify peer certificate.                                     |
| tls.fail_if_no_peer_cert | Boolean | Server will fail if the client does not have a certificate to send. |
| websocket.enable | Boolean | Enable websocket listener(*default: true*). |
| websocket.url | String  | URL of websocket listener. |
| websocket.tls_url |  String | URL of TLS over websocket listerner. |
| http_server.enable| Boolean | Enable http server listerner (*default: false*). |
| http_server.port | Integer | Port of http server. |
| http_server.username | String | User name of http server. |
| http_server.password | String | Password of http server. |
| http_server.auth_type | Enum | Http server authentication type (*default: basic*). |
| http_server.jwt.public.keyfile | String |public key file for *JWT*. |
| http_server.jwt.private.keyfile | String |private key file for *JWT*. |

### nanomq_bridge.conf

| Name                  | Type    | Description                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| bridge.bridge_mode | Boolean | Enter MQTT bridge mode (default `false` ).                                  |
| bridge.address | String | Remote Broker address. |
| bridge.proto_ver | String | MQTT client version（3｜4｜5）。 |
| bridge.clientid | String | MQTT client identifier. |
| bridge.keepalive | Integer | Interval of keepalive.                                       |
| bridge.clean_start | Boolean | Clean seeson.                                                |
| bridge.parallel | Long | Parallel of mqtt client。 |
| bridge.username | String | Login user name. |
| bridge.password | String | Login password. |
| bridge.forwards | Array[String] | Array of forward topics.( *Use commas `,` to separate multiple topics* ) |
| bridge.mqtt.subscription.1.topic | String | First `Topic`.                               |
| bridge.mqtt.subscription.1.qos | Integer | First `Qos`.                       |
| bridge.mqtt.subscription.2.topic | String        | Second`Topic` ( *And so on* ).             |
| bridge.mqtt.subscription.2.qos   | Integer       | Second`Qos`( *And so on* ). |

### nanomq_auth_username.conf

| Name                  | Type    |  Description                                     |
| --------------- | -------- | ------------------------------- |
| auth.1.login    | String   | First Username.               |
| auth.1.password | String   | First Password.                 |
| auth.2.login    | String   | Second Username ( *And so on* ). |
| auth.2.password | String   | Second Password ( *And so on* ). |

### nanomq_web_hook.conf

| Name | Type | Description |
| ------ | -------- | -------- |
| web.hook.enable       | Boolean | Enable WebHook (default: `false`) |
| web.hook.url       | String | *Webhook URL* |
| web.hook.headers.\<Any\> | String | *HTTP Headers*<br>*Example:*<br>*1. web.hook.headers.content-type=application/json*<br> *2. web.hook.headers.accept=\** |
| web.hook.body.encoding_of_payload_field | Enum | *The encoding format of the payload field in the HTTP body*<br>Options: <br>plain \| base64 \| base62 |
| web.hook.ssl.cacertfile       | String | *PEM format file of CA's*. |
| web.hook.ssl.certfile       | String | *Certificate file to use, PEM format assumed.* |
| web.hook.ssl.keyfile       | String | *Private key file to use, PEM format assumed.* |
| web.hook.ssl.verify       | Boolean | *Turn on peer certificate verification*  (default: `false`). |
| web.hook.ssl.server_name_indication       | Boolean | *Verify server_name*  (default: `false`). |
| web.hook.pool_size | Integer | *Connection process pool size* (default: 32). |
| web.hook.rule.client.connack.\<No\>      | String  | Example: <br>*web.hook.rule.client.connack.1={"action": "on_client_connack"}* |
| web.hook.rule.client.disconnected.\<No\> | String  | *Example: <br/>web.hook.rule.client.disconnected.1={"action": "on_client_disconnected"}* |
| web.hook.rule.message.publish.\<No\>     | String  | Example: <br/>*web.hook.rule.message.publish.1={"action": "on_message_publish"}* <br>*web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "topic/1/2"}* <br>*web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}* |

