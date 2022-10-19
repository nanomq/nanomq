# Configuration

## Introduction

The configuration files of NanoMQ Broker is HOCON（Human-Optimized Config Object Notation）.It is ideal for configuration data storage that is easy for humans to read and write. You can find these configuration files in the etc directory.
| File                      | Description                   |
| ----------------------------- | ---------------------- |
| etc/nanomq.conf               | NanoMQ Configuration File        |
| etc/nanomq_gateway.conf       | NanoMQ Gateway File (for `nanomq_cli`) |

## Syntax

In config file the values can be notated as JSON like objects, such as
```
websocket {
     enable=false
     url="nmq-ws://0.0.0.0:8083/mqtt"
     tls_url="nmq-wss://0.0.0.0:8084/mqtt"
}
```

Another equivalent representation is flat, such as

```
websocket.enable = false
websocket.url="nmq-ws://0.0.0.0:8083/mqtt"
websocket.tls_url="nmq-wss://0.0.0.0:8084/mqtt"
```

This flat format is almost backward compatible (the so called 'cuttlefish' format).

It is not fully compatible because the often HOCON requires strings to be quoted,
while cuttlefish treats all characters to the right of the `=` mark as the value.

e.g. cuttlefish: cuttlefish：`websocket.url = nmq-ws://0.0.0.0:8083/mqtt`，HOCON：`websocket.url = "nmq-ws://0.0.0.0:8083/mqtt"`.

### Config Overlay Rules
HOCON objects are overlaid, in general:

- Within one file, objects defined 'later' recursively override objects defined 'earlier'
- When layered, 'later' (higher layer) objects override objects defined 'earlier' (lower layer)

Below are more detailed rules.

For example, in below config, the last line `debug` overwrites `error` for
console log handler's `level` config, but leaving `to` unchanged.
```
log {
    to=["file","console"]
    level="error"
}

## ... more configs ...

log.level=debug
```

## Parameter Description

### nanomq.conf

#### basic configuration

| Name                  | Type    | Description                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| url              | String  | Url of listener.                        |
| num_taskq_thread | Integer | Number of taskq threads used. |
| max_taskq_thread | Integer | Maximum number of taskq threads used. |
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
| http_server.auth_type | String | Http server authentication type (*default: basic*). |
| http_server.jwt.public.keyfile | String |public key file for *JWT*. |
| http_server.jwt.private.keyfile | String |private key file for *JWT*. |
| log.to | Array[String] | Array of log types，( *Use commas `,` to separate multiple types* )<br>Log types:  *file, console, syslog* |
| log.level                       | String        | Log level：trace, debug, info, warn, error, fatal            |
| log.dir                         | String      | The dir for log files. (if log to file)                      |
| log.file                        | String      |The log filename. (if log to file) |
| log.rotation.size | String | Maximum size of each log file; <br>Supported Unit: `KB | MB | GB`;<br> Default: `10MB` |
| log.rotation.count | Integer | Maximum rotation count of log files; <br>Default: `5` |

#### MQTT bridge configuration

| Name                  | Type    | Description                                                  |
| --------------------- | ------- | ------------------------------------------------------------ |
| bridge.mqtt.nodes[0].name | String | Node name |
| bridge.mqtt.nodes[0].enable | Boolean | Enter MQTT bridge mode (default `false` ).                                  |
| bridge.mqtt.nodes[0].address | String | Remote Broker address. |
| bridge.mqtt.nodes[0].proto_ver | Boolean | MQTT client version（3｜4｜5）. |
| bridge.mqtt.nodes[0].clientid | String | MQTT client identifier. |
| bridge.mqtt.nodes[0].keepalive | Integer | Interval of keepalive.                                       |
| bridge.mqtt.nodes[0].clean_start | Boolean | Clean seeson.                                                |
| bridge.mqtt.nodes[0].parallel | Long | Parallel of mqtt client. |
| bridge.mqtt.nodes[0].username | String | Login user name. |
| bridge.mqtt.nodes[0].password | String | Login password. |
| bridge.mqtt.nodes[0].forwards | Array[String] | Array of forward topics.( *Use commas `,` to separate multiple topics* ) |
| bridge.mqtt.nodes[0].subscription[0].topic | String | First `Topic`.                               |
| bridge.mqtt.nodes[0].subscription[0].qos | Integer | First `Qos`.                       |
| bridge.mqtt.nodes[0].tls.enable | Boolean | Launch TLS （* default false*）。 |
| bridge.mqtt.nodes[0].tls.key_password | String | String containing the user's password. only used if the private keyfile is password-protected. |
| bridge.mqtt.nodes[0].tls.keyfile | String | User's private PEM-encoded key. |
| bridge.mqtt.nodes[0].tls.certfile |String  | User certificate data. |
| bridge.mqtt.nodes[0].tls.cacertfile | String | User's PEM-encoded CA certificates.|

#### AWS IoT Core bridge configuration

| Name                                 | Type          | Description                                                  |
| ------------------------------------ | ------------- | ------------------------------------------------------------ |
| bridge.aws.nodes[0].name | String | Node name |
| bridge.aws.nodes[0].enable | Boolean | Enter MQTT bridge mode (default `false` ).                                  |
| bridge.aws.nodes[0].host                 | String        | aws endpoint.                                                |
| bridge.aws.nodes[0].port                 | Integer       | aws MQTT port.                                               |
| bridge.aws.nodes[0].clientid             | String        | MQTT client identifier.                                      |
| bridge.aws.nodes[0].keepalive            | Integer       | Interval of keepalive.                                       |
| bridge.aws.nodes[0].clean_start          | Boolean       | Clean seeson.                                                |
| bridge.aws.nodes[0].parallel             | Long          | Parallel of mqtt client.                                     |
| bridge.aws.nodes[0].username             | String        | Login user name.                                             |
| bridge.aws.nodes[0].password             | String        | Login password.                                              |
| bridge.aws.nodes[0].forwards             | Array[String] | Array of forward topics.( *Use commas `,` to separate multiple topics* ) |
| bridge.aws.nodes[0].subscription[0].topic | String | First `Topic`.                               |
| bridge.aws.nodes[0].subscription[0].qos | Integer | First `Qos`.                       |
| bridge.aws.nodes[0].tls.enable | Boolean | Launch TLS （* default false*）。 |
| bridge.aws.nodes[0].tls.key_password | String | String containing the user's password. only used if the private keyfile is password-protected. |
| bridge.aws.nodes[0].tls.keyfile | String | User's private PEM-encoded key. |
| bridge.aws.nodes[0].tls.certfile |String  | User certificate data. |
| bridge.aws.nodes[0].tls.cacertfile | String | User's PEM-encoded CA certificates.|

#### Authorization configuration

| Name                  | Type    |  Description               |
| --------------- | -------- | ------------------------------- |
| auth[0].login    | String   | Username.                      |
| auth[0].password | String   | Password.                      |

#### WebHook configuration

| Name | Type | Description |
| ------ | -------- | -------- |
| webhook.enable       | Boolean | Enable WebHook (default: `false`) |
| webhook.url       | String | *Webhook URL* |
| webhook.headers.\<Any\> | String | *HTTP Headers*<br>*Example:*<br>*1. webhook.headers.content-type=application/json*<br> *2. webhook.headers.accept=\** |
| webhook.body.encoding | String | *The encoding format of the payload field in the HTTP body*<br>Options: <br>plain \| base64 \| base62 |
| webhook.pool_size | Integer | *Connection process pool size* (default: 32). |
| webhook.rule.client.connack.\<No\>      | String  | Example: <br>*webhook.rule.client.connack=[{"action": "on_client_connack"}]* |
| webhook.rule.client.disconnected.\<No\> | String  | *Example: <br/>webhook.rule.client.disconnected=[{"action": "on_client_disconnected"}]* |
| webhook.rule.message.publish.\<No\>     | String  | Example: <br/>*webhook.rule.message.publish={"action": "on_message_publish"}* <br>*webhook.rule.message.publish=[{"action": "on_message_publish"}, {"topic": "topic/1/2"}]* <br>*webhook.rule.message.publish = [{"action": "on_message_publish"}, {"topic": "foo/#"}]* |

#### Http authorication configuration

| Name                              | Type | Description                                                     | default                                                         |
| ----------------------------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth_http.enable                    | Boolean  | Enable HTTP authentication                        | `false`                                                      |
| auth_http.auth_req.url              | String   | Specify the target URL of the authentication request. | `http://127.0.0.1:80/mqtt/auth`                              |
| auth_http.auth_req.method           | String     | Specify the request method of the authentication request.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth_http.auth_req.headers.\<Any\>  | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.auth_req.headers.content-type = application/x-www-form-urlencoded` <br/>`auth_http.auth_req.headers.accept = */*` |
| auth_http.auth_req.params           | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows:<br>`%u: Username`<br>`%c: MQTT Client ID`<br>`%a: Client's network IP address`<br>`%r: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp`<br>`%P: Password`<br>`%p: Server port for client connection`<br>`%C: Common Name in client certificate`<br>`%d: Subject in client certificate` | `auth_http.auth_req.params = [{clientid: "%c"}, {username: "%u"}, {password: "%P"}]`                        |
| auth_http.super_req.url             | String   | Specify the target URL for the superuser authentication request. | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth_http.super_req.method          | String   | Specifies the request method of the super user authentication request.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth_http.super_req.headers.\<Any\> | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth_http.super_req.headers.accept = */*` |
| auth_http.super_req.params          | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are the same as those of `auth_http.auth_req.params`. | `auth_http.super_req.params = [{clientid: "%c"}, {username: "%u"}, {password: "%P"}]`                                    |
| auth_http.acl_req.url               | String   | Specify the target URL for ACL verification requests. | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth_http.acl_req.method            | String   | Specifies the request method for ACL verification requests.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth_http.acl_req.headers.\<Any\>   | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth_http.super_req.headers.accept = */*` |
| auth_http.acl_req.params            | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows:<br/>`%A: Permission to be verified, 1 means subscription, 2 means publish`<br>`%u: UserName`<br/>`%c: MQTT Client ID`<br/>`%a: Client network IP address`<br/>`%r: The protocol used by the client can be: mqtt, mqtt-sn, coap, lwm2m and stomp`<br/>`%m: Mount point`<br>`%t: Topic` | `auth_http.acl_req.params = [{clientid = "%c"}, {username = "%u"}, { access = "%A"}, {ipaddr = "%a"}, {topic = "%t"}, {mountpoint = "%m"}]` |
| auth_http.timeout                   | Integer  | HTTP request timeout. Any setting equivalent to `0s` means never timeout. | `5s`                                                         |
| auth_http.connect_timeout           | Integer  | Connection timeout for HTTP requests. Any setting value equivalent to `0s` means never time out. | `5s`                                                         |


#### Rule engine configuration

| Name                          | Type    | Description                                                                      |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.option                   | String  | Rule engine option, when persistence with rule engine, this option is must be ON.|
#### Rule configuration for sqlite

| Name                          | Type    | Description                                                                      |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.sqlite.path              | String  | Rule engine option SQLite3 database path, default is /tmp/rule_engine.db         |
| rule.sqlite.enabled           | Boolen  | Rule engine option SQLite3 is enabled,  default is true                          |
| rule.sqlite.rules[0].enabled  | Boolen  | Rule engine option rule is enbaled, default is  true                             |
| rule.sqlite.rules[0].table    | String  | Rule engine option SQLite3 database table name                                   |
| rule.sqlite.rules[0].sql      | String  | Rule engine sql clause                                                           |

#### Rule configuration for mysql

| Name                          | Type    | Description                                                                      |
| ------------------------------| ------- | -------------------------------------------------------------------------------- |
| rule.mysql.name               | String  | Rule engine option mysql database name, default is mysql_rule_db                 |
| rule.mysql.enabled            | Boolen  | Rule engine option mysql is enabled,  default is true                            |
| rule.mysql.rules[0].enabled   | Boolen  | Rule engine option rule is enbaled, default is  true                             |
| rule.mysql.rules[0].table     | String  | Rule engine option mysql database table name                                     |
| rule.mysql.rules[0].host      | String  | Rule engine option mysql database host                                           |
| rule.mysql.rules[0].username  | String  | Rule engine option mysql database username                                       |
| rule.mysql.rules[0].password  | String  | Rule engine option mysql database password                                       |
| rule.mysql.rules[0].sql       | String  | Rule engine sql clause                                                           |

#### Rule configuration for repub

| Name                          | Type    | Description                                                     |
| ------------------------------| ------- | --------------------------------------------------------------- |
| rule.repub.enabled               | Boolen  | Rule engine option repub is enabled,  default is true        |
| rule.repub.rules[0].enabled      | Boolen  | Rule engine option rule is enbaled, default is  true         |
| rule.repub.rules[0].address      | String  | Rule engine option repub address (mqtt-tcp://host:port)      |
| rule.repub.rules[0].topic        | String  | Rule engine option repub topic                               |
| rule.repub.rules[0].username     | String  | Rule engine option repub username                            |
| rule.repub.rules[0].password     | String  | Rule engine option repub password                            |
| rule.repub.rules[0].proto_ver    | Integer | Rule engine option repub protocol version, default is 4      |
| rule.repub.rules[0].clientid     | String  | Rule engine option repub clientid                            |
| rule.repub.rules[0].keepalive    | Integer | Rule engine option repub keepalive                           |
| rule.repub.rules[0].clean_start  | Boolean | Rule engine option repub clean_start flag, default is true   |
| rule.repub.rules[0].sql          | String  | Rule engine sql clause                                       |


### nanomq_gateway.conf

| Name                            | Type    | Description                          |
| ------------------------------- | ------- | ------------------------------------ |
| gateway.mqtt.address            | String  | Remote Broker address.               |
| gateway.mqtt.proto_ver          | String  | MQTT client version（3｜4｜5).        |
| gateway.mqtt.clientid           | String  | MQTT client identifier.              |
| gateway.mqtt.keepalive          | Integer | Interval of keepalive.               |
| gateway.mqtt.clean_start        | Boolean | Clean seeson.                        |
| gateway.mqtt.parallel           | Long    | Parallel of mqtt client.             |
| gateway.mqtt.username           | String  | Login user name.                     |
| gateway.mqtt.password           | String  | Login password.                      |
| gateway.mqtt.forward            | String  | Forward topic.                       |
| gateway.mqtt.sub_topic          | String  | Mqtt subscribe topic.                |
| gateway.mqtt.sub_qos            | Integer | Mqtt subscribe qos.                  |
| gateway.zmq.sub_address         | String  | Remote ZMQ server subscribe address. |
| gateway.zmq.pub_address         | String  | Remote ZMQ server publish address.   |
| gateway.zmq.sub_pre             | String  | Remote ZMQ server subscribe prefix.  |
| gateway.zmq.pub_pre             | String  | Remote ZMQ server publish prefix.    |

