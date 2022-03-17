# Configuration

## Introduction

The configuration files of NanoMQ Broker usually have the suffix .conf. You can find these configuration files in the etc directory.
| File                      | Description                   |
| ----------------------------- | ---------------------- |
| etc/nanomq.conf               | NanoMQ Configuration File        |
| etc/nanomq_bridge.conf        | NanoMQ Bridge File     |
| etc/nanomq_auth_username.conf | NanoMQ Authorization File  |

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
