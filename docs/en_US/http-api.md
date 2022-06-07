# HTTP API

NanoMQ Broker provides HTTP APIs for integration with external systems, such as querying broker statistics information, clients information, subscribe topics information, and restart with new config file.

NanoMQ Broker's HTTP API service listens on port 8081 by default. You can modify the listening port through the configuration file of `etc/nanomq.conf`. All API calls with `api/v1`.

## Interface security

NanoMQ Broker's HTTP API uses the method of [Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) or [JWT Authentication](https://jwt.io/introduction). The `username` and `password` must be filled. The default `username` and `password` are: `admin/public`. You can modify username and password through the configuration file of `etc/nanomq.conf`.

## Response code

### HTTP status codes

The NanoMQ Broker interface always returns 200 OK when the call is successful, and the response content is returned in JSON format.

The possible status codes are as follows:

| Status Code | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| 200         | Succeed, and the returned JSON data will provide more information |
| 400         | Invalid client request, such as wrong request body or parameters |
| 401         | Client authentication failed , maybe because of invalid authentication credentials |
| 404         | The requested path cannot be found or the requested object does not exist |
| 500         | An internal error occurred while the server was processing the request |

### result codes

The response message body of the NanoMQ Broker interface is in JSON format, which always contains the returned `code`.

The possible returned codes are as follows:

| Return Code | Description                                     |
| ----------- | ----------------------------------------------- |
| 0           | Succeed                                         |
| 101         | RPC error                                       |
| 102         | unknown mistake                                 |
| 103         | wrong user name or password                     |
| 104         | Empty username or password                      |
| 105         | User does not exist                             |
| 106         | Administrator account cannot be deleted         |
| 107         | Missing key request parameters                  |
| 108         | Request parameter error                         |
| 109         | Request parameters are not in legal JSON format |
| 110         | Plug-in is enabled                              |
| 111         | Plugin is closed                                |
| 112         | Client is offline                               |
| 113         | User already exists                             |
| 114         | Old password is wrong                           |
| 115         | Illegal subject                                 |
| 116         | Token expired                                   |



## API Endpoints 

### GET /api/v4

Return all Endpoints supported by NanoMQ Broker.

**Parameters:** 无

**Success Response Body (JSON):**

| Name             | Type    | Description    |
| ---------------- | ------- | -------------- |
| code             | Integer | 0              |
| data             | Array   | Endpoints list |
| - data[0].path   | String  | Endpoint       |
| - data[0].name   | String  | Endpoint Name  |
| - data[0].method | String  | HTTP Method    |
| - data[0].descr  | String  | Description    |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4"

{"code":0,"data":[{"path":"/brokers/","name":"list_brokers","method":"GET","descr":"A list of brokers in the cluster"},{"path":"/nodes/","name":"list_nodes","method":"GET","descr":"A list of nodes in the cluster"},{"path":"/clients/","name":"list_clients","method":"GET","descr":"A list of clients on current node"},{"path":"/clients/:clientid","name":"lookup_client","method":"GET","descr":"Lookup a client in the cluster"},{"path":"/clients/username/:username","name":"lookup_client_via_username","method":"GET","descr":"Lookup a client via username in the cluster"},{"path":"/subscriptions/","name":"list_subscriptions","method":"GET","descr":"A list of subscriptions in the cluster"},{"path":"/subscriptions/:clientid","name":"lookup_client_subscriptions","method":"GET","descr":"A list of subscriptions of a client"},{"path":"/topic-tree/","name":"list_topic-tree","method":"GET","descr":"A list of topic-tree in the cluster"},{"path":"/configuration/","name":"get_broker_configuration","method":"GET","descr":"show broker configuration"},{"path":"/configuration/","name":"set_broker_configuration","method":"POST","descr":"set broker configuration"},{"path":"/ctrl/:action","name":"ctrl_broker","method":"POST","descr":"Control broker stop or restart"}]}
```



## Broker Basic Information

### GET /api/v4/brokers

Return basic information of NanoMQ Broker.

**Success Response Body (JSON):**

| Name             | Type                    | Description                                                  |
| ---------------- | ----------------------- | ------------------------------------------------------------ |
| code             | Integer                 | 0                                                            |
| data             | Object/Array of Objects | Returns the information of all nodes*(Only one node for NanoMQ)* |
| data.datetime    | String                  | Current time, in the format of "YYYY-MM-DD HH: mm: ss"       |
| data.node_status | String                  | Node status                                                  |
| data.sysdescr    | String                  | Software description                                         |
| data.uptime      | String                  | NanoMQ Broker runtime, in the format of "H hours, m minutes, s seconds" |
| data.version     | String                  | NanoMQ Broker version                                        |

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/brokers"

{"code":0,"data":[{"datetime":"2022-06-07 10:02:24","node_status":"Running","sysdescr":"NanoMQ Broker","uptime":"15 Hours, 1 minutes, 38 seconds","version":"0.7.9-3"}]}
```



## Node

### GET /api/v4/nodes

Return the status of the node.

**Success Response Body (JSON):**

| Name             | Type                    | Description                                        |
| ---------------- | ----------------------- | -------------------------------------------------- |
| code             | Integer                 | 0                                                  |
| data             | Object/Array of Objects | Returns information about all nodes in an Array    |
| data.connections | Integer                 | Number of clients currently connected to this node |
| data.node_status | String                  | Node status                                        |
| data.uptime      | String                  | NanoMQ Broker runtime                              |
| data.version     | String                  | NanoMQ Broker version                              |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/nodes"

{"code":0,"data":[{"connections":0,"node_status":"Running","uptime":"15 Hours, 22 minutes, 4 seconds","version":"0.8.1"}]}
```



## Client

### GET /api/v4/clients

支持多条件查询，其包含的查询参数有：

| Name        | Type    | Required | Description                                                  |
| ----------- | ------- | -------- | ------------------------------------------------------------ |
| clientid    | String  | False    | Client identifier                                            |
| username    | String  | False    | Client username                                              |
| conn_state  | Enum    | False    | The current connection status of the client, the possible values are`connected`,`idle`,`disconnected` |
| clean_start | Bool    | False    | Whether the client uses a new session                        |
| proto_name  | Enum    | False    | Client protocol name, the possible values are`MQTT`,`CoAP`,`LwM2M`,`MQTT-SN` |
| proto_ver   | Integer | False    | Client protocol version                                      |

**Success Response Body (JSON):**

| Name                | Type             | Description                                              |
| ------------------- | ---------------- | -------------------------------------------------------- |
| code                | Integer          | 0                                                        |
| data                | Array of Objects | Information for all clients                              |
| data[0].clientid    | String           | Client identifier                                        |
| data[0].username    | String           | User name of client when connecting                      |
| data[0].proto_name  | String           | Client protocol name*(MQTT,CoAP,LwM2M,MQTT-SN)*          |
| data[0].proto_ver   | Integer          | Protocol version used by the client                      |
| data[0].connected   | Boolean          | Whether the client is connected                          |
| data[0].keepalive   | Integer          | keepalive time, with the unit of second                  |
| data[0].clean_start | Boolean          | Indicate whether the client is using a brand new session |
| data[0].recv_msg    | Integer          | Number of PUBLISH packets received                       |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients"

{"code":0,"data":[{"client_id":"nanomq-f6d6fbfb","username":"alvin","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5,"recv_msg":3},{"client_id":"nanomq-bdf61d9b","username":"nanomq","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5,"recv_msg":0}]}
```

### GET /api/v4/clients/{clientid}

Returns information for the specified client

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| clientid | String | True     | ClientID    |

**Success Response Body (JSON):**

| Name | Type             | Description                                                  |
| ---- | ---------------- | ------------------------------------------------------------ |
| code | Integer          | 0                                                            |
| data | Array of Objects | Client information, for details, see  [GET /api/v4/clients](#GET /api/v4/clients) |

**Examples:**

Query the specified client

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients/nanomq-29978ec1"

{"code":0,"data":[{"client_id":"nanomq-29978ec1","username":"","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5}]}
```



### GET /api/v4/clients/username/{username}

Query client information by Username. Since there may be multiple clients using the same user name, multiple client information may be returned at the same time.

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| username | String | True     | Username    |

**Success Response Body (JSON):**

| Name | Type             | Description                                                  |
| ---- | ---------------- | ------------------------------------------------------------ |
| code | Integer          | 0                                                            |
| data | Array of Objects | Information about clients, for details, see [GET /api/v4/clients](#GET /api/v4/clients) |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/clients/username/user001"

{"code":0,"data":[{"client_id":"nanomq-56baa74d","username":"user001","keepalive":60,"conn_state":"connected","clean_start":true,"proto_name":"MQTT","proto_ver":5}]}
```



### Subscription Information

### GET /api/v4/subscriptions

Multiple conditions queries are supported:

| Name     | Type   | Description                    |
| -------- | ------ | ------------------------------ |
| clientid | String | Client identifier              |
| topic    | String | congruent query                |
| qos      | Enum   | Possible values are 0`,`1`,`2` |
| share    | String | Shared subscription group name |

**Success Response Body (JSON):**

| Name             | Type             | Description                  |
| ---------------- | ---------------- | ---------------------------- |
| code             | Integer          | 0                            |
| data             | Array of Objects | All subscription information |
| data[0].clientid | String           | Client identifier            |
| data[0].topic    | String           | Subscribe to topic           |
| data[0].qos      | Integer          | QoS level                    |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/subscriptions"

{"code":0,"data":[{"clientid":"nanomq-29978ec1","topic":"topic123","qos":2},{"clientid":"nanomq-3020ffac","topic":"topic123","qos":2}]}
```



### GET /api/v4/subscriptions/{clientid}

Return the subscription information of the specified client in the Broker.

**Path Parameters:**

| Name     | Type   | Required | Description |
| -------- | ------ | -------- | ----------- |
| clientid | String | True     | ClientID    |

**Success Response Body (JSON):**

| Name          | Type    | Description                  |
| ------------- | ------- | ---------------------------- |
| code          | Integer | 0                            |
| data          | Object  | All subscription information |
| data.clientid | String  | Client identifier            |
| data.topic    | String  | Subscribe to topic           |
| data.qos      | Integer | QoS level                    |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/subscriptions/123"

{"data":[{"topic":"a/b/c","qos":1,"clientid":"123"}],"code":0}
```



## Topic tree structure

### GET /api/v4/topic-tree

**Success Response Body (JSON):**

| Name             | Type             | Description                |
| ---------------- | ---------------- | -------------------------- |
| code             | Integer          | 0                          |
| data             | Array of Objects |                            |
| data[0].clientid | Array of String  | Array of client identifies |
| data[0].topic    | String           | Subscribe to topic         |
| data[0].cld_cnt  | Integer          | Number of child node       |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X GET "http://localhost:8081/api/v4/topic-tree"

{"code":0,"data":[[{"topic":"","cld_cnt":1}],[{"topic":"topic123","cld_cnt":1,"clientid":["nanomq-3a4a0956"]}],[{"topic":"123","cld_cnt":1,"clientid":["nanomq-0cfd69bb"]}],[{"topic":"456","cld_cnt":0,"clientid":["nanomq-26971dc8"]}]]}
```



## Get configuration

### GET /api/v4/configuration

Read all of configure parameters from broker.

**Success Response Body (JSON):**

| Name                              | Type          | Description                                                  |
| --------------------------------- | ------------- | ------------------------------------------------------------ |
| code                              | Integer       | 0                                                            |
| data.url                          | String        | Url of listener.                                             |
| data.num_taskq_thread             | Integer       | Number of taskq threads used.                                |
| data.max_taskq_thread             | Integer       | Maximum number of taskq threads used。                       |
| data.parallel                     | Long          | Number of parallel.                                          |
| data.property_size                | Integer       | Max size for a MQTT property.                                |
| data.msq_len                      | Integer       | Queue length for resending messages.                         |
| data.qos_duration                 | Integer       | The interval of the qos timer.                               |
| data.allow_anonymous              | Boolean       | Allow anonymous login.                                       |
| data.tls.enable                   | Boolean       | Enable TLS listener.                                         |
| data.tls.url                      | String        | URL of TLS listener.                                         |
| data.tls.key                      | String        | User's private PEM-encoded key.                              |
| data.tls.keypass                  | String        | String containing the user's password. Only used if the private keyfile is password-protected. |
| data.tls.cert                     | String        | User certificate data.                                       |
| data.tls.cacert                   | String        | User's PEM-encoded CA certificates.                          |
| data.tls.verify_peer              | Boolean       | Verify peer certificate.                                     |
| data.tls.fail_if_no_peer_cert     | Boolean       | Server will fail if the client does not have a certificate to send. |
| data.websocket.enable             | Boolean       | Enable websocket listener.                                   |
| data.websocket.url                | String        | URL of websocket listener.                                   |
| data.websocket.tls_url            | String        | URL of TLS over websocket listerner.                         |
| data.http_server.enable           | Boolean       | Enable http server listerner.                                |
| data.http_server.port             | Integer       | Port of http server.                                         |
| data.http_server.username         | String        | User name of http server.                                    |
| data.http_server.password         | String        | Password of http server.                                     |
| data.bridge.bridge_mode           | Boolean       | Enter MQTT bridge mode .                                     |
| data.bridge.address               | String        | Remote Broker address.                                       |
| data.bridge.proto_ver             | String        | MQTT client version（3｜4｜5）。                             |
| data.bridge.clientid              | String        | MQTT client identifier.                                      |
| data.bridge.keepalive             | Integer       | Interval of keepalive.                                       |
| data.bridge.clean_start           | Boolean       | Clean seeson.                                                |
| data.bridge.parallel              | Long          | Parallel of mqtt client。                                    |
| data.bridge.username              | String        | Login user name.                                             |
| data.bridge.password              | String        | Login password.                                              |
| data.bridge.forwards              | Array[String] | Array of forward topics.                                     |
| data.bridge.forwards[0]           | String        | Topic.                                                       |
| data.bridge.subscription          | Array[Object] | Array of subscriptions.                                      |
| data.bridge.subscription[0].topic | String        | Topic.                                                       |
| data.bridge.subscription[0].qos   | Integer       | Qos.                                                         |

**Examples:**

```shell
$ curl -i --basic -u admin:public -X GET 'http://127.0.0.1:8081/api/v4/configuration' 
{
    "code": 0,
    "data": {
        "url": "nmq-tcp://0.0.0.0:1883",
        "num_taskq_thread": 4,
        "max_taskq_thread": 4,
        "parallel": 32,
        "property_size": 32,
        "msq_len": 64,
        "allow_anonymous": true,
        "daemon": false,
        "tls": {
            "enable": false,
            "url": "tls+nmq-tcp://0.0.0.0:8883",
            "key_password": null,
            "key": null,
            "cert": null,
            "cacert": null,
            "verify_peer": false,
            "fail_if_no_peer_cert": false
        },
        "websocket": {
            "enable": true,
            "url": "nmq-ws://0.0.0.0:8083/mqtt",
            "tls_url": "nmq-wss://0.0.0.0:8084/mqtt"
        },
        "http_server": {
            "enable": true,
            "port": 8081,
            "username": "admin",
            "password": "public",
            "auth_type": "basic"
        },
        "bridge": {
            "bridge_mode": false,
            "address": "mqtt-tcp://broker.emqx.io:1883",
            "proto_ver": 4,
            "clientid": "bridge_client",
            "clean_start": true,
            "username": "username",
            "password": "passwd",
            "keepalive": 60,
            "parallel": 2,
            "forwards": [
                "topic1/#",
                "topic2/#"
            ],
            "subscription": [
                {
                    "topic": "cmd/topic1",
                    "qos": 1
                },
                {
                    "topic": "cmd/topic2",
                    "qos": 2
                }
            ]
        }
    }
}
```



## Set Configuration

### POST /api/v4/configuration

Set configure parameters for broker.

**Parameters (json):**

| Name | Type   | Required | Value | Description                                  |
| ---- | ------ | -------- | ----- | -------------------------------------------- |
| data | Object | Required |       | See [Get Configuration](#Get Configuration). |

**Success Response Body (JSON):**

| Name | Type    | Description |
| ---- | ------- | ----------- |
| code | Integer | 0           |

**Examples:**

```shell
$ curl -i --basic -u admin:public -X POST 'http://localhost:8081/api/v4/configuration' -d \
'{
   "data": {
        "url": "nmq-tcp://0.0.0.0:1883",
        "num_taskq_thread": 8,
        "max_taskq_thread": 4,
        "parallel": 32,
        "property_size": 32,
        "msq_len": 64,
        "allow_anonymous": true,
        "daemon": false,
        "tls": {
            "enable": false,
            "url": "nmq-tls://0.0.0.0:8883",
            "key_password": null,
            "key": null,
            "cert": null,
            "cacert": null,
            "verify_peer": false,
            "fail_if_no_peer_cert": false
        },
        "websocket": {
            "enable": true,
            "url": "nmq-ws://0.0.0.0:8083/mqtt",
            "tls_url": "nmq-wss://0.0.0.0:8084/mqtt"
        },
        "http_server": {
            "enable": true,
            "port": 8081,
            "username": "admin",
            "password": "public",
            "auth_type": "basic"
        },
        "bridge": {
            "bridge_mode": false,
            "address": "127.0.0.1:1883",
            "proto_ver": 4,
            "clientid": "bridge_client",
            "clean_start": true,
            "username": "user",
            "password": "passwd",
            "keepalive": 60,
            "parallel": 1,
            "forwards": [
                "topic1/#",
                "topic2/#"
            ],
            "subscription": [
                {
                    "topic": "cmd/topic1",
                    "qos": 1
                }
            ]
        }
    }
}'

{"code":0}
```



## Broker Control

### POST /api/v4/ctrl/{action}

Stop or Restart the NanoMQ Broker（Usually used after the configuration is modified).

**Path Parameters:**

| Name     | Type   | Required | Description                             |
| -------- | ------ | -------- | --------------------------------------- |
| clientid | String | True     | Possible values are  `stop`,  `restart` |

**Success Response Body (JSON):**

| Name | Type    | Description |
| ---- | ------- | ----------- |
| code | Integer | 0           |

**Examples:**

```bash
$ curl -i --basic -u admin:public -X POST 'http://localhost:8081/api/v4/restart'

{"code":0}
```

