# HTTP API

Nanomq Broker provides HTTP APIs for integration with external systems, such as querying broker statistics information, clients information, subscribe topics information, and restart with new config file .

Nanomq Broker's HTTP API service listens on port 8081 by default. You can modify the listening port through the configuration file of `etc/nanomq.conf`. All API calls with `api/v1`.

## Interface security

Nanomq Broker's HTTP API uses the method of [Basic Authentication (opens new window)](https://en.wikipedia.org/wiki/Basic_access_authentication). The `id` and `password` must be filled with AppID and AppSecret respectively. The default AppID and AppSecret are: `admin/public`. You can modify username and password through the configuration file of `etc/nanomq.conf`.

## Response code

### HTTP status codes

The Nanomq Broker interface always returns 200 OK when the call is successful, and the response content is returned in JSON format.

The possible status codes are as follows:

| Status Code | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| 200         | Succeed, and the returned JSON data will provide more information |
| 400         | Invalid client request, such as wrong request body or parameters |
| 401         | Client authentication failed , maybe because of invalid authentication credentials |
| 404         | The requested path cannot be found or the requested object does not exist |
| 500         | An internal error occurred while the server was processing the request |

### result codes

The response message body of the Nanomq Broker interface is in JSON format, which always contains the returned `code`.

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

## API Endpoints | POST /api/v1

### Broker info

Returns the information of broker.

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 2      | The req equal 2 is used call rest api to get broker info.    |
| seq  | Integer | Required | unique | The seq is a unique number, response will carry this field. So you can know correspondence between request and response. |

**Success Response Body (JSON):**

| Name              | Type    | Description                                                  |
| ----------------- | ------- | ------------------------------------------------------------ |
| code              | Integer | 0                                                            |
| seq               | Integer | The seq is a unique number, response get this value from request. So you can know correspondence between request and response. |
| rep               | Integer | The rep equal 2 as response to req equal 2.                  |
| data.client_size  | Integer | Subscribe client size.                                       |
| data.message_in   | Integer | Statistic broker  message in.                                |
| data.message_out  | Integer | Statistic broker message out.                                |
| data.message_drop | Integer | Statistic broker message drop.                               |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 2,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":2,"data":{"client_size":1,"message_in":4,"message_out":0,"message_drop":4}}
```

### Topic info

Returns the information of all subscribe topics with client identifier and qos.

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 4      | The req equal  4 is used call rest api to get topics info.   |
| seq  | Integer | Required | unique | The seq is a unique number, response will carry this field. So you can know correspondence between request and response. |

**Success Response Body (JSON):**

| Name                           | Type    | Description                                                  |
| ------------------------------ | ------- | ------------------------------------------------------------ |
| code                           | Integer | 0                                                            |
| seq                            | Integer | The seq is a unique number, response get this value from request. So you can know correspondence between request and response. |
| rep                            | Integer | The rep equal 4 as response to req equal 4.                  |
| data[0].client_id              | String  | client identifier.                                           |
| data[0].subscriptions[0].topic | String  | Subscribe topic.                                             |
| data[0].subscriptions[0].qos   | Integer | Subscribe qos.                                               |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 4,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":4,"data":[{"client_id":"nanomq-ebd54382","subscriptions":[{"topic":"a/b/c","qos":0}]}]}
```

#### Client info

Returns the information of all clients.

**Parameters (json):**

| Name | Type    | Required | Value  | Description                                                  |
| ---- | ------- | -------- | ------ | ------------------------------------------------------------ |
| req  | Integer | Required | 5      | The req equal  5 is used call rest api to get clients info.  |
| seq  | Integer | Required | unique | The seq is a unique number, response will carry this field. So you can know correspondence between request and response. |

**Success Response Body (JSON):**

| Name                    | Type    | Description                                                  |
| ----------------------- | ------- | ------------------------------------------------------------ |
| code                    | Integer | 0                                                            |
| seq                     | Integer | The seq is a unique number, response get this value from request. So you can know correspondence between request and response. |
| rep                     | Integer | The rep equal 5 as response to req equal 5.                  |
| data[0].client_id       | String  | client identifier.                                           |
| data[0].username        | String  | Username.                                                    |
| data[0].keepalive       | Integer | Keepalive.                                                   |
| data[0].protocol        | Integer | Protocol version.                                            |
| data[0].connect_status  | Integer | Connected status.                                            |
| data[0].message_receive | Integer | Received message of this client.                             |

#### **Examples:**

```shell
$ curl -i --basic -u admin:public -X POST "http://localhost:8081/api/v1" -d '{"req": 5,"seq": 1111111}'
{"code":0,"seq":1111111,"rep":5,"data":[{"client_id":"nanomq-ebd54382","username":"nanmq","keepalive":60,"protocol":4,"connect_status":1,"message_receive":0}]
```

