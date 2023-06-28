# HTTP Authorization Configuration

HTTP Authorization provides yet another method for authentication and authorization. It supports CONNECT requests, while PUBLISH & SUBSCRIBE are not implemented yet.

## Configuration Item

| Name                              | Type | Description                                                     | default                                                         |
| ----------------------------------- | -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth.http_auth.auth_req.url              | String   | Specify the target URL of the authentication request. | `http://127.0.0.1:80/mqtt/auth`                              |
| auth.http_auth.auth_req.method           | String     | Specify the request method of the authentication request.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth.http_auth.auth_req.headers.\<Any\>  | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth.http_auth.auth_req.headers.content-type = application/x-www-form-urlencoded` <br/>`auth.http_auth.auth_req.headers.accept = */*` |
| auth.http_auth.auth_req.params           | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows:<br>`%u: Username`<br>`%c: MQTT Client ID`<br>`%a: Client's network IP address`<br>`%r: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp`<br>`%P: Password`<br>`%p: Server port for client connection`<br>`%C: Common Name in client certificate`<br>`%d: Subject in client certificate` | `auth.http_auth.auth_req.params = {clientid= "%c", username= "%u", password= "%P"}`                        |
| auth.http_auth.super_req.url             | String   | Specify the target URL for the superuser authentication request. | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth.http_auth.super_req.method          | String   | Specifies the request method of the super user authentication request.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth.http_auth.super_req.headers.\<Any\> | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth.http_auth.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http_auth.super_req.headers.accept = */*` |
| auth.http_auth.super_req.params          | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are the same as those of `auth.http_auth.auth_req.params`. | `auth.http_auth.super_req.params = {clientid= "%c", username= "%u", password= "%P"}`                                    |
| auth.http_auth.acl_req.url               | String   | Specify the target URL for ACL verification requests. | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth.http_auth.acl_req.method            | String   | Specifies the request method for ACL verification requests.<br>(`POST`  , `GET`) | `POST`                                                       |
| auth.http_auth.acl_req.headers.\<Any\>   | String   | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth.http_auth.super_req.headers.content-type = application/x-www-form-urlencoded`<br/>`auth.http_auth.super_req.headers.accept = */*` |
| auth.http_auth.acl_req.params            | Array[Object]    | Specify the data carried in the authentication request. <br>When using the **GET** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. <br>When using the **POST** method, the value of `auth.http_auth.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows:<br/>`%A: Permission to be verified, 1 means subscription, 2 means publish`<br>`%u: UserName`<br/>`%c: MQTT Client ID`<br/>`%a: Client network IP address`<br/>`%r: The protocol used by the client can be: mqtt, mqtt-sn, coap, lwm2m and stomp`<br/>`%m: Mount point`<br>`%t: Topic` | `auth.http_auth.acl_req.params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}` |
| auth.http_auth.timeout                   | Integer  | HTTP request timeout. Any setting equivalent to `0s` means never timeout. | `5s`                                                         |
| auth.http_auth.connect_timeout           | Integer  | Connection timeout for HTTP requests. Any setting value equivalent to `0s` means never time out. | `5s`                                                         |

Example :

If you need to use `http_auth`, you can modify it in the format of the following example, and then put the configuration of `http_auth` into the `auth {}` configuration.

```bash
http_auth = {
  auth_req {
    url = "http://127.0.0.1:80/mqtt/auth"
    method = post
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", password = "%p"}
  }

  super_req {
    url = "http://127.0.0.1:80/mqtt/superuser"
    method = "post"
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", password = "%p"}
  }

  acl_req {
    url = "http://127.0.0.1:8991/mqtt/acl"
    method = "post"
    headers.content-type = "application/x-www-form-urlencoded"
    params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}
  }

  timeout = 5s
  connect_timeout = 5s
  pool_size = 32
}
```