# HTTP Authorization Configuration

HTTP Authorization provides yet another method for authentication and authorization. It supports CONNECT requests, while PUBLISH & SUBSCRIBE are not implemented yet.

## Configuration Item

| Name                              | Type          | Description                                                  | default                                                      |
| --------------------------------- | ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| auth_http.enable                  | Boolean       | Enable HTTP authentication                                   | `false`                                                      |
| auth_http.auth_req.url            | String        | Specify the target URL of the authentication request.        | `http://127.0.0.1:80/mqtt/auth`                              |
| auth_http.auth_req.method         | String        | Specify the request method of the authentication request. (`POST` , `GET`) | `POST`                                                       |
| auth_http.auth_req.headers.<Any>  | String        | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.auth_req.headers.content-type = application/x-www-form-urlencoded` `auth_http.auth_req.headers.accept = */*` |
| auth_http.auth_req.params         | Array[Object] | Specify the data carried in the authentication request. When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows: `%u: Username` `%c: MQTT Client ID` `%a: Client's network IP address` `%r: The protocol used by the client can be:mqtt, mqtt-sn, coap, lwm2m and stomp` `%P: Password` `%p: Server port for client connection` `%C: Common Name in client certificate` `%d: Subject in client certificate` | `auth_http.auth_req.params = {clientid= "%c", username= "%u", password= "%P"}` |
| auth_http.super_req.url           | String        | Specify the target URL for the superuser authentication request. | `http://127.0.0.1:80/mqtt/superuser`                         |
| auth_http.super_req.method        | String        | Specifies the request method of the super user authentication request. (`POST` , `GET`) | `POST`                                                       |
| auth_http.super_req.headers.<Any> | String        | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded` `auth_http.super_req.headers.accept = */*` |
| auth_http.super_req.params        | Array[Object] | Specify the data carried in the authentication request. When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are the same as those of `auth_http.auth_req.params`. | `auth_http.super_req.params = {clientid= "%c", username= "%u", password= "%P"}` |
| auth_http.acl_req.url             | String        | Specify the target URL for ACL verification requests.        | `http://127.0.0.1:8991/mqtt/acl`                             |
| auth_http.acl_req.method          | String        | Specifies the request method for ACL verification requests. (`POST` , `GET`) | `POST`                                                       |
| auth_http.acl_req.headers.<Any>   | String        | Specify the data in the HTTP request header. `<Key>` Specify the field name in the HTTP request header, and the value of this configuration item is the corresponding field value. `<Key>` can be the standard HTTP request header field. User can also customize the field to configure multiple different request header fields. | `auth_http.super_req.headers.content-type = application/x-www-form-urlencoded` `auth_http.super_req.headers.accept = */*` |
| auth_http.acl_req.params          | Array[Object] | Specify the data carried in the authentication request. When using the **GET** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent as query string parameters. When using the **POST** method, the value of `auth_http.auth_req.params` will be converted into `k=v` key-value pairs separated by `&` and sent in the form of Request Body. All placeholders will be replaced by run-time data , and the available placeholders are as follows: `%A: Permission to be verified, 1 means subscription, 2 means publish` `%u: UserName` `%c: MQTT Client ID` `%a: Client network IP address` `%r: The protocol used by the client can be: mqtt, mqtt-sn, coap, lwm2m and stomp` `%m: Mount point` `%t: Topic` | `auth_http.acl_req.params = {clientid = "%c", username = "%u", access = "%A", ipaddr = "%a", topic = "%t", mountpoint = "%m"}` |
| auth_http.timeout                 | Integer       | HTTP request timeout. Any setting equivalent to `0s` means never timeout. | `5s`                                                         |
| auth_http.connect_timeout         | Integer       | Connection timeout for HTTP requests. Any setting value equivalent to `0s` means never time out. | `5s`                                                         |

## Configuration Example

```bash
authorization {
			sources = [
        type = http
        enable = false
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
		]
}
```

