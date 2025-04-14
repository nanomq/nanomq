# WebHook

In NanoMQ, the WebHook feature enables the broker to send HTTP requests to designated endpoints upon the occurrence of specific events. These events include client connections, message publications, session terminations, and more. This feature empowers you to integrate NanoMQ with other services and build complex event-driven architectures.

## **Example Configuration**

```hcl
webhook = {
  url = "http://127.0.0.1:80"        # URL where webhooks will send HTTP requests to
  headers.content-type = "application/json" # HTTP header specifying request content type
  body.encoding = "plain"            # Encoding format of the payload field in 
  cancel_timeout = 5000              # HTTP max timeout duration (ms)
  pool_size = 32                     # Connection process pool size
  events = [
    {
      event = "on_message_publish"   # Event type
      topic = "a/b/c"                # The specific topic that this event applies to
    }
    {
      event = "on_client_connack"    
    }
  ]
}
```

## **Configuration Items**

- `url`: The URL where webhooks will send HTTP requests to when events occur. This should be the endpoint of a service that can handle these requests appropriately.
- `headers.content-type`: Content type of the HTTP request included in the headers. For example, "application/json" means HTTP request's body will be formatted as a JSON object. 
- `body.encoding`: Encoding format of the payload field in the HTTP body. This field only appears in the `on_message_publish` and `on_message_delivered` events. The value can be `plain`, `base64`, or `base62`.
- `pool_size`: The connection process pool size. This determines the number of concurrent connections that webhooks can maintain with the endpoint specified in the `url`. Default: 32
- `cancel_timeout`: The HTTP connection waits `cancel_timeout` for reomte reply. 5 seconds by default. Exceed this settiong will result in Request canceled.
- `events`: An array of event objects. Each object specifies an event that can trigger a webhook:
  - `event`: Specify the type of the event that will trigger a webhook. The following events are supported:
    - `on_client_connack`
    - `on_client_disconnected`
    - `on_message_publish`
  - `topic`(Optional): For `on_message_publish` event, you can specify a particular topic. Webhooks are triggered only for messages published to this topic.

## Upcoming Features

**TLS**

TLS-related configuration items will be supported in upcoming releases, please stay tuned. 

```
tls {
   	keyfile="/etc/certs/key.pem"
  	certfile="/etc/certs/cert.pem"
  	cacertfile="/etc/certs/cacert.pem"
}
```

**Event**

More events will be supported in upcoming releases, please stay tuned. 

- `on_client_connect`
- `on_client_connected`
- `on_client_subscribe`
- `on_client_unsubscribe`
- `on_session_subscribed`
- `on_session_unsubscribed`
- `on_session_terminated`
- `on_message_delivered`
- `on_message_acked`
