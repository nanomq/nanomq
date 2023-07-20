# WebHook

Webhook in NanoMQ allows the broker to send HTTP requests to specified endpoints when certain events occur. These events include client connections, message publications, session terminations, and more. With this feature, you can integrate NanoMQ with other services and build complex event-driven architectures.

**Example Configuration**

```hcl
webhook = {
  url = "http://127.0.0.1:80"        # URL where the webhook will send HTTP requests
  headers.content-type = "application/json" # HTTP header specifying request content type
  body.encoding = "plain"            # Encoding format of the payload field in HTTP body
  pool_size = 32                     # Connection process pool size
  events = [
    {
      event = "on_message_publish"   # Webhook will trigger when a message is published
      topic = "a/b/c"                # The specific topic that this event applies to
    }
    {
      event = "on_client_connack"    # Webhook will trigger when a client ACK is received
    }
  ]
}
```

**Configuration Items**

- `url`: Specifies the URL that the webhook will send HTTP requests to when the specified events occur. This should be the endpoint of a service that can handle these requests appropriately.
- `headers.content-type`:  Defines the HTTP header for the content type of the request. For example, "application/json", meaning that the body of the HTTP request will be formatted as a JSON object.
- `body.encoding`: Specifies the encoding format of the payload field in the HTTP body. This field only appears in the `on_message_publish` and `on_message_delivered` events. The value can be `plain`, `base64`, or `base62`.
- `pool_size`: Specifies the connection process pool size. This determines the number of concurrent connections that the webhook can maintain with the endpoint specified in the `url`.
- `events`: This is an array of event objects. Each object specifies an event that will trigger the webhook:
  - `event`: Specifies the name of the event that will trigger the webhook. The supported events include:
    - `on_client_connect`
    - `on_client_connack`,
    - `on_client_connected`
    - `on_client_disconnected`
    - `on_client_subscribe`
    - `on_client_unsubscribe`
    - `on_session_subscribed`
    - `on_session_unsubscribed`
    - `on_session_terminated`
    - `on_message_publish`
    - `on_message_delivered`
    - `on_message_acked`
  - `topic`(Optional): For the `on_message_publish` event, you can specify a particular topic. The webhook will only trigger for messages published to this topic.