# Configure with WebHook

## Configuration item

The webhook configuration file is located in: `etc/nanomq.conf`, the detailed description of configuration items can be found in [Configuration item](../config-description/v014.md).

**Enable Webhook**

```bash
webhook {
    ......
}
```
**📢 Attention:** Starting from NanoMQ version 0.18, the `enable` option has been removed. Therefore, to enable the `webhook` configuration, simply add this module to the configuration file as shown above.

## Trigger rule

Trigger rules can be configured in `etc/nanomq.conf`.  The configuration format is as follows:

```bash
## Format example
webhook.events = [
    ## Multi rules can be added here.
    {
        <Rule>
    }
]

## Example
webhook.events = [
	url = "http://127.0.0.1:80"
	headers.content-type = "application/json"
	body.encoding = plain
	pool_size = 32

	{ 
		# # Webhook event.
		# #
		# # Value: String
		# # Supported event list:
		# # event: on_client_connack
		# # event: on_client_disconnected
		# # event: on_message_publish
		event = "on_message_publish"

		# # Webhook topic.
		# #
		# # Value: String
		# # Support on message publish
		topic = "a/b/c"
	}
	{
		event = "on_client_connack"
	}
]

```

### Trigger event

The following events are currently supported:

| Name                   | Description                  | **Execution timing**                               |
| ---------------------- | ---------------------------- | -------------------------------------------------- |
| on_client_connack      | Issue connection acknowledge | When the server is ready to send connack packet    |
| on_client_disconnected | disconnected                 | When the client connection layer is about to close |
| on_message_publish     | message published            | Before the server rpublishes (routes) the message  |

### Rule

The trigger rule's 'value is a JSON string, and the available Keys are:

- event: string, taking a fixed value
- topic: a string, indicating a topic filter, the operation topic can only trigger the forwarding of the event if it matches the topic

For example, we only forward messages matching the topics of `a/b/c` and `foo/#` to the web server, and the configuration should be:

```bash
webhook.events = [
	{ 
		event = "on_message_publish"
		topic = "a/b/c"
	}
	{
		event = "on_message_publish"
		topic = "foo/#"
	}
]
```

In this way, Webhook will only forward messages matching the topics of `a/b/c` and `foo/#`, such as `foo/bar`, etc., instead of forwarding `a/b/d` or `fo/bar`

## Webhook event parameters

When the event is triggered, Webhook will group each event into an HTTP request and sent it to the web server configured by url according to the configuration. The request format is:

```bash
URL: <url>      # From the url field in the configuration
Method: POST    # Fixed as POST method

Body: <JSON>    # Body is a JSON format string
```

For different events, the content of the request body is different. The following table lists the parameters of the body in each event:

**on_client_connack**

| Key       | Type    | Description                                                 |
| --------- | ------- | ----------------------------------------------------------- |
| action    | string  | event name<br/>fixed at: "client_connack"                   |
| clientid  | string  | client ClientId                                             |
| username  | string  | client Username, When not existed, the value is "undefined" |
| keepalive | integer | Heartbeat keepalive time applied by client                  |
| proto_ver | integer | Protocol version number （3 ｜ 4 ｜ 5）                     |
| conn_ack  | string  | "success" means success, other means failure                |

**on_client_disconnected**

| Key      | Type   | Description                                                 |
| -------- | ------ | ----------------------------------------------------------- |
| action   | string | event name<br/>fixed at: "client_disconnected"              |
| clientid | string | client ClientId                                             |
| username | string | client Username, When not existed, the value is "undefined" |
| reason   | string | error reason                                                |

**on_message_publish**

| Key            | Type    | Description                                                  |
| -------------- | ------- | ------------------------------------------------------------ |
| action         | string  | event name<br/>fixed at: "message_publish"                   |
| from_client_id | string  | Publisher's ClientId                                         |
| from_username  | string  | Publisher's Username, When not existed, the value is "undefined" |
| topic          | string  | Unsubscribed topic                                           |
| qos            | enum    | QoS level, and the optional value is `0` `1` `2`             |
| retain         | bool    | Whether it is a Retain message                               |
| payload        | string  | Message Payload                                              |
| ts             | integer | Timestamp (second)                                           |