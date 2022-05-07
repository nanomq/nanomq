# WebHook



## Configuration item

The webhook configuration file is located in: `etc/nanomq_web_hook.conf`, the detailed description of configuration items can be found in [Configuration item](./config-description.md).

**Enable Webhook**

```bash
web.hook.enable=true
```

## Trigger rule

Trigger rules can be configured in `etc/nanomq_web_hook.conf`.  The configuration format is as follows:

```bash
## Format example
web.hook.rule.<Event>.<Number>=<Rule>

## Example
web.hook.rule.message.publish.1={"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2={"action": "on_message_publish", "topic": "foo/#"}
```

### Trigger event

The following events are currently supported:

| Name                | Description                  | **Execution timing**                               |
| ------------------- | ---------------------------- | -------------------------------------------------- |
| client.connack      | Issue connection acknowledge | When the server is ready to send connack packet    |
| client.disconnected | disconnected                 | When the client connection layer is about to close |
| message.publish     | message published            | Before the server rpublishes (routes) the message  |

### Number

Multiple trigger rules can be configured for the same event, and events with the same configuration should be incremented in sequence.

### Rule

The trigger rule's 'value is a JSON string, and the available Keys are:

- action: string, taking a fixed value
- topic: a string, indicating a topic filter, the operation topic can only trigger the forwarding of the event if it matches the topic

For example, we only forward messages matching the topics of `a/b/c` and `foo/#` to the web server, and the configuration should be:

```bash
web.hook.rule.message.publish.1 = {"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}
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

**client.connack**

| Key       | Type    | Description                                                 |
| --------- | ------- | ----------------------------------------------------------- |
| action    | string  | event name<br/>fixed at: "client_connack"                   |
| clientid  | string  | client ClientId                                             |
| username  | string  | client Username, When not existed, the value is "undefined" |
| keepalive | integer | Heartbeat keepalive time applied by client                  |
| proto_ver | integer | Protocol version number （3 ｜ 4 ｜ 5）                     |
| conn_ack  | string  | "success" means success, other means failure                |

**client.disconnected**

| Key      | Type   | Description                                                 |
| -------- | ------ | ----------------------------------------------------------- |
| action   | string | event name<br/>fixed at: "client_disconnected"              |
| clientid | string | client ClientId                                             |
| username | string | client Username, When not existed, the value is "undefined" |
| reason   | string | error reason                                                |

**message.publish**

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