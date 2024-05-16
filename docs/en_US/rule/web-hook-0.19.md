# Configure with WebHook

NanoMQ is furnished with an event-driven WebHook interface. This section provides an introduction to enabling the WebHook feature, outlines relevant configuration items, and elucidates how WebHook is triggered by specific topics or events.

The webhook configuration file is located in `etc/nanomq.conf`. NanoMQ offers 2 formats of configuration files:

- [HOCON (recommended, supported since v0.14 or above)](../config-description/webhook.md)
- [Key-Value format](../config-description/v013.md)

## Configure in HOCON

### Enable Webhook

```bash
webhook {
    ......
}
```
**Attention:** for NanoMQ 0-14 ~ 0.18 users, you also need to activate this feature with `webhook.enable = true`. For details, see [Configuration v0.14](../config-description/v014.md)

Since NanoMQ version 0.18, the `enable` option has been removed. To enable `webhook` configuration, simply add this module to the configuration file as shown above.

### Rule Syntax

NanoMQ provides the following configuration keys for WebHook:

- `event`: string, taking a fixed value.
- `topic`: a string, functioning like a topic filter, the messaging forwarding action is triggered only if the message topic matches the one specified in the rule. 

**Syntax**

```bash
webhook {
    ## Multi rules can be added here.
    events = [
        {
            <Rule>
        }
    ]
}
```

**Example**

For example, you want to forward messages matching the topics of `a/b/c` and `foo/#` to the web server, the configuration should be:

```bash
webhook {
    url = "http://127.0.0.1:80"
    headers.content-type = "application/json"
    body.encoding = plain
    pool_size = 32

    events = [
        {
            event = "on_message_publish"
            topic = "a/b/c"
        }
        {
            event = "on_message_publish"
            topic = "foo/#"
        }
    ]
}
```

### WebHook Trigger Events

WebHook can be triggered by the following events:

| Name                   | Description                  | **Execution timing**                               |
| ---------------------- | ---------------------------- | -------------------------------------------------- |
| on_client_connack      | Issue connection acknowledge | When the server is ready to send connack packet    |
| on_client_disconnected | disconnected                 | When the client connection is about to close |
| on_message_publish     | message published            | Before the broker publishes (routes) the message   |

### Event Parameters

When an event occurs, NanoMQ WebHook will package an HTTP request based on this event. The request is then sent to a pre-configured web server. 

The request format is:

```bash
URL: <url>      # From the url field in the configuration file
Method: POST    # Fixed as POST method

Body: <JSON>    # Body is a JSON format string
```

The `body` for different events may differ. The content of the `body` in each type of event are as following:

**on_client_connack**

| Key       | Type    | Description                                                  |
| --------- | ------- | ------------------------------------------------------------ |
| action    | string  | Event name<br />Value: "client_connack", cannot be modified  |
| clientid  | string  | Client's Client ID                                           |
| username  | string  | Client's Username, when there is no username, will use "undefined" |
| keepalive | integer | Heartbeat keepalive time applied by the client               |
| proto_ver | integer | Protocol version number （3 ｜ 4 ｜ 5）                      |
| conn_ack  | string  | "success" or failure                                         |

**on_client_disconnected**

| Key      | Type   | Description                                                  |
| -------- | ------ | ------------------------------------------------------------ |
| action   | string | Event name<br />Value: "client_disconnected", cannot be modified |
| clientid | string | Client's Client ID                                           |
| username | string | Client's Username, when there is no username, will use "undefined" |
| reason   | string | Error reasons                                                |

**on_message_publish**

| Key            | Type    | Description                                                  |
| -------------- | ------- | ------------------------------------------------------------ |
| action         | string  | Event name<br/>Value: "message_publish", cannot be modified  |
| from_client_id | string  | Publisher's Client ID                                        |
| from_username  | string  | Publisher's Username, when there is no username, will use "undefined" |
| topic          | string  | Topic                                                        |
| qos            | enum    | QoS level, and the optional value is `0` `1` `2`             |
| retain         | bool    | Whether it is a Retain message                               |
| payload        | string  | Message Payload                                              |
| ts             | integer | Timestamp (second)                                           |

### Configure Multiple Rules

NanoMQ supports defining multiple trigger rules through the configuration file. This section will demonstrate by defining two WebHook trigger rules as an example:

- Rule 1: When a message is sent to the "a/b/c" topic, trigger the WebHook. 
- Rule 2: When a client initiates a connection request, trigger the WebHook.

The sample configuration is as follows:

```bash
webhook {
    url = "http://127.0.0.1:80"
    headers.content-type = "application/json"
    body.encoding = plain
    pool_size = 32

    events = [
        {
            event = "on_message_publish"
            topic = "a/b/c"
        }
        {
            event = "on_client_connack"
        }
    ]
}
```

`event`: WebHook triggered event, string, supported events include:

- `on_client_connack`: Client connects
- `on_client_disconnected`: Client disconnects
- `on_message_publish`: Message published

`topic`: The topic that the message is published into, a string 

## Configure in Key-Value Format

### Enable Webhook

```bash
web.hook.enable = true
```

### Rule Syntax

The trigger rule's value is a JSON string, and the available Keys are:

- action: string, taking a fixed value
- topic: a string, indicating a topic filter, the operation topic can only trigger the forwarding of the event if it matches the topic

**Syntax**

```json
web.hook.rule.<Event>.<Number>=<Rule>
```

Note: You can configure multiple trigger rules for one event, and use `number` to differentiate the rules.

**Example**

For example, we only forward messages matching the topics of `a/b/c` and `foo/#` to the web server, and the configuration should be:

```json
web.hook.rule.message.publish.1 = {"action": "on_message_publish", "topic": "a/b/c"}
web.hook.rule.message.publish.2 = {"action": "on_message_publish", "topic": "foo/#"}
```

In this way, Webhook will only forward messages matching the topics of `a/b/c` and `foo/#`, such as `foo/bar`, etc., instead of forwarding `a/b/d` or `fo/bar`

### WebHook Trigger Events

The following events are currently supported:

| Name                | Description                  | **Execution timing**                               |
| ------------------- | ---------------------------- | -------------------------------------------------- |
| client.connack      | Issue connection acknowledge | When the server is ready to send connack packet    |
| client.disconnected | disconnected                 | When the client connection layer is about to close |
| message.publish     | message published            | Before the server publishes (routes) the message   |

### Event Parameters

When the event is triggered, Webhook will group each event into an HTTP request and send it to the pre-configured web server. The request format:

```bash
URL: <url>      # From the url field in the configuration
Method: POST    # Fixed as POST method

Body: <JSON>    # Body is a JSON format string
```

The `body` for different events may differ. The content of the `body` in each type of event are as following:

**client.connack**

| Key       | Type    | Description                                                  |
| --------- | ------- | ------------------------------------------------------------ |
| action    | string  | Event name<br />Value: "client_connack", cannot be modified  |
| clientid  | string  | Client's Client ID                                           |
| username  | string  | Client's Username, when there is no username, will use "undefined" |
| keepalive | integer | Heartbeat keepalive time applied by the client               |
| proto_ver | integer | Protocol version number （3 ｜ 4 ｜ 5）                      |
| conn_ack  | string  | "success" or failure                                         |

**client.disconnected**

| Key      | Type   | Description                                                  |
| -------- | ------ | ------------------------------------------------------------ |
| action   | string | Event name<br />Value: "client_disconnected", cannot be modified |
| clientid | string | Client's Client ID                                           |
| username | string | Client's Username, when there is no username, will use "undefined" |
| reason   | string | Error reasons                                                |

**message.publish**

| Key            | Type    | Description                                                  |
| -------------- | ------- | ------------------------------------------------------------ |
| action         | string  | Event name<br/>Value: "message_publish", cannot be modified  |
| from_client_id | string  | Publisher's Client ID                                        |
| from_username  | string  | Publisher's Username, when there is no username, will use "undefined" |
| topic          | string  | Topic                                           |
| qos            | enum    | QoS level, and the optional value is `0` `1` `2`             |
| retain         | bool    | Whether it is a Retain message                               |
| payload        | string  | Message Payload                                              |
| ts             | integer | Timestamp (second)                                           |
