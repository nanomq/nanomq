# Data Bridges

Bridging is a way to connect multiple MQTT brokers. Unlike swarms, topic trees, and routing tables are not replicated between nodes operating in bridge mode. This is how data bridges work:

- Forward the message to the bridge node according to the rules;
- Subscribe to the topic from the bridge node, and forward the message to this node/group after collecting the message.

## MQTT over TCP Bridge

In NanoMQ, the MQTT over TCP Bridge configuration is used to specify settings for the MQTT Bridge that uses TCP as its transport protocol. This allows NanoMQ to communicate with remote MQTT servers and exchange MQTT messages with them.

### **Example Configuration**

```hcl
bridges.mqtt.emqx1 = {
  server = "mqtt-tcp://127.0.0.1:1883"    # MQTT server address
  proto_ver = 4                           # MQTT protocol version
  clientid = "bridge_client"              # Client ID for the bridge
  keepalive = "60s"                       # Ping interval for the bridge
  clean_start = false                     # Clean start flag for the bridge
  username = "username"                   # Username for the bridge
  password = "passwd"                     # Password for the bridge
  will = {                                # Will properties
  	topic = "will_topic"                  # Will topic
  	qos = 1                               # Will QoS
  	retain = false                        # Will payload retain flag
  	payload = "will_message"              # Will payload
  	properties = {                        # Will properties
    	payload_format_indicator = 0
    	message_expiry_interval = 0
    	content_type = ""
    	response_topic = ""
    	correlation_data = ""
    	will_delay_interval = 0
    	user_property = {
      	key1 = "value1"
      	key2 = "value2"
    	}
  	}
  }
  ssl = {                                 # SSL configuration
    key_password = "yourpass"             # SSL key password
    keyfile = "/etc/certs/key.pem"        # SSL keyfile
    certfile = "/etc/certs/cert.pem"      # SSL cert file
    cacertfile = "/etc/certs/cacert.pem"  # SSL CA cert file
  }
  
  forwards = [                            # Topics that need to be forwarded to the remote MQTT server
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
      suffix = "/emqx"
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
      prefix = "emqx/"
    }
  ]     
  subscription = [                        # Topics that need to be subscribed from the remote MQTT server
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
      retain = 2                          # flag to override retain flag
      suffix = "/emqx"
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  tcp = {
    bind_interface = wlan0
    nodelay = false
    quickack = true
    keepalive = true
    keepidle = 60000
    keepintvl = 30000
    keepcnt = 1000
    sendtimeo = 3000
    recvtimeo = 8000
  }
  max_parallel_processes = 2              # Maximum number of parallel processes for handling outstanding requests
  max_send_queue_len = 32                 # Maximum number of message send queue length
  max_recv_queue_len = 128                # Maximum number of message receive queue length
}
```

This configuration enables NanoMQ to establish an MQTT over TCP bridge connection to a remote MQTT server, using will message and secure communication with SSL.

### **Configuration Items**

- bridges.mqtt.\<name>: Specifies the name of the bridge. 
- `server`: Specifies the MQTT server address for the bridge. Example: 
  - `mqtt-tcp://127.0.0.1:1883` for MQTT over TCP bridge
  - `tls+mqtt-tcp://127.0.0.1:8883` for MQTT over TCP bridge with SSL eneabled
  - `mqtt-quic://54.75.171.11:14567` for MQTT over QUIC bridge

- `proto_ver`: Specifies the MQTT protocol version to use. Options:
  - `5` for MQTT v5
  - `4` for MQTT v3.1.1
  - `3` for MQTT v3.1
- `clientid`: Specifies the client ID for the bridge.
- `keepalive`: Specifies the ping interval for the bridge.
- `clean_start`: Specifies the clean start flag for the bridge. **Note**: Some IoT platforms require this to be set to `false`.
- `username`: Specifies the username for the bridge.
- `password`: Specifies the password for the bridge.
- `ssl`: Contains settings for SSL/TLS security:
  - `key_password`: Specifies the password for the client's private key file, if it's password-protected.
  - `keyfile`: Specifies the path to the client's private key file.
  - `certfile`: Specifies the path to the client's certificate file.
  - `cacertfile`: Specifies the path to the server's root CA certificate file. This certificate is used to identify the AWS IoT server.
- `forwards`: This is an array of topics that need to be forwarded to the remote MQTT server, including
  - `remote_topic`: Topics refection topic, will change the topic in publish msg. Just leave `remote_topic=""` to preserve the original topic in msg   
  - `local_topic`: Topics that need to be forwarded to the remote MQTT server.
  - `qos`: overwrite original QoS level of Publish msg, this is optional.
  - `suffix`: A suffix string will be added to the remote topic(add to the original topic if you leave remote_topic as null)
  - `prefix`: A prefix string will be added to the remote topic(add to the original topic if you leave remote_topic as null)
- `subscription`: This is an array of topic objects that need to be subscribed from the remote MQTT server. Each object defines a topic and the QoS level for the subscription(!Be aware that only the first rule takes effect if you configure multiple overlapping rules). Including
  - `remote_topic`: The topic filter used to subscribe to the remote broker.
  - `local_topic`: This is for Topic reflection, if you want the vanila way, then just leave `local_topic=""` to preserve the original topic in msg from remote broker.

  ::: tip
  
  `local_topic` of `subscription` section works differently from `forwards` part. In order to ease the work of managing local & remote topic relationship (frequently asked feature from community), since 0.23.7, the topic remapping feature is introduced, which includes the ability to strip or replace parts of the topic with the help of wildcards. Specifically, the wildcard acts as the string searching anchor here for users to preserve the matching parts.
  For example:
    `remote_topic = "+/nanomq/#"`
    `local_topic = "#"`
    And downward message is from topic `cmd/nanomq/hello/world`, then you get a message with topic `hello/world` locally.

  :::

  - `qos`: Define the QoS in the subscribe packet. This is a must. 
  - `retain`: a flag to override retain flag.
  - `retain_as_published`: an optional item for the MQTTv5 feature, Retain As Published.
  - `retain_handling`: an optional item for MQTTv5 feature, Retain Handling.
  - `suffix`: A suffix string will be added to the local topic(add to the original topic if you leave local_topic as null)
  - `prefix`: A prefix string will be added to the local topic(add to the original topic if you leave local_topic as null)

  ::: tip

  `tcp` section allows fine tuning of TCP options, which are equals to socket options in POSIX standard. (https://www.man7.org/linux/man-pages/man7/tcp.7.html)
  the `nodelay` option is slight different, despite its original meaning. It also serves as the switch of a fail interface binding action. `true` keeps retrying. `false` ignore fales, skip this time.

  :::

- `max_parallel_processes`: Specifies the maximum number of parallel processes for handling outstanding requests.
- `max_send_queue_len`: Specifies the maximum number of messages that can be queued for sending. Since 0.23.1, It also takes effect while TCP connection is explicitly closed, which gurantees no msg lost till cache queue is full.
- `max_recv_queue_len`: Specifies the maximum number of messages that can be queued for processing. 

### **MQTT 5** 

If MQTT v5 is used (`proto_ver = 5`), the following configuration items are also supported:

**Connection related:**

| Configuration Item                             | Description                                                  | Value Range                      |
| ---------------------------------------------- | ------------------------------------------------------------ | -------------------------------- |
| `conn_property.maximum_packet_size`            | Specifies the maximum packet size for the MQTT connection    | 1 - 4294967295                   |
| `conn_properties.receive_maximum`              | Limits the number of QoS 1 and QoS 2 publications that the client can process concurrently. This only applies to the current network connection. <br />If left unconfigured, it will use the default value: 65535. <!--to be confirmed--> | 1 - 65535                        |
| `conn_properties.topic_alias_maximum`          | Specifies the highest value that the client will accept as a Topic Alias sent by the server. Used to limit the number of Topic Aliases that the client is willing to hold on this connection | 0 - 65535                        |
| `conn_properties.request_problem_information`  | Specifies if the server should send additional diagnostic information (i.e., a Reason String or User Properties) in case of failures:  <br /><br />- If set to 0, the server is allowed to include additional diagnostic information only when responding with PUBLISH, CONNACK or DISCONNECT packets. For all other packet types, the server must not include this information. If the server violates this rule, the client will disconnect and report a Protocol Error. <!--to be confirmed--><br /><br />-  If set to 1, the server has the discretion to include additional diagnostic information in any type of packet where it's allowed. | 0 or 1                           |
| `conn_properties.request_response_information` | Specifies whether to request the server to return Response Information in the CONNACK. <br /><br />- If set to 0, the server must not return Response Information.<br /><br />-  If set to 1, the server may return Response Information in the CONNACK packet | 0 or 1                           |
| `conn_properties.session_expiry_interval`      | Specifies the session expiry interval.<br /><br />- If set to 0, the session ends when the network connection is closed.<br /><br />- If set to 4294967295 (UINT_MAX), the session will never expire | 0 - 4294967295                   |
| `conn_properties.user_property`                | A map of key-value pairs. Allowed to appear multiple times to represent multiple name-value pairs. The same name is allowed to appear more than once. | Map[key(String) - value(String)] |

**Subscription Related**

| Configuration Item             | Description             | Value Range                       |
| ------------------------------ | ----------------------- | --------------------------------- |
| `sub_properties.identifier`    | Subscription Identifier | 1 ~ 268,435,455                   |
| `sub_properties.user_property` | User Property           | Map[key(String) - value(String)]* |

### **Will Message**

The above example configuration also leverages the feature of will messages. In MQTT, a Will Message is a message that is set up at the time of establishing the MQTT connection from the client to the broker. This message is stored at the broker and is forwarded to the specified topics when the broker detects that the client has disconnected unexpectedly. The main purpose of the Will Message is to notify other clients about an ungracefully disconnected client. Below are detailed explain of the will message related configuration items:

- `will.topic`: Specifies the topic on which the Will Message should be published.

- `will.payload`: Specifies the payload of the Will Message. This is typically a message that informs others about the disconnection.
- `will.qos`: Specifies the QoS level for the Will Message. It can be 0 (At most once), 1 (At least once), or 2 (Exactly once).
- `will.retain`: Specifies whether the Will Message should be retained by the broker or not. If set to true, the Will Message is stored on the broker and is sent to any future subscribers of the topic.
- `will.properties`: 
  - `payload_format_indicator`: Specifies the format of the Will Message's payload. It can take the values 0 or 1. A value of 0 indicates an unspecified byte stream, and 1 indicates a UTF-8 encoded string.
  - `message_expiry_interval`: Specifies the period of time (in seconds) that the broker should hold the Will Message. If left unconfigured, the message will never expire. 
  - `content_type`: Specifies the content type of the Will Message's payload, allowing to interpret the data contained in the payload.
  - `response_topic`: Specifies the topic for the response to the Will Message. Other clients can use this topic to send a response to the Will Message.
  - `correlation_data`: Specifies binary data that is used for correlating the response with the Will Message.
  - `will_delay_interval`: Specifies the delay between the ungraceful disconnection of the client and the moment when the broker publishes the Will Message. It's expressed in seconds. Note: the default value 0 indicates there is non delay before the Will Message is published. 
  - `user_property`: Specifies a set of user-defined key-value pairs. This can be used for sending additional custom data in format of `key1 = value1`.

## MQTT over QUIC Bridge

This part introduces the settings for the MQTT Bridge that uses QUIC as its transport protocol. QUIC is a modern transport protocol that provides reliable, secure communication with improved performance compared to TCP.

### **Example Configuration**

```hcl
bridges.mqtt.emqx1 = {
  server = "mqtt-quic://127.0.0.1:14567"  # MQTT server address
  proto_ver = 4                           # MQTT protocol version
  clientid = "bridge_client"              # Client ID for the bridge
  keepalive = "60s"                       # Ping interval for the bridge
  clean_start = false                     # Clean start flag for the bridge
  username = "username"                   # Username for the bridge
  password = "passwd"                     # Password for the bridge
  quic_keepalive = "120s"                 # Ping interval for the bridge using QUIC
  quic_idle_timeout = "120s"              # Idle timeout for the bridge using QUIC
  quic_discon_timeout = "20s"             # Disconnect timeout for the bridge using QUIC
  quic_handshake_timeout = "60s"          # Handshake timeout for the bridge using QUIC
  quic_send_idle_timeout = "2s"           # Send idle timeout for the bridge using QUIC
  quic_initial_rtt_ms = "800ms"           # Initial Round-Trip Time (RTT) estimate for QUIC
  quic_max_ack_delay_ms = "100ms"         # Maximum Acknowledgement (ACK) delay for QUIC
  hybrid_bridging = false                 # Enable or disable the hybrid bridging mode
  quic_multi_stream = false               # Enable or disable the multi-stream bridging mode
  quic_qos_priority = true                # Send QoS 1/2 messages in high priority
  quic_0rtt = true                        # Enable or disable 0-RTT, QUIC feature for quick re-establishment of connections
  forwards = [                            # Topics that need to be forwarded to the remote MQTT server
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
      qos = 1
    },
    {
      remote_topic = ""
      local_topic = "topic2"
      qos = 2
      prefix = "emqx/"
      suffix = "/nanomq"
    }
  ]     
  subscription = [                        # Topics that need to be subscribed from the remote MQTT server
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  max_parallel_processes = 2              # Maximum number of parallel processes for handling outstanding requests
  max_send_queue_len = 32                 # Maximum number of message send queue length
  max_recv_queue_len = 128                # Maximum number of message receive queue length
}
```

#### **Configuration Items**

This part will focus on the MQTT over QUIC bridge-related configuration items, for other configuration items not included here, you may refer to [MQTT over TCP Bridge](#mqtt-over-tcp-bridge).

- Server: Specifies the MQTT server address for the bridge. For MQTT over QUIC bridge, it should be, for example, `mqtt-quic://54.75.171.11:14567` 
- `quic_keepalive`: Specifies the interval for sending keep-alive packets over QUIC. The default is 120 seconds.
- `quic_idle_timeout`: Specifies the maximum amount of time a connection can remain idle before it is gracefully shut down. Setting it to 0 disables the timeout, but this could result in lost disconnect event messages. The default is 120 seconds.
- `quic_discon_timeout`: Specifies the maximum amount of time to wait for an acknowledgment (ACK) before declaring a path dead and disconnecting. This setting affects the lifespan of the stream. The default is 20 seconds.
- `quic_handshake_timeout`: Specifies the maximum amount of time to wait for a QUIC connection to be established. If the handshake process takes longer than this, it is discarded. The default is 60 seconds.
- `quic_send_idle_timeout`:  Resets the congestion control after being idle for a specified amount of time. The default is 60 seconds.
- `quic_initial_rtt_ms`: Specifies the initial estimate for the round-trip time (RTT) in milliseconds. The default is 800 milliseconds.
- `quic_max_ack_delay_ms`: Specifies the maximum amount of time to wait after receiving data before sending an ACK. The default is 100 milliseconds.
- `hybrid_bridging`: Specifies whether to enable the hybrid bridging mode. The default is `false`.
- `hybrid_servers`: Specifies hybrid servers. The default is `[]`.
- `quic_multi_stream`: Specifies whether to enable the multi-stream bridging mode. This is a work-in-progress feature and should not be enabled. The default is `false`.
- `quic_qos_priority`: This sends QoS 1/2 messages with high priority, while QoS 0 messages remain the same. The default is `true`.
 - `quic_0rtt`: Specifies whether to enable the 0RTT feature of QUIC, which allows connections to be re-established quickly. The default is `true`.

::: tip

The SSL configuration is invalid when operating in MQTT over QUIC mode.

:::

## MQTT Bridges Cache

NanoMQ provides the functionality to configure multiple data bridges by utilizing the `nanomq.conf` configuration files. Each bridge can be distinctly identified by unique names. Furthermore, the "cache" configuration is a standalone component that can be commonly used across these data bridges. For instance, if you need to implement message caching in more than one data bridge, you can effortlessly incorporate the cache component as illustrated below.

### **Example Configuration**

```hcl
## First bridge client
bridges.mqtt.emqx1 {
  retry_qos_0 = true
  ......
  resend_interval = 5000    # Resend interval (ms)
  resend_wait = 3000
  cancel_timeout  = 10000
}

## Second bridge client
bridges.mqtt.emqx2 {
  retry_qos_0 = false
  ......
  resend_interval = 5000    # Resend interval (ms)
  resend_wait = 3000
  cancel_timeout  = 10000
}

bridges.mqtt.cache {
    disk_cache_size = 102400   # Max message limitation for caching
    mounted_file_path="/tmp/"  # Mounted file path 
    flush_mem_threshold = 100  # The threshold of flushing messages to flash
}
```

### **Configuration Items**

- `retry_qos_0`: Specifies the maximum level of QoS that can be cached in the MQTT bridges. Set to `false` will disable QoS 0 message cache, Which reserve disk space for MQTT QoS 1/2. This is helpful when prioritization is required.
- `disk_cache_size`: Specifies the maximum number of messages that can be cached in the MQTT bridges. A value of 0 indicates that the cache for messages is inefficient.
- `mounted_file_path`: Specifies the file path where the cache file for the MQTT bridges is mounted.
- `flush_mem_threshold`: Specifies the threshold for flushing messages to the cache file. When the number of messages reaches this threshold, they will be flushed to the cache file.
- `resend_interval`: Specifies the interval, in milliseconds, for resending the messages interval. Only takes effect in bridging. This is a timer per bridging connection, also in charge of sending PINGREQ, resending msg cached in SQLite and healthy checking. Please set it with cautious.
  -  default: 5000 ms. 
- `resend_wait`: Specifies the wait time, in milliseconds, for start resending this messages after certain period aftet it was published. Only takes effect in bridging.
  -  default: 3000 ms. 
- `cancel_timeout`: Specifies the max wait time before canceling QoS ACK action, in milliseconds. Only takes effect in bridging. Once the action is canceled, there is no more retrying of this msg. So, you can call it max retrying time window.
  -  default: 8000 ms. 

::: tip

The canceling of a QoS msg doesn't actually means the msg is lost; just means it stopped waiting for the ACK of this msg from the remote broker. Before 0.22.4, there is no such feature, you will only see `bridging to xxxxx aio busy! msg lost! Ctx: xx`, once you hit a busy aio. and the aio will be occupied forever if remote broker fail to deliver the ACK eternally. Hence, `cancel_timeout` is added, Which means the maximum wait time for acknowledgment of each QoS msg . 

If you want a guaranteed retry logic of QoS msg in bridging. You can reference to the following configurations:

```hcl
## First bridge client
bridges.mqtt.emqx1 {
  ......
  keepalive = 30s           # Taking 30s keepalive as context
	max_send_queue_len = 512  # Give inflight window enought space for caching msg
	max_recv_queue_len = 512  # Give inflight window enought space for caching msg
  resend_interval = 5000    # Resend interval (ms), it will retry QoS every 5s 
                            # if there is no other action blocking.
                            # retry time shall be at least 1/2 or 1/4 of keepalive
  resend_wait = 3000  # resend_wait is the waiting time for resending the messages
                      # after it is publiushed. Please set it longer than 
                      # keepalive if you dont want duplicated QoS msg.
  cancel_timeout  = 10000 	# set a max timeout time before canceling the ack   
                            # action. Basically, this is also the time window you # spare to each QoS msg. 
                            # (cancel_timeout - resend_wait) / resend_wait > 1 : retry at least once.
}
```

To explain further, also gives a hints about how to finely tuned it:
QoS msg will go into the inflight window (max_send_queue_len) first if you are dealing with a busy network, then silently wait for its time to come. During waiting, It will be dropped only if the inflight window is full and new QoS msg keep comming. Once it exceeds the max wait time of QoS Ack, it will be excluded from a hashmap (QoS awaiting queue) which is different from inflight window. but it only means client will not try to resend it anymore.

NanoMQ uses SQLite to deliver the cache feature, for details on the configuration, see [SQLite](broker.md#cache)

:::

## AWS IoT Core Bridge

This part introduces the settings for the MQTT Bridge that connects to AWS IoT Core. AWS IoT Core is a managed cloud service that lets connected devices easily and securely interact with cloud applications and other devices.

AWS IoT cannot be enabled with MQTT over QUIC bridging due to the incompatibility between MsQUIC and AWS IoT SDK.

### **Example Configuration**

```hcl
bridges.aws.c1 = {
  server = "127.0.0.1:8883"             # AWS IoT Core server address
  proto_ver = 4                         # MQTT protocol version
  clientid = "aws_bridge_client"        # Client ID for the bridge
  keepalive = "60s"                     # Ping interval for the bridge
  clean_start = true                    # Clean start flag for the bridge
  forwards = [                          # Topics that need to be forwarded to AWS IoT Core
    {
      remote_topic = "fwd/topic1"
      local_topic = "topic1"
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
    }
  ]     
  subscription = [                        # Topics that need to be forwarded to AWS IoT Core
    {
      remote_topic = "cmd/topic1"
      local_topic = "topic3"
      qos = 1
    },
    {
      remote_topic = "cmd/topic2"
      local_topic = "topic4"
      qos = 2
    }
  ]
  max_parallel_processes = 2            # Maximum number of parallel processes for handling outstanding requests
}
```

### **Configuration Items**

- `server`: Specifies the address (host:port) of the AWS IoT Core server. For example, "127.0.0.1:8883".
- `proto_ver`: Specifies the MQTT protocol version used by the bridge. Possible values are 4 (for MQTT v3.1.1) and 5 (for MQTT v5).
- `clientid`: Specifies the client ID for the bridge when connecting to AWS IoT Core. The default is a random string.
- `keepalive`: Specifies the interval for sending keep-alive messages to AWS IoT Core. The default is 60 seconds.
- `clean_start`: Specifies whether to start a clean session when the bridge connects to AWS IoT Core. Some IoT platforms require this to be set to true.
- `username` and `password`: Specifies the username and password for the bridge to authenticate with AWS IoT Core, if required.
- `ssl`: Contains settings for SSL/TLS security:
  - `key_password`: Specifies the password for the client's private key file, if it's password-protected.
  - `keyfile`: Specifies the path to the client's private key file.
  - `certfile`: Specifies the path to the client's certificate file.
  - `cacertfile`: Specifies the path to the server's root CA certificate file. This certificate is used to identify the AWS IoT server.
- `forwards`: Specifies the topics that need to be forwarded to AWS IoT Core.
- `subscription`: Specifies the topics that the bridge should subscribe to from AWS IoT Core. Each group has a (`remote_topic`), `local_topic`, and a Quality of Service level (`qos`).
- `max_parallel_processes`: Specifies the maximum number of outstanding requests that can be handled simultaneously.
