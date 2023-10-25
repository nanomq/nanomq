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
    },
    {
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
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

This configuration enables NanoMQ to establish an MQTT over TCP bridge connection to a remote MQTT server, using will message and secure communication with SSL.

### **Configuration Items**

- bridges.mqtt.\<name>: Specifies the name of the bridge. 
- `server`: Specifies the MQTT server address for the bridge. Example: 
  - mqtt-tcp://127.0.0.1:1883 for MQTT over TCP bridge
  - tls+mqtt-tcp://127.0.0.1:8883 for MQTT over TCP bridge with SSL eneabled
  - mqtt-quic://54.75.171.11:14567 for MQTT over QUIC bridge

- `proto_ver`: Specifies the MQTT protocol version to use. Options:
  - `5` for MQTT v5

  - `4` for MQTT v3.1.1

  - `3` for MQTT v3.1
- `clientid`: Specifies the client ID for the bridge.
- `keepalive`: Specifies the ping interval for the bridge.
- `clean_start`: Specifies the clean start flag for the bridge. **Note**: Some IoT platforms require this to be set to `false`.
- `username`: Specifies the username for the bridge.
- `password`: Specifies the password for the bridge.
- `forwards`: This is an array of topics that need to be forwarded to the remote MQTT server, including
  - `remote_topic`: Topics refection topic, will change the topic in publish msg. Just leave `remote_topic=""` to preserve the original topic in msg   
  - `local_topic`: Topics that need to be forwarded to the remote MQTT server.

- `ssl`: Contains settings for SSL/TLS security:
  - `key_password`: Specifies the password for the client's private key file, if it's password-protected.
  - `keyfile`: Specifies the path to the client's private key file.
  - `certfile`: Specifies the path to the client's certificate file.
  - `cacertfile`: Specifies the path to the server's root CA certificate file. This certificate is used to identify the AWS IoT server.
- `subscription`: This is an array of topic objects that need to be subscribed from the remote MQTT server. Each object defines a topic and the QoS level for the subscription. Including
  - `remote_topic`: The topic filter used to subscribe to the remote broker.
  - `local_topic`: This is for Topic reflection, if you want the vanila way, then just leave `local_topic=""` to preserve the original topic in msg from remote broker.
  - `qos`: Define the QoS in the subscribe packet. This is a must. 

- `max_parallel_processes`: Specifies the maximum number of parallel processes for handling outstanding requests.
- `max_send_queue_len`: Specifies the maximum number of messages that can be queued for sending.
- `max_recv_queue_len`: Specifies the maximum number of messages that can be queued for processing. 

### **MQTT 5** 

 if MQTT v5 is to be used (`proto_ver = 5`), the following configuration items are also supported:

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
      remote_topic = "fwd/topic2"
      local_topic = "topic2"
      qos = 2
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
- `hybrid_bridging`: Specifies whether to enable the hybrid bridging mode. This should be enabled if you want to use QUIC but aren't sure if the public network supports it. The default is `false`.
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
  ......
}

## Second bridge client
bridges.mqtt.emqx2 {
  ......
}

bridges.mqtt.cache {
    disk_cache_size = 102400   # Max message limitation for caching
    mounted_file_path="/tmp/"  # Mounted file path 
    flush_mem_threshold = 100  # The threshold of flushing messages to flash
    resend_interval     = 3000 # The interval of resending cached SQLite msg
}
```

### **Configuration Items**

- `disk_cache_size`: Specifies the maximum number of messages that can be cached in the MQTT bridges. A value of 0 indicates no limit.
- `mounted_file_path`: Specifies the file path where the cache file for the MQTT bridges is mounted.
- `flush_mem_threshold`: Specifies the threshold for flushing messages to the cache file. When the number of messages reaches this threshold, they are flushed to the cache file.
- `resend_interval`: Specifies the interval, in milliseconds, for resending the messages after a failure is recovered. This is not related to the trigger for the resend operation. Only takes effect in bridging.

::: tip

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