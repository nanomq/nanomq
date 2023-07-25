# Gateway

This section introduces how to use the configuration file to configure multi-protocol gateways, including ZMQ gateway, SOME/IP Gateway, and DDS Gateway.

In order to utilize these gateways, you must first build NanoMQ from its source code. Detailed instructions on how to enable each gateway are provided in the following pages:

- [ZMQ Gateway](../gateway/zmq-gateway.md)
- [SOME/IP Gateway](../gateway/someip-gateway.md)
- [DDS Gateway](../gateway/dds.md)

When configuring various gateways in NanoMQ, you can manage each gateway's configuration independently. For each gateway, create a separate configuration file:

- `nanomq_zmq_gateway.conf` for the ZeroMQ gateway.
- `nanomq_vsomeip_gateway.conf` for the SomeIP gateway.
- `nanomq_dds_gateway.conf` for the DDS gateway.

Once these configuration files are complete, you can use the `nanomq_cli` tool to enable each configuration.

Usage example:

```hcl
nanomq_cli zmq_gateway --conf <path>
```

Here, `<path>` should be replaced with the path of the respective configuration file. This approach allows for easier management and activation of individual gateway configurations.

## ZMQ Gateway

NanoMQ supports data transmission and routing for ZeroMQ message queues through its ZMQ gateway.

### **Example Configuration**

```hcl
gateway.mqtt {
    address = "mqtt-tcp://broker.emqx.io:1883"  # MQTT Broker address
    sub_topic = "topic/sub"                     # Topic to subscribe to from the broker
    proto_ver = 4                               # MQTT protocol version
    keepalive = 60                              # Ping interval in seconds
    clean_start = true                          # Clean start flag
    username = "username"                       # Username for MQTT client
    password = "passwd"                         # Password for MQTT client
    forward = "topic/pub"                       # Topic to forward to IoTHUB
    parallel = 2                                # Maximum number of concurrent requests
}

gateway.zmq {
    sub_address = "tcp://127.0.0.1:5560"        # ZeroMQ Subscribe address
    pub_address = "tcp://127.0.0.1:5559"        # ZeroMQ Publish address
    sub_pre = "sub_prefix"                      # ZeroMQ subscription prefix
    pub_pre = "pub_prefix"                      # ZeroMQ publish prefix
}

http_server {
    port = 8082  																# HTTP server port
    parallel = 2  															# Maximum number of concurrent requests
    username = "admin" 												  # Basic authorization username
    password = "public"  												# Basic authorization password
}
```

### Configuration Items

#### gateway.mqtt

The `gateway.mqtt` configuration is used to specify how the MQTT gateway communicates with the MQTT broker:

- `address`: Specifies the MQTT Broker's address in the format "mqtt-tcp://host:port".
- `sub_topic`: Specifies the topic that the gateway should subscribe to from the MQTT broker.
- `proto_ver`: Specifies the MQTT protocol version. Acceptable values are 3, 4, and 5, corresponding to MQTT v3.1, MQTT v3.1.1 (also known as MQTT v4), and MQTT v5 respectively.
- `keepalive`: Specifies the ping interval in seconds for the MQTT connection.
- `clean_start`: Specifies whether the MQTT client connection should start clean. **Note**: Some IoT platforms require this to be set to true.
- `username`: Specifies the username for the MQTT client when connecting to the broker.
- `password`: Specifies the password for the MQTT client when connecting to the broker.
- `forward`: Specifies the topic that needs to be forwarded to IoTHUB.
- `parallel`: Specifies the maximum number of concurrent requests that can be handled.

#### gateway.zmq

The `gateway.zmq` configuration is used to specify how the MQTT gateway communicates with ZeroMQ:

- `sub_address`: Specifies the ZeroMQ Subscribe address in the format "tcp://host:port".
- `pub_address`: Specifies the ZeroMQ Publish address in the format "tcp://host:port".
- `sub_pre`: Specifies the prefix for the ZeroMQ subscription.
- `pub_pre`: Specifies the prefix for the ZeroMQ publish.

### http_server (Optional)

The `http_server` configuration allows you to configure an HTTP server for dynamic configuration updates and control over the gateway's restart or shutdown:

- `port`: Specifies the port number for the HTTP server. The value should be between 0 and 65535.
- `parallel`: Specifies the maximum number of concurrent requests that the HTTP server can handle.
- `username`: Specifies the username for basic authorization when accessing the HTTP server.
- `password`: Specifies the password for basic authorization when accessing the HTTP server.



## SOME/IP Gateway

NanoMQ now supports SOME/IP data communication based on the AUTOSAR standard via the SOME/IP Gateway.  

### **Example Configuration**

```hcl
gateway.mqtt {
    address = "mqtt-tcp://localhost:1885"    # MQTT Broker address
    sub_topic = "topic/sub"             # Topic to subscribe to
    sub_qos = 0                         # Quality of Service for subscription
    proto_ver = 4                       # MQTT protocol version
    keepalive = 60                      # Keepalive interval in seconds
    clean_start = true  								# Clean start flag
    username = "username"  							# MQTT username
    password = "passwd"  								# MQTT password
    clientid = "vsomeip_gateway"    		# MQTT client ID
    forward = "topic/pub"  							# Topics to forward to VSOMEIP
    parallel = 2                        # Maximum number of concurrent requests
}

gateway.vsomeip {
    service_id = "0x1111"               # VSOMEIP service ID
    service_instance_id = "0x2222"      # VSOMEIP instance ID
    service_method_id = "0x3333"        # VSOMEIP method ID
    conf_path = "/etc/vsomeip.json"     # Path to the VSOMEIP configuration file
}

http_server {
    port = 8082                         # HTTP server port
    parallel = 2                        # Maximum number of concurrent requests on the HTTP server
    username = "admin"                  # Basic authorization username for the HTTP server
    password = "public"                 # Basic authorization password for the HTTP server
}
```



### **Configuration Items**

::: tip

The configuration items for the optional HTTP server are the same, for details, see [HTTP Sever](#http_server-optional).

:::

### gateway.mqtt

- `address`: Specifies the address of the MQTT broker.
- `sub_topic`: Specifies the topic that the MQTT client should subscribe to.
- `sub_qos`: Specifies the QoS level for the subscription.
- `proto_ver`: Specifies the MQTT protocol version to be used.
- `keepalive`: Specifies the interval in seconds that the MQTT client should send a keepalive message to the broker.
- `clean_start`: Specifies whether the MQTT client should start a clean session each time it connects to the broker.
- `username`: Specifies the username for the MQTT client.
- `password`: Specifies the password for the MQTT client.
- `clientid`: Specifies the client ID for the MQTT client.
- `forward`: Specifies the topic that should be forwarded to the VSOMEIP gateway.
- `parallel`: Specifies the maximum number of concurrent requests that the MQTT client should handle.

#### gateway.vsomeip <!--@jaylin the vsomeip in the configuration file may need to be renamed-->

- `service_id`: Specifies the service ID for the VSOMEIP service.
- `service_instance_id`: Specifies the instance ID for the VSOMEIP service.
- `service_method_id`: Specifies the method ID for the VSOMEIP service.
- `conf_path`: Specifies the path to the VSOMEIP configuration file.

## DDS Gateway

From version v0.16, NanoMQ introduced a DDS Proxy plugin developed based on Cyclone DDS. This plugin can convert DDS messages into MQTT messages and bridge them to the cloud, allowing users to transmit DDS data across domains through NanoMQ and communicate with the cloud through MQTT.

### **Example Configuration**

```hcl
forward_rules = {
    dds_to_mqtt = {
        from_dds = "MQTTCMD/topic1"  				# DDS topic
        to_mqtt = "DDS/topic1"     					# MQTT topic
        struct_name = "idl_struct1"  				# Struct name for the topic
    }
    
    mqtt_to_dds = {
        from_mqtt = "DDSCMD/topic1"  				# MQTT topic
        to_dds = "MQTT/topic1"       				# DDS topic
        struct_name = "idl_struct2"  				# Struct name for the topic
    }
}

dds {
    domain_id = 0                    				# DDS domain ID
    
    shared_memory = {
        enable = false               				# Enable shared memory transport
        log_level = info             				# Log level for the shared memory transport
    }
}

mqtt {
    connector {
        server = "mqtt-tcp://127.0.0.1:1883"  # MQTT Broker address
        proto_ver = 4   											# MQTT protocol version
        keepalive = 60s 											# Keepalive interval in seconds
        clean_start = true  									# Clean start flag
        username = "username"  								# MQTT username
        password = "passwd"  									# MQTT password
        
        ssl {
            key_password = "yourpass"  				# Password for the SSL key
            keyfile = "/etc/certs/key.pem"  	# Path to the SSL key file
            certfile = "/etc/certs/cert.pem"  # Path to the SSL certificate file
            cacertfile = "/etc/certs/cacert.pem"  # Path to the SSL CA certificate file
        }
    }
}

http_server {
    port = 8082  																 # HTTP server port
    parallel = 2  # Maximum number of concurrent requests on the HTTP server
    username = "admin"  # Basic authorization username for the HTTP server
    password = "public"  # Basic authorization password for the HTTP server
}
```

### **Configuration Items**

::: tip

The configuration items for the optional HTTP server are the same, for details, see [HTTP Sever](#http_server-optional).

:::

#### forward_rules

- `dds_to_mqtt`: Specifies the forwarding rules from DDS to MQTT.
  - `from_dds`: Specifies the DDS topic to subscribe to.
  - `to_mqtt`: Specifies the MQTT topic to publish to.
  - `struct_name`: Specifies the name of the struct for the topic.
- `mqtt_to_dds`: Specifies the forwarding rules from MQTT to DDS.
  - `from_mqtt`: Specifies the MQTT topic to subscribe to.
  - `to_dds`: Specifies the DDS topic to publish to.
  - `struct_name`: Specifies the name of the struct for the topic.

**DDS Configuration**

- `domain_id`: Specifies the domain ID for the DDS network.
- `shared_memory`: Specifies the shared memory settings.
  - `enable`: Specifies whether to enable the shared memory transport.
  - `log_level`: Specifies the log level for the shared memory transport.

**MQTT Connector Configuration**

- `server`: Specifies the address of the MQTT broker.
- `proto_ver`: Specifies the MQTT protocol version to be used.
- `keepalive`: Specifies the interval in seconds that the MQTT client should send a keepalive message to the broker.
- `clean_start`: Specifies whether the MQTT client should start a clean session each time it connects to the broker.
- `username`: Specifies the username for the MQTT client.
- `password`: Specifies the password for the MQTT client.
- `ssl`: Specifies the SSL settings. 
  - `key_password`: Specifies the password for the SSL key file.
  - `keyfile`: Specifies the path to the SSL key file.
  - `certfile`: Specifies the path to the SSL certificate file.
  - `cacertfile`: Specifies the path to the SSL CA certificate file.
