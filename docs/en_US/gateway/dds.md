# DDS

The OMG Data Distribution Service (DDS™) is a middleware protocol and API standard for data-centric connectivity from the [Object Management Group® (OMG®)](https://www.omg.org/). It integrates the components of a system together, providing low-latency data connectivity, extreme reliability, and a scalable architecture that business and mission-critical Internet of Things (IoT) applications need.

[Cyclone DDS](https://cyclonedds.io/) is a high performing, OMG-DDS standard based data sharing technology which allows system designers to create digital twins of their systems' entities to share their states, events, data-streams and messages on the network in real-time and fault-tolerant way.

## DDS to MQTT Proxy

Here we combine dds with mqtt. So DDS node can communicate with MQTT broker.

<img src="./images/dds-mqtt.png" style="zoom: 67%;" />



## Building

### Iceoryx

> If you have no plan to use Iceoryx, just skip this step.

```bash
$ git clone https://github.com/eclipse-iceoryx/iceoryx.git
$ cd iceoryx
$ git checkout release_2.0
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={USER_LIBRARY_PATH} ../iceoryx_meta
$ ninja
$ sudo ninja install
```

### CycloneDDS

```bash
$ git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
$ cd cyclonedds
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={USER_LIBRARY_PATH} -DCMAKE_PREFIX_PATH={USER_LIBRARY_PATH} -DBUILD_EXAMPLES=ON ..
$ ninja 
$ sudo ninja install
```

> Specify you installation path by `USER_LIBRARY_PATH`. 



## DDS Proxy on NanoMQ_CLI 

### Building idl-serial-code-gen

Build  `IDL` code generator.

```bash
$ git clone https://github.com/nanomq/idl-serial.git
$ cd idl-serial
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_INSTALL_PREFIX={USER_LIBRARY_PATH}..
$ ninja 
$ sudo ninja install
```



### Build NanoMQ with DDS Proxy

1. Specify idl file path by cmake option `IDL_FILE_PATH` (default path: `etc/idl/dds_type.idl`), enable DDS by `-DBUILD_DDS_PROXY=ON` ;

```bash
$ git clone https://github.com/emqx/nanomq.git 
$ cd nanomq 
$ mkdir build && cd build 
$ cmake -G Ninja -DIDL_FILE_PATH={IDL_PATH} -DCMAKE_PREFIX_PATH={USER_LIBRARY_PATH} -DBUILD_DDS_PROXY=ON .. 
$ ninja  
$ sudo ninja install
```

2. Check if  `dds` client is built in `nanomq_cli` ;

```bash
$ ./nanomq_cli/nanomq_cli  
   nanomq_cli { pub | sub | conn | nngproxy | nngcat | dds } [--help] 
   
   available tools:   
     * pub   
     * sub   
     * conn   
     * nngproxy   
     * nngcat   
     * dds 
   
   Copyright 2022 EMQ Edge Computing Team
```

```bash
$ ./nanomq_cli/nanomq_cli dds
 nanomq_cli dds { sub | pub | proxy } [--help] 

 available apps: 
        * sub   
        * pub   
        * proxy 
```



## Quick start

### Configuration

#### Configuring DDS Proxy

##### DDS subscription and MQTT publish

- DDS  Topic for subscribe

- -  `forward_rules.dds_to_mqtt.from_dds = "MQTTCMD/topic1"`

- MQTT Topic for publish

- - `forward_rules.dds_to_mqtt.to_mqtt = "DDS/topic1"`

- Specify dds structure name for subscribe

- - `forward_rules.dds_to_mqtt.struct_name = "remote_control_result_t"`

##### MQTT subscription and DDS publish

- MQTT Topic for subscribe

- -  `forward_rules.dds_to_mqtt.from_dds = "DDSCMD/topic1"`

- DDS Topic for publish

- - `forward_rules.dds_to_mqtt.to_mqtt = "MQTT/topic1"`

- Specify dds structure name for publish

- - `forward_rules.dds_to_mqtt.struct_name = "remote_control_req_t"`

 **Note: The `struct_name` must be included in the `IDL` file .**

```bash
## Forwarding rules
forward_rules = {
	## DDS to MQTT
    dds_to_mqtt = {
        from_dds = "MQTTCMD/topic1"
        to_mqtt = "DDS/topic1"
        struct_name = "remote_control_result_t"
    }
    ## MQTT to DDS
    mqtt_to_dds = {
        from_mqtt = "DDSCMD/topic1"
        to_dds = "MQTT/topic1"
        struct_name = "remote_control_req_t"
    }
}

## DDS Configuration
dds {
    # # dds domain id
    # # default: 0
    # # Value: uint32
    domain_id = 0
    
    shared_memory = {
        # # Enable shared memory transport.
        # # Iceoryx is required if enable shared memory transport.
        # #
        # # Default: false
        # # Value:  boolean
        enable = false
        
        # # controls the output of the iceoryx runtime and can be set to, in order of decreasing output:
        # # log level: verbose, debug, info, warn, error, fatal, off
        # # Default:  info
        # # Value: enum
        log_level = info
    }
}

## MQTT client Configuration
mqtt {
	connector {
        # # Bridge address: host:port .
        # #
        # # Value: String
        # # Example: mqtt-tcp://127.0.0.1:1883
        # #          tls+mqtt-tcp://127.0.0.1:8883
        server = "mqtt-tcp://127.0.0.1:1883"
        
        # # Protocol version of the bridge.
        # #
        # # Value: Enum
        # # - 5: mqttv5
        # # - 4: mqttv311
        # # - 3: mqttv31
        proto_ver = 4
        # # The ClientId of a remote bridge.
        # # Default random string.
        # #
        # # Value: String
        # clientid="bridge_client"
        
        # # Ping: interval of a downward bridge.
        # #
        # # Value: Duration
        # # Default: 10 seconds
        keepalive = 60s
        # # The Clean start flag of a remote bridge.
        # #
        # # Value: boolean
        # # Default: false
        # #
        # # NOTE: Some IoT platforms require clean_start
        # #       must be set to 'true'
        clean_start = false
        # # The username for a remote bridge.
        # #
        # # Value: String
        username = username
        # # The password for a remote bridge.
        # #
        # # Value: String
        password = passwd
        
        ssl {
            # # enable ssl
            # # 
            # # Value: true | false
            enable = false
            # # Ssl key password
            # # String containing the user's password. Only used if the private keyfile
            # # is password-protected.
            # #
            # # Value: String
            key_password = "yourpass"
            # # Ssl keyfile
            # # Path of the file containing the client's private key.
            # #
            # # Value: File
            keyfile = "/etc/certs/key.pem"
            # # Ssl cert file
            # # Path of the file containing the client certificate.
            # #
            # # Value: File
            certfile = "/etc/certs/cert.pem"
            # # Ssl ca cert file
            # # Path of the file containing the server's root CA certificate.  
            # # 
            # # This certificate is used to identify the AWS IoT server and is publicly
            # # available.
            # #
            # # Value: File
            cacertfile = "/etc/certs/cacert.pem"
        }
    }
}
```



### Running

#### Iceoryx

>  If you don't want to start running Cyclone DDS with shared memory exchange or haven't enabled shared memory transpot layer, just skip the following steps

1. Create an example `iceoryx` configuration file which has a memory pool of 2^15 blocks which can store data types of 16384 bytes (+ 64 byte header = 16448 byte block): <br>

   ```toml
   [general]
   version = 1
   
   [[segment]]
   
   [[segment.mempool]]
   size = 16448
   count = 32768
   ```

   Please save this file as *iox_config.toml* in your own directory.

2. Start `RouDi` in `iceoryx` in a terminal.<br>

   ```bash
   $ cd {USER_LIBRARY_PATH}
   $ bin/iox-roudi -c iox_config.toml
   ```

#### DDS Proxy

1. Start MQTT Broker

```bash
$ nanomq start
```

or

```bash
$ emqx start
```

2. Start DDS Proxy

```bash
$ ./nanomq_cli dds proxy --conf nanomq_dds_gateway.conf
```

3. Start MQTT client and subscribe topic `DDS/topic1`

```bash
$ ./nanomq_cli sub --url "mqtt-tcp://127.0.0.1:1883" -t "DDS/topic1"
```

4. Start DDS client, specify structure name `remote_control_result_t` and publish message ( *JSON format* ) to DDS topic `MQTTCMD/topic1`

```bash
$ ./nanomq_cli dds pub -t "MQTTCMD/topic1" --struct "remote_control_result_t"  -m '{
  "req_result_code": 1,
  "req_token": [1,2,3,4,5,6],
  "req_result_msg": [7,8,9,10,11],
  "req_id": [12,13,14],
  "req_token_len": 6,
  "req_id_len": 3
}'
```

5. Start DDS client to subscribe DDS topic `MQTT/topic1` and specify structure name `remote_control_req_t`

```bash
$ ./nanomq_cli dds sub -t "MQTT/topic1" --struct "remote_control_req_t"
```

6. Start MQTT client to publish message ( *JSON format*) to MQTT topic `DDSCMD/topic1`

```bash
$ ./nanomq_cli pub --url "mqtt-tcp://127.0.0.1:1883" -t "DDSCMD/topic1" -m '{ 
  "req": 1,         
  "req_id": [15,16],
  "req_id_len": 2
 }'
```

