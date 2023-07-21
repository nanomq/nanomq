# ZMQ Gateway

[**ZeroMQ**](https://en.wikipedia.org/wiki/ZeroMQ) (also spelled **ØMQ**, **0MQ,** or **ZMQ**) is an asynchronous messaging library, aimed at use in distributed or concurrent applications. It provides a message queue, but unlike message-oriented middleware, a ZeroMQ system can run without a dedicated message broker; the zero in the name is for zero brokers.

NanoMQ supports data transmission and routing for ZeroMQ message queues through its ZMQ gateway.

## Enable ZMQ Gateway

You can enable the ZMQ gateway feature during the compilation process using the `-DBUILD_ZMQ_GATEWAY=ON` switch. For further details on the compilation, refer to [this guide on installing NanoMQ via compilation](../installation/build-options.md).

Example command:

```bash
cmake -G Ninja -DBUILD_ZMQ_GATEWAY=ON ..
ninja
```

After the compilation is complete, you can navigate to the build -> nanomq_cli directory, and execute the `nanomq_cli` command to verify if the ZMQ gateway is correctly installed:

```bash
$ ./nanomq_cli
nanomq_cli { pub | sub | conn | nngproxy | nngcat | zmq_gateway } [--help]

available tools:
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * zmq_gateway

Copyright 2022 EMQ Edge Computing Team
```
Then run the command `./nanomq_cli zmq_gateway --help` and you will get:

```
Usage: nanomq_cli zmq_gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq configuration file 
```

The output indicates that you should first specify a configuration file for this gateway.

### Configure the ZMQ Gateway
The configuration file `etc/nanomq_zmq_gateway.conf` allows you to specify the topics and service addresses for bridging.

Suppose you aim to build a powerful gateway that connects a local ZeroMQ server, and a remote MQTT broker ([broker.emqx.io:1883](https://www.emqx.com/zh/mqtt/public-mqtt5-broker)). In this case, you can use the following configuration file to facilitate cross-protocol and cross-network message transmission under the `sub` and `pub` topics:

```bash
##====================================================================
## Configuration for MQTT ZeroMQ Gateway
##====================================================================

gateway.mqtt {
    ## MQTT Broker address: host:port .
    ##
    ## Value: String
    ## Example: mqtt-tcp://127.0.0.1:1883
    address="mqtt-tcp://broker.emqx.io:1883"
    ## Need to subscribe to remote broker topics
    ##
    ## Value: String
    sub_topic="topic/sub"
    ## Protocol version of the mqtt client.
    ##
    ## Value: Enum
    ## - 5: mqttv5
    ## - 4: mqttv4
    ## - 3: mqttv3
    proto_ver=4
    ## Ping interval of a down mqtt client.
    ##
    ## Value: Duration
    ## Default: 10 seconds
    keepalive=60
    ## The Clean start flag of mqtt client.
    ##
    ## Value: boolean
    ## Default: true
    ##
    ## NOTE: Some IoT platforms require clean_start
    ##       must be set to 'true'
    clean_start=true
    ## The username for mqtt client.
    ##
    ## Value: String
    username="username"
    ## The password for mqtt client.
    ##
    ## Value: String
    password="passwd"
    ## Topics that need to be forward to IoTHUB
    ##
    ## Value: String
    ## Example: topic1/pub
    forward="topic/pub"
    ## parallel
    ## Handle a specified maximum number of outstanding requests
    ##
    ## Value: 1-infinity
    parallel=2
}
gateway.zmq {
    ## ZeroMQ Subscribe address: host:port .
    ##
    ## Value: String
    ## Example: tcp://127.0.0.1:5560
    sub_address="tcp://127.0.0.1:5560"
    ## ZeroMQ Publish address: host:port .
    ##
    ## Value: String
    ## Example: tcp://127.0.0.1:5559
    pub_address="tcp://127.0.0.1:5559"
    ## ZeroMQ subscription prefix
    ##
    ## Value: String
    ## Example: sub_prefix
    sub_pre="sub_prefix"
    ## ZeroMQ publish prefix
    ##
    ## Value: String
    ## Example: pub_prefix
    pub_pre="pub_prefix"
}
```
Configure file description can find [here](../config-description/gateway.md).

## Test ZMQ Gateway

After setting up the configuration, use the following commands to start the NanoMQ Broker, ZMQ server, and ZMQ gateway. This will enable the message transmission between the ZMQ server and the MQTT Broker:

```bash
$ nanomq start
$ {your.zmq.server}
$ nanomq_cli zmq_gateway --conf path/to/nanomq_zmq_gateway.conf
```



