# SOME/IP Gateway

Developed by the German company BMW, SOME/IP (**Scalable service-Oriented MiddlewarE over IP**) is a service-oriented vehicle Ethernet communication protocol that supports a Service-Oriented Architecture (SOA). Unlike traditional vehicular buses, according to the SOME/IP protocol, data is only transmitted when at least one recipient in the network needs the relevant data, thus greatly improving the utilization rate of network bandwidth.

Under the trend of software-defined cars, SOME/IP shows high efficiency and security in handling data from various sources within the car. It can interface with traditional TSP platforms and offload computations to new-generation application services like ADAS.

NanoMQ now supports SOME-IP data communication based on the AUTOSAR standard via the SOME/IP Gateway. It can be deployed in the central gateway of the vehicle to aggregate data and interface with the TSP platform. The security of the gateway is ensured through MQTT over QUIC/TCP + TLS encrypted connection.

<img src="/Users/lena/Documents/GitHub/Lena Pan/nanomq-1/docs/zh_CN/gateway/assets/someip-solution.png" alt="SOME/IP + MQTT 共同应用场景" style="zoom:50%;" />

## Prerequisites

The SOME/IP Gateway function of NanoMQ depends on [vSOMEIP](https://github.com/COVESA/vsomeip). Run the following commands to install vSOMEIP.

::: tip

Check the installation dependencies of vSOMEIP on the [vSOMEIP GitHub page](https://github.com/COVESA/vsomeip)

:::

```shell
git clone https://github.com/COVESA/vsomeip.git
cd vsomeip
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH
make -j8
make install
```

### Compile the Sample Service

Compile the hello_world_service sample service in vSOMEIP, which will be subsequently used to test the NanoMQ's SOME/IP Gateway.

```shell
cd vsomeip/examples/hello_world
mkdir build
cd build
cmake ..
make -j8
```

## Enable SOME/IP Protocol Conversion

Enable the SOME/IP protocol conversion feature for NanoMQ at the compile stage with the following command:

```shell
cmake -G Ninja -DBUILD_VSOMEIP_GATEWAY=ON ..
ninja
```

## Configure the SOME/IP Gateway

Before starting, specify the bridged topic and the address of the required SOME/IP service via the `etc/nanomq_vsomeip_gateway.conf` configuration file.

Suppose you wish to route the data received from the SOME/IP service to the `topic/pub` topic of your local MQTT Broker. Moreover, you want to channel the MQTT messages received through the `topic/sub` topic to the SOME/IP service. You can accomplish this through the following configuration:

```apacheconf
gateway.mqtt {
    address = "mqtt-tcp://localhost:1883"
    sub_topic = "topic/sub" # message from mqtt
    sub_qos = 0
    proto_ver = 4
    keepalive = 60
    clean_start = true
    username = "username"
    password = "passwd"
    clientid = "vsomeip_gateway"
    forward = "topic/pub" # message to mqtt
    parallel = 2
}

gateway.vsomeip {
    service_id = "0x1111"
    service_instance_id = "0x2222"
    service_method_id = "0x3333"
    # conf_path = "/etc/vsomeip.json"
}

http_server {
	enable = false
	port = 8082
	parallel = 2
	username = admin
	password = public
}
```

In this example, you've designated two distinct SOME/IP services, each corresponding to its respective MQTT topic, namely `someip/1234/5678/9ABC` and `someip/1111/2222/3333`.

- When the SOME/IP gateway receives a message from a particular combination of `service_id`, `service_instance_id`, and `service_method_id`, it promptly transposes it into an MQTT message and publishes it onto the related topic.
- When the SOME/IP gateway receives messages from an MQTT topic, it will transcribe the message into the SOME/IP format and forward it to the predefined SOME/IP service.

## Test the SOME/IP Gateway

This section uses the `hello_world_service` sample service provided by the vSOMEIP project to connect and forward the SOME/IP service, and integrate it with NanoMQ via the SOME/IP gateway.

::: tip

For guidance on how to install and initiate this sample service, please refer to the vSOMEIP project documentation. This service can also be replaced with other SOME/IP-compatible services.

:::

Use the following commands to initiate `hello_world_service`:

``` shell
ldconfig
./hello_world_service // Launch SOME/IP Server
nanomq start // Launch NanoMQ MQTT Broker
nanomq_cli vsomeip_gateway --conf ../etc/nanomq_vsomeip_gateway.conf // Launch SOME/IP proxy
```

Once the SOME/IP Gateway is configured, when you send a message to the `topic/pub` topic via your MQTT client, the SOME/IP Gateway will forward this message to the pre-specified SOME/IP service, namely `hello_world_service`. Upon receipt, the SOME/IP service will generate a response and route it back to the `topic/sub` topic via the SOME/IP Gateway. Any client subscribed to this topic will then receive the corresponding response message.

Here's an illustration of the running process:
![img](/Users/lena/Documents/GitHub/Lena Pan/nanomq-1/docs/zh_CN/gateway/assets/hello_service.png)
![img](/Users/lena/Documents/GitHub/Lena Pan/nanomq-1/docs/zh_CN/gateway/assets/nanomq_someip_gateway.png)
![img](/Users/lena/Documents/GitHub/Lena Pan/nanomq-1/docs/zh_CN/gateway/assets/someip_gateway.png)
![img](/Users/lena/Documents/GitHub/Lena Pan/nanomq-1/docs/zh_CN/gateway/assets/pub_sub.png)

At present, the SOME/IP Gateway in NanoMQ supports transparent services only, meaning the original data remains unchanged as it passes through the gateway. However, we're constantly striving for enhancement. Our future plans include developing advanced features like automatic code generation and data serialization, catering to user preferences in terms of data serialization and deserialization format tools like IDL or FIDL. We appreciate your patience and look forward to offering these improved functionalities.

