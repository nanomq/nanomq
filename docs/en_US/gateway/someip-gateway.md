# SOME/IP Gateway

Developed by the German company BMW, SOME/IP (**Scalable service-Oriented MiddlewarE over IP**) is a service-oriented vehicle Ethernet communication protocol that supports a Service-Oriented Architecture (SOA). Unlike traditional vehicular buses, according to the SOME/IP protocol, data is only transmitted when at least one recipient in the network needs the relevant data, thus greatly improving the utilization rate of network bandwidth.

Under the trend of software-defined cars, SOME/IP shows high efficiency and security in handling data from various sources within the car. It can interface with traditional TSP platforms and offload computations to new-generation application services like ADAS.

NanoMQ now supports SOME-IP data communication based on the AUTOSAR standard via the SOME/IP Gateway. It can be deployed in the central gateway of the vehicle to aggregate data and interface with the TSP platform. The security of the gateway is ensured through MQTT over QUIC/TCP + TLS encrypted connection.

<img src="./assets/someip-solution.png" alt="SOME/IP + MQTT Solution" style="zoom:50%;" />

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

## Enable SOME/IP Gateway

You can enable the SOME/IP gateway feature during the compilation process using the `-DBUILD_VSOMEIP_GATEWAY=ON` switch. For further details on the compilation, refer to [this guide on installing NanoMQ via compilation](../installation/build-options.md).

Example command:

```shell
cmake -G Ninja -DBUILD_VSOMEIP_GATEWAY=ON ..
ninja
```

After the compilation is complete, you can navigate to the build -> nanomq_cli directory, and execute the `nanomq_cli` command to verify if the ZMQ gateway is correctly installed:

```bash
$ ./nanomq_cli
nanomq_cli { pub | sub | conn | nngproxy | nngcat | vsomeip_gateway } [--help]

available tools:
   * pub
   * sub
   * conn
   * nngproxy
   * nngcat
   * vsomeip_gateway

Copyright 2022 EMQ Edge Computing Team
```

Then run the command `nanomq_cli vsomeip_gateway --help` and you will get:

```
Usage: nanomq_cli vsomeip_gateway [--conf <path>]

  --conf <path>  The path of a specified nanomq_vsomeip_gateway.conf file
```

The output indicates that you should first specify a configuration file for this gateway.

## Configure the SOME/IP Gateway

The configuration file `etc/nanomq_vsomeip_gateway.conf` allows you to specify the topics and service addresses for bridging.

Suppose you wish to route the data received from the SOME/IP service to your local MQTT Broker's `topic/pub` topic. Moreover, you want to channel the MQTT messages received through the `topic/sub` topic to the SOME/IP service. You can accomplish this through the following configuration:

```bash
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

```

If you wish to dynamically update configuration or control the gateway's restart or shutdown through an HTTP API, you can add the following configuration to `nanomq_vsomeip_gateway.conf` and start the HTTP service:

```bash
# #============================================================
# # Http server
# #============================================================
http_server {
	# # http server port
	# #
	# # Value: 0 - 65535
	port = 8082
	# # parallel for http server
	# # Handle a specified maximum number of outstanding requests
	# #
	# # Value: 1-infinity
	parallel = 2
	# # username
	# #
    # # Basic authorization 
    # #
	# # Value: String
	username = admin
	# # password
	# #
    # # Basic authorization
    # #
	# # Value: String
	password = public
}
```
## HTTP API
The HTTP API provides the following interfaces:

- Get configuration file:
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/configuration/someip' --output nanomq_vsomeip_gateway.conf
```

- Update configuration file:
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/configuration/someip' --header 'Content-Type: text/plain'  --data-binary '@nanomq_vsomeip_gateway.conf'
```

- Stop gateway:
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/ctrl/stop' \
--header 'Content-Type: application/json' \
--data '{
    "req": 10,
    "action": "stop",
    "seq": 1234
}'
```

- Restart gateway:
```shell
$ curl --basic -u admin:public 'http://127.0.0.1:8082/api/v4/proxy/ctrl/restart' \
--header 'Content-Type: application/json' \
--data '{
    "req": 10,
    "action": "restart",
    "seq": 1234
}'
```

## Test the SOME/IP Gateway

This section uses the `hello_world_service` sample service provided by the vSOMEIP project to connect and forward the SOME/IP service, and integrate it with NanoMQ via the SOME/IP gateway.

::: tip

This service can also be replaced with other SOME/IP-compatible services.

:::

Use the following commands to initiate `hello_world_service`:

``` bash
$ ldconfig
$ ./hello_world_service // Launch SOME/IP Server
$ nanomq start // Launch NanoMQ MQTT Broker
$ nanomq_cli vsomeip_gateway --conf path/to/nanomq_vsomeip_gateway.conf // Launch SOME/IP proxy
```

Once the SOME/IP Gateway is configured, when you send a message to the `topic/sub` topic via your MQTT client, the SOME/IP Gateway will forward this message to the pre-specified SOME/IP service, namely `hello_world_service`. Upon receipt, the SOME/IP service will generate a response and route it back to the `topic/pub` topic via the SOME/IP Gateway. Any client subscribed to this topic will then receive the corresponding response message.

Here's an illustration of the running process:
![img](./assets/hello_service.png)
![img](./assets/nanomq_someip_gateway.png)
![img](./assets/someip_gateway.png)
![img](./assets/pub_sub.png)

At present, the SOME/IP Gateway in NanoMQ supports transparent services only, meaning the original data remains unchanged as it passes through the gateway. However, we're constantly striving for enhancement. Our future plans include developing advanced features like automatic code generation and data serialization, catering to user preferences in terms of data serialization and deserialization format tools like IDL or FIDL. We appreciate your patience and look forward to offering these improved functionalities.

