# MQTT Data Bridges

Bridging is a way to connect multiple MQTT brokers. This section introduces MQTT over TCP bridge and MQTT over QUIC bridge. 

## MQTT over TCP Bridging

This section provides an in-depth guide to configuring MQTT over TCP bridging, explaining the primary configuration parameters and demonstrating a typical `nanomq.conf` file setup. It also introduces how to run NanoMQ with a specified configuration file and test bridging to ensure its successful implementation.

## MQTT over QUIC Bridging

In cases where integration with MQTT over TCP bridging is hard to implement, NanoMQ has innovatively introduced a new protocol, MQTT over QUIC. QUIC, initially developed by Google, was later adopted as a worldwide standard by the Internet Engineering Task Force (IETF). With MQTT over QUIC bridging, you can take full advantage of the QUIC protocol's benefits in IoT scenarios. 