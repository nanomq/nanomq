# HTTP API

NanoMQ Broker provides HTTP APIs for integration with external systems, such as querying broker statistics information, clients information, subscribe topics information, and restart with the new config file.

NanoMQ Broker's HTTP API service listens on port 8081 by default. You can modify the listening port through the configuration file of `etc/nanomq.conf`. All API calls with `api/v1` or `api/v4`.

NanoMQ currently provides 2 versions of HTTP APIs, you can click the link below to learn the details:

- [HTTP API (V4)](./v4.md)
- [HTTP API (V1)](./v1.md)