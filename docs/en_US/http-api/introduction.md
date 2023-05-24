# HTTP API

NanoMQ Broker provides HTTP APIs for integration with external systems, such as querying broker statistics information, clients information, subscribe topics information, and restart with new config file.

NanoMQ Broker's HTTP API service listens on port 8081 by default. You can modify the listening port through the configuration file of `etc/nanomq.conf`. All API calls with `api/v1`.

## Interface security

NanoMQ Broker's HTTP API uses the method of [Basic Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) or [JWT Authentication](./jwt.md). The `username` and `password` must be filled. The default `username` and `password` are: `admin/public`. You can modify username and password through the configuration file of `etc/nanomq.conf`.