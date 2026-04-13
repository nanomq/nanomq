## 1.4.0
Release Date: 2026-04-13

### Enhancements
- Rename binary from nanomq to emqx-edge.
- Extend the HTTP server to support multiple accounts.
- Updated password in HTTP Server with a encrypted one.
- Added TLS support to the HTTP Server.
- Support to set ALPN for OpenSSL and MbedTLS TLS Layers.
- Support to create a LMQ for each topic of Bridge.
- Added fuzz for MQTT-Stream.
- Updated l8w8jwt from 2.1.0 to 2.5.0.
- Updated dashboard to 0.0.7.
  - Move superuser configuration from authentication to authorization.
  - Support multiple accounts for dashboard.
  - Support more parameters for HTTP ACL request.
  - Support to set ACL Cache TTL for ACL and Superuser HTTP request.

### Fixes
- Fixed the error that nanomq stop reading args when read the conf path.
- Fixed the wrong retain flags when the message was not sent.
- Fixed the wrong keepalive behavior when a client set keepalive to 0.
- Fixed the wrong mtx guard range in websocket transport layer.
- Fixed the compatibility issue of Posix interface send on MacOS when use no_local.
- Fixed the missing pipe id property in retain message.
- Fixed the TLS alert and PSA API error when access HTTPS Server.
- Fixed the extra usernames and passwords in configuration.
- Fixed the error that failed to encode Will msg for MQTT V5.
- Fixed potential memleaks in parquet search and msg cat/split.
- Fixed potential memleaks of http response in webhook aio callback.
- Fixed the error in CI about base62.
- Fixed several typos and issues in CI.
