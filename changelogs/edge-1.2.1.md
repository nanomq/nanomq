## 1.2.1
Release Date: 2026-01-14

### Enhancements
- EMQX-Edge with Parquet is supported now.
- Arm64 docker image for EMQX-Edge is supported now.
- ACL Cache mechanism is supported.
- Added shared tag for different Docker platforms.
- Optimizated the process of message resend and check logic of MQTT bridge.
- Optimizated the github workflow.
- Updated dashboard to 0.0.6-beta.1.

### Fixes
- Fixed the missing checking for length of UTF-8 string when handling MQTTV3.1.1 subscribe packets.
- Update the path of configuration file in docker image.
- Fixed some errors in configuration about SNI and SQLite.
- Fixed some memory address security issues in websocket layer.
- Fixed some memory address security issues in Rule Engine.
- Fixed the error that the metrics for quic bridge didn't work.
- Fixed the issue that builtin MQTT Client Hook-trigger keep reconnecting when ACL is enabled.
- Fixed the issue that Super Request doesn't work when ACL Cache is enabled.
