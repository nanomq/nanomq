## v1.3.0
Release Date: 2026-01-29

### Enhancements
- Updated license policy. EMQX Edge will stop accepting new MQTT connections instead of exiting when license expires.
- EMQX Edge now supports Arm64 docker image.
- Added shared tag for different Docker platforms.
- Optimizated the process of message resend and check logic of MQTT bridge.
- Optimizated the github workflow.
- Updated dashboard to 0.0.6.

### Fixes
- Fixed missing UTF-8 string length validation when handling MQTT v3.1.1 SUBSCRIBE packets.
- Updated the configuration file path in Docker image.
- Fixed configuration errors related to SNI and SQLite.
- Fixed memory address security issues in WebSocket layer.
- Fixed memory address security issues in Rule Engine.
- Fixed an issue where QUIC bridge metrics did not work correctly.
- Fixed an issue where the built-in MQTT client hook trigger kept reconnecting when ACL was enabled.
- Fixed an issue where Super Request did not work when ACL cache was enabled.
- Fixed an error where Dashboard could not retrieve the QUIC bridge status after reloading.
- Fixed an error when reading configuration items with millisecond (`ms`) units.
- Fixed errors when performing Parquet history queries.
- Fixed an issue where a null QUIC connection was closed during QUIC bridge reload.
- Reset `max_ack_delay` to the default maximum value when an invalid value was configured.
- Fixed an issue where the Dashboard failed to access `quic_handshake_timeout`.
- Fixed incorrect QUIC bridge behavior when certificates were set to null.
- Fixed an error when parsing a null encrypted password.
- Fixed incorrect default values for some QUIC options.
