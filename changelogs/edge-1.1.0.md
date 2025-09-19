## v1.1.0
Release Date: 2025-09-19

### Summary
- New EMQX Edge for Windows was supported.
- New encrypted password in configuration file was supported.
- New REST APIs to get logs.
- New HTTP framework and AES module were introduced.
- Updated Dashboard to v0.0.4.
- Fixed some issues.

### Enhancements
- Added REST APIs to AES encrypted data.
- Updated authorization REST APIs and accessing IP Address is supported.
- Updated online/offline notification messages.
- Replace passwords in authentication with base64d encrypted passwords.
- New AES module was introduced.
- Added REST APIs to get the latest logs.
- Added REST APIs to get a tarball file contains all logs files.
- Added REST APIs to enable or disable ACL rules and bridge cache.
- Added EMQX Edge packages for Windows.
- Added new configuration file for Windows EMQX Edge.
- Added TLS, Sqlite and JWT support for Windows EMQX Edge.
- Updated default maximum packet size to protocol defined value.
- New HTTP reaping framework with better performance.
- Added heartbeat logs for EMQX Edge.
- New encrypted bridge password is supported.
- Updated configuration files for new features.
- Added more items to metric RestAPI.
- Updated Dashboard to version 0.0.4.

### Fixes
- Fixed some unmatch dashboard APIs.
- Fixed some potential data races on quic layers.
- Fixed the statistics of bytes sent and received.
- Fixed the error that build-in mqtt client keep reconnecting when auth.http is enabled.
- Fixed the start command for Windows EMQX Edge, Now EMQX Edge has same start command on linux and Windows.
- Fixed the error that local ws clients and tls clients can't receive messages from subscriptions.
- Fixed the error where resend aio might be null in hybrid bridging mode.
- Fixed the wrong CPU and Memory usage on Windows.
- Fixed the issue where Dashboard can't get latest logs on Windows.
- Fixed the issue where bridge cache bytes statistic is wrong.
- Fixed the issue where Dashboard can't switch pages of logs on Windows.

