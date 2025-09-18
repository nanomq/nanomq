## v1.1.0.beta.3
Release Date: 2025-09-18

### Enhancements
- New HTTP reaping framework with better performance.
- Updated Dashboard to version 0.0.4-beta.4.
- Added heartbeat logs for EMQX Edge.
- New encrypted bridge password is supported.
- Updated configuration files.

### Fixes
- Fixed the error that local ws clients and tls clients can't receive messages from subscriptions.
- Fixed the error where resend aio might be null in hybrid bridging mode.
- Fixed the wrong CPU and Memory usage on Windows.
- Fixed the issue where Dashboard can't get latest logs on Windows.

