## v1.2.0
Release Date: 2025-11-14

### Enhancements
- EMQX Edge Docker Image is available now.
- Support to publish base64 decoded binary data payload with http api.
- Support to set SNI for tls bridge by configuration file.
- Support to download all logs on Windows.
- Updated dashboard to version 0.0.5.

### Fixes
- Fixed the error in updating Windows release packages to Home Page.
- Fixed the name of release package.
- Fixed the a heap use after free error in reloading bridge.
- Fixed the confusing logs that printing logs about TLS when it's a TCP Bridge.
