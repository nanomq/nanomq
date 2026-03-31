## 1.4.0.alpha.2
Release Date: 2026-03-31

### Enhancements
- Rename binary from nanomq to emqx-edge.
- Support to set ALPN for OpenSSL TLS Layer.
- Support to create a LMQ for each topic of Bridge.
- Updated dashboard to 0.0.7-beta.2. (multiple accounts for dashboard)
- Updated dashboard to 0.0.7-beta.3. (cache_ttl config And CN/Subject Param in HTTP ACL)

### Fixes
- Fixed the wrong retain flags when the message was not sent.
- Fixed the keepalive behavior when a client set keepalive to 0.
- Fixed the compatibility issue of Posix interface send on MacOS when use no_local.
- Fixed the missing pipe id property in retain message.
