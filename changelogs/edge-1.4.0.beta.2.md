## 1.4.0.beta.2
Release Date: 2026-04-08

### Enhancements
- Optimize & consolidate get_utf8_str.

### Fixes
- Fixed potential memleak in parquet search and msg cat/split.
- Fixed memleak of http response in webhook aio callback.
- Fixed the error in CI about base62.
- Synced the fix for issue 2268 from oss.
- Fixed the wrong mtx guard range in websock transport layer.
