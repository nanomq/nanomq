# Changelog for NanoMQ

## NanoMQ 0.17.2

### What's Changed

* Fix a use-after-free bug in sub_handler.c by @moonZHH in https://github.com/emqx/nanomq/pull/1117
* Fixed vsomeip compile error. by @lee-emqx in https://github.com/emqx/nanomq/pull/1121
* Sync with new version of nanosdk by @JaylinYu in https://github.com/emqx/nanomq/pull/1124
* New QUIC config params & move nng head by @JaylinYu in https://github.com/emqx/nanomq/pull/1125
* Fix #1127 by @JaylinYu in https://github.com/emqx/nanomq/pull/1129
* Support generates idl_convert.c & idl_convert.h with specified idl file by cmake. by @alvin1221 in https://github.com/emqx/nanomq/pull/1122
* Update dds README.md by @alvin1221 in https://github.com/emqx/nanomq/pull/1123
* MDF [nng] move nng head fix release by @JaylinYu in https://github.com/emqx/nanomq/pull/1130
* NEW [conf] Add new configuration option 0RTT supported. by @wanghaEMQ in https://github.com/emqx/nanomq/pull/1136
* Add docs for QUIC & TCP bridge by @alvin1221 in https://github.com/emqx/nanomq/pull/1134
* Update en_US/config-description. by @alvin1221 in https://github.com/emqx/nanomq/pull/1139
* Update bridging documents (English) by @alvin1221 in https://github.com/emqx/nanomq/pull/1140
* Fix the wrong default value was set in nanomq_example.conf. by @wanghaEMQ in https://github.com/emqx/nanomq/pull/1143
* Update docs related to mqtt bridge by @alvin1221 in https://github.com/emqx/nanomq/pull/1144
* MDF [conf] update docs & move nng head by @JaylinYu in https://github.com/emqx/nanomq/pull/1146


### What's Changed in NanoNNG
* FIX [broker_tcp] Fix the error that sending null tcp packets. by @wanghaEMQ in https://github.com/nanomq/NanoNNG/pull/487
* Fix No_Local by @JaylinYu in https://github.com/nanomq/NanoNNG/pull/488
* Fix the error that heap-buffer-overflow on rotation index. by @wanghaEMQ in https://github.com/nanomq/NanoNNG/pull/489
* Configuration 0RTT option is supported. by @wanghaEMQ in https://github.com/nanomq/NanoNNG/pull/493
* Fix [QUIC] seg.fault & remove unused configuration item by @alvin1221 in https://github.com/nanomq/NanoNNG/pull/495
* FIX [mqtt-tcp test] fix memleak of connmsg. by @Hermann0222 in https://github.com/nanomq/NanoNNG/pull/491
* fix memleak in nng_mqtt_client_free & transtest by @Hermann0222 in https://github.com/nanomq/NanoNNG/pull/496
* Fix the error that the value in bridge_node was not initialled by @wanghaEMQ in https://github.com/nanomq/NanoNNG/pull/497
* FIX [QUIC] fix potential deadlock in mqtt over quic by @JaylinYu in https://github.com/nanomq/NanoNNG/pull/503

**Full Changelog**: https://github.com/nanomq/NanoNNG/compare/0.17.0...0.17.2

### New Contributors
* @moonZHH made their first contribution in https://github.com/emqx/nanomq/pull/1117

**Full Changelog**: https://github.com/emqx/nanomq/compare/0.16.5...0.17.2