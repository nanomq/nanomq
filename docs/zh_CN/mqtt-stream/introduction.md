# MQTT STREAM
对于同一topic的MQTT消息，可以看做一条数据流，并且这个数据流是可以进行落盘存储以及查询操作的，对于一些网络较差的环境下，为数据的完整性和可靠性提供了解决方案.

本章主要介绍如何[通过配置文件开启MQTT STREAM](./configuration.md)以及[如何使用consumer对持久化的数据进行查询](./consumer.md).

## 通过配置文件开启MQTT STREAM
本节将介绍如何通过配置nanomq.conf配置文件来开启MQTT STREAM.

## 通过consumer对持久化的数据进行查询
本节将介绍如何使用consumer对持久化的数据进行查询，并提供一个demo供参考.
