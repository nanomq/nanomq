# dds2mqtt

Here we combine dds with mqtt. So DDS node can communicate with MQTT broker.

DDS node <--local--> NanoSDK client <--network--> NanoMQ Broker

## Requires

Select cyclonedds as dds backend.

+ CycloneDDS version == 0.10.1

NanoSDK is a MQTT SDK.

+ NanoSDK version >= 0.7.5

Note. libddsc and libnng should be installed.

## NOTE

+ Select topics from configure file is not supported.
+ [How to enable and run Cyclone DDS with shared memory exchange](./doc/Shared_memory.md).

## Update IDL

Update dds_type.idl. Then go to path/to/nanomq directory.

Edit CMakeLists.txt and specific your structure name in dds_type.idl as DDS_TYPE_NAME.

Note. The code about type conversation between DDS_TYPE_NAME and MQTT should be provided.

## Quick start

Step1. Turn on nanomq

```bash
./nanomq start
```

Step2. Start the dds2mqtt proxy 

```bash
./nanomq_cli ddsproxy proxy --conf nanomq_dds_gateway.conf
```

Test msgs from DDS to MQTT

Step3.

```bash
./nanomq_cli sub --url "mqtt-tcp://127.0.0.1:1883" -t "DDS/topic1"
```

Step4.

```bash
./nanomq_cli ddsproxy pub -t "MQTTCMD/topic1"
```

Test msgs from MQTT to DDS

Step5.

```bash
./nanomq_cli ddsproxy sub -t "MQTT/topic1"
```

Step6.

```bash
./nanomq_cli pub --url "mqtt-tcp://127.0.0.1:1883" -t "DDSCMD/topic1" -m '{
        "int8_test":    1,
        "uint8_test":   50,
        "int16_test":   27381,
        "uint16_test":  1,
        "int32_test":   0,
        "uint32_test":  32,
        "int64_test":   6820785120,
        "uint64_test":  25855901936,
        "message":      "aaabbbddd",
        "example_enum": 0,
        "example_stru": {
                "message":      "abc"
        }
}'
```

