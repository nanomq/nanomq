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

Select topics from configure file is not supported.

## TEST

Step1. Turn on nanomq

Step2. Start the dds2mqtt proxy

```
./dds2mqtt proxy
```

Test msgs from DDS to MQTT

Step3.

```
./nanomq_cli/nanomq_cli sub --url "mqtt-tcp://127.0.0.1:1883" -t "DDS/HelloWorld"
```

Step4.

```
./dds2mqtt pub
```

Test msgs from MQTT to DDS

Step5.

```
./dds2mqtt sub
```

Step6.

```
./nanomq_cli/nanomq_cli pub -t DDSCMD/HelloWorld -m '{
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

