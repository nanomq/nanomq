# Shared Memory

## Build 

The following steps are intended to describe how build CycloneDDS with Iecoryx to support shared memory exchange;

### Iceoryx

> Get and build iceoryx.

```bash
$ git clone https://github.com/eclipse-iceoryx/iceoryx.git
$ cd iceoryx
$ git checkout release_2.0
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX={YOUR_LIBRARY_PATH} ../iceoryx_meta
$ ninja
$ sudo ninja install
```

### CycloneDDS

> Get Cyclone DDS and build it with shared memory support.

```bash
$ git clone git@github.com:eclipse-cyclonedds/cyclonedds.git
$ cd cyclonedds
$ mkdir build && cd build
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON -DCMAKE_INSTALL_PREFIX={YOUR_LIBRARY_PATH} -DCMAKE_PREFIX_PATH={YOUR_LIBRARY_PATH} ..
$ ninja 
$ sudo ninja install
```



## Run

Now, to start running Cyclone DDS with shared memory exchange.

1. Create an example `iceoryx` configuration file which has a memory pool of 2^15 blocks which can store data types of 16384 bytes (+ 64 byte header = 16448 byte block): <br>

   ```toml
   [general]
   version = 1
   
   [[segment]]
   
   [[segment.mempool]]
   size = 16448
   count = 32768
   ```

   Please save this file as *iox_config.toml* in your own directory.

2. Start `RouDi` in `iceoryx` in *1st* terminal.<br>

   ```bash
   $ cd {YOUR_LIBRARY_PATH}
   $ bin/iox-roudi -c iox_config.toml
   ```

3. Run a MQTT broker in *2nd* terminal .<br>

   ```bash
   $ nanomq start
   ```

4. Enable shared memory in the configuration file `nanomq_dds_gateway.conf` .<br>

   ```bash
   dds {
       idl_type = topic1Type
       
       # # dds domain id
       # # default: 0
       # # Value: uint32
       domain_id = 0
       
       shared_memory = {
           # # Enable shared memory transport.
           # # Iceoryx is required if enable shared memory transport.
           # #
           # # Default: false
           # # Value:  boolean
           enable = true
           
           # # controls the output of the iceoryx runtime and can be set to, in order of decreasing output:
           # # log level: verbose, debug, info, warn, error, fatal, off
           # # Default:  info
           # # Value: enum
           log_level = info
       }
   }
   ```

5. Start the dds2mqtt proxy in *3rd* terminal.

   ```bash
   $ ./nanomq_cli ddsproxy proxy --conf nanomq_dds_gateway.conf 
   ```

6. Subscribe from MQTT in *4th* terminal.

   ```bash
   $ ./nanomq_cli sub --url "mqtt-tcp://127.0.0.1:1883" -t "DDS/topic1"
   ```

7. Publish message to DDS in *5th* terminal (enable shared memory with `[-s, --shm_mode]`) .

   ```bash
   $ ./nanomq_cli ddsproxy pub -t "MQTTCMD/topic1" -s 
   ```

8.  Subscribe from DDS in *6th* terminal (enable shared memory with `[-s, --shm_mode]`) .<br>

   ```bash
   $ ./nanomq_cli ddsproxy sub -t "MQTT/topic1" -s 
   ```

9. Publish message to MQTT in *7th* terminal .

   ```bash
   $ ./nanomq_cli pub --url "mqtt-tcp://127.0.0.1:1883" -t "DDSCMD/topic1" -m '{
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

   
