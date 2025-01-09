# Enable the MQTT STREAM through the configuration file
In this section, we will describe how to enable MQTT streams by configuring the nanomq.conf configuration file.

Since 0.23.0, The MQTT stream of NanoMQ is a value add-on feature for commercial customer. Please contact us if you need a light-weight Messaging queue data persistence.

## Configuration
Here is a simple example MQTT STREAM configuration.
```
exchange_client.mq1 {
	# # exchanges contains multiple MQ exchanger
	exchange {
		# # MQTT Topic for filtering messages and saving to queue
		topic = "exchange/topic1",
		# # MQ name
		name = "exchange_no1",
		# # MQ category. Only support Ringbus for now
		ringbus = {
			# # ring buffer name
			name = "ringbus",
			# # max length of ring buffer (msg count)
			cap = 1000,
			fullOp = 3
		}
	}
}
```

- exchange_client: The client hosting the exchange.
- exchange: It is used to receive a specific topic message and put the message data into ringbus.
- ringbus: For storing mqtt messages, its capacity can be set, and it also provides fullOp, which is the behavior when the ringbus is full.
  - cap: ringbus capacity size.
  - fullOp: Four behaviors are currently provided when the ringbus is full.
    ```
        0: RB_FULL_NONE: When the ringbus is full, no action is taken and the message enqueue fail.
        1: RB_FULL_DROP: When the ringbus is full, the data in the ringbus is discarded.
        2: RB_FULL_RETURN: When the ringbus is full, the data in the ringbus is taken out and returned to the aio.
        3: RB_FULL_FILE(Relying on parquet): When the ringbus is full, the data in the ringbus is written to the file.
    ```
    Note: If fullOp=3 you need to enable PARQUET compilation and configure parquet in nanomq.conf.
    ```
    # Enable PARQUET compile options
    cmake -DENABLE_PARQUET=ON ../
    ```
    ```
    # Configure parquet in nanomq.conf
    parquet {
        compress = gzip
        encryption {
            key_id = kf
            key = "0123456789012345"
            type = AES_GCM_CTR_V1
        }
        dir = "/tmp/nanomq-parquet"
        file_name_prefix = "nanomq-parquet-"
        file_count = 5
    }
    ```

## Testing the MQTT STREAM
This is followed by an example of fullOp of 3 for ringbus to test the offloading capability of mqtt stream. (Remember to enable parquet compile).
1. Configuration
```
...
exchange_client.mq1 {
	# # exchanges contains multiple MQ exchanger
	exchange {
		# # MQTT Topic for filtering messages and saving to queue
		topic = "topic1",
		# # MQ name
		name = "exchange_no1",
		# # MQ category. Only support Ringbus for now
		ringbus = {
			# # ring buffer name
			name = "ringbus",
			# # max length of ring buffer (msg count)
			cap = 10000,
			fullOp = 3
		}
	}
}
...
parquet {
    compress = gzip
    encryption {
        key_id = kf
        key = "0123456789012345"
        type = AES_GCM_CTR_V1
    }
    dir = "/tmp/nanomq-parquet"
    file_name_prefix = "nanomq-parquet-"
    file_count = 5
}
...
```

1. Start NanoMQ
```
nanomq start --conf=/etc/nanomq.conf
```

1. Publish mqtt messages
mqtt messages are sent using emqtt_bench
```
emqtt_bench pub -p 1883 -i 1 -I 1 -c 1 -s 10 -t "topic1" -V 5 -L 30005
```

1. The NanoMQ log
NanoMQ prints a log to indicate that the disk write was successful.
```
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--79060194635079892~370618470429406089.parquet success
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--370618474724373386~375711962341231626.parquet success
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--375711966636198923~380805454253057163.parquet success
```

1. File storage path
```
/tmp/nanomq-parquet/nanomq-parquet--370618474724373386~375711962341231626.parquet
/tmp/nanomq-parquet/nanomq-parquet--375711966636198923~380805454253057163.parquet
/tmp/nanomq-parquet/nanomq-parquet--79060194635079892~370618470429406089.parquet
```