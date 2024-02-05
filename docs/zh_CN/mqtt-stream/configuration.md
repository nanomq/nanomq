# 通过配置文件开启MQTT STREAM
本节将介绍如何通过配置nanomq.conf配置文件来开启MQTT STREAM

## 配置选项
以下是一个简单的MQTT STREAM 配置样例
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

- exchange_client: 承载exchange的客户端
- exchange: 用于接收特定topic消息的交换机，并将消息数据放入ringbus中
- ringbus: 用于存放mqtt消息，其大小是可以进行设置，同时还提供了fullOp，也就是当ringbus满的时候的行为
  - cap: ringbus容量大小
  - fullOp: 目前提供了四种当ringbus满的时候的行为
    ```
        0: RB_FULL_NONE: 当ringbus满时，不执行额外动作，入队失败
        1: RB_FULL_DROP: 当ringbus满时，将该消息丢弃，清空所有在ringbus中的数据并执行入队动作
        2: RB_FULL_RETURN: 当ringbus满时，ringbus中的数据会放入aio进行返回
        3: RB_FULL_FILE（依赖parquet）: 当ringbus满时，ringbus中的数据会写入文件中进行持久化存储
    ```
    注意： 如果fullOp=3则需要开启PARQUET编译选项，并在nanomq.conf中配置parquet
    ```
    # 开启PARQUET编译选项
    cmake -DENABLE_PARQUET=ON ../
    ```
    ```
    # 在nanomq.conf中配置parquet
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

## 测试MQTT STREAM
接下来是ringbus的fullOp为3为例，测试mqtt stream的落盘能力。（记得开启parquet编译选项）
1. 配置选项
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

2. 启动NanoMQ
```
nanomq start --conf=/etc/nanomq.conf
```

3. 使用emqtt_bench发送消息
```
emqtt_bench pub -p 1883 -i 1 -I 1 -c 1 -s 10 -t "topic1" -V 5 -L 30005
```

4. NanoMQ打印
```
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--79060194635079892~370618470429406089.parquet success
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--370618474724373386~375711962341231626.parquet success
ringbuffer_parquet_cb: ringbus: parquet write to file: /tmp/nanomq-parquet/nanomq-parquet--375711966636198923~380805454253057163.parquet success
```

5. 文件存储路径
```
/tmp/nanomq-parquet/nanomq-parquet--370618474724373386~375711962341231626.parquet
/tmp/nanomq-parquet/nanomq-parquet--375711966636198923~380805454253057163.parquet
/tmp/nanomq-parquet/nanomq-parquet--79060194635079892~370618470429406089.parquet
```