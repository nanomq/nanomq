# Parquet

NanoMQ 提供了可拓展到事件驱动型的 Parquet 功能，用户可通过规则配置 exchange 的触发事件或消息主题。借助Parquet，用户可以将数据以 Parquet 格式进行落盘。
Parquet 是一种列式存储格式，它具有高效的压缩和查询性能。通过配置 Parquet 的相关参数，用户可以灵活地控制数据的存储方式、压缩算法和编码方式，以满足特定的需求。

## **配置示例**
下面是 exchange 的规则设置和 parquet 落盘的相关配置：
```hcl
# #====================================================================
# # Exchange configuration for Embedded Messaging Queue
# #====================================================================
# # Initalize multiple MQ exchanger by giving them different name (mq1)
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
			# # 2: RB_FULL_RETURN: When the ringbus is full, the data in the ringbus is taken out and returned to the aio
			fullOp = 2
		}
	}
}

# #====================================================================
# # Parquet configuration (Apply to Exchange/Messaging_Queue)
# #====================================================================
parquet {
	# # Parquet compress algorithm.
	# #
	# # Value: uncompressed | snappy | gzip | brotli | zstd | lz4
	compress = uncompressed
	# # Encryption options
	encryption {
		# # Set a key retrieval metadata.
		# #
		# # Value: String
		key_id = kf
		# # Parquet encryption key.
		# #
		# # Value: String key must be either 16, 24 or 32 bytes.
		key = "0123456789012345"
		# # Set encryption algorithm. If not called, files 
		# # will be encrypted with AES_GCM_V1 (default).
		# #
		# # Value: AES_GCM_CTR_V1 | AES_GCM_V1
		type = AES_GCM_V1
	}
	# # The dir for parquet files.
	# #
	# # Value: Folder
	dir = "/tmp/nanomq-parquet"
	# # The prefix of parquet files written.
	# #
	# # Value: string
	file_name_prefix = ""
	# # Maximum rotation count of parquet files.
	# #
	# # Value: Number
	# # Default: 5
	file_count = 5
}
```

## **配置项**
exchange_client
- exchange_client.\<name>：交换机客户端名称, 当需要启动多个交换机时，可以通过指定多个不同的名字来启动。
- `exchange.topic`：MQTT 主题用于过滤消息并保存到队列。
- `exchange.name`: 交换机名称。
- `exchange.ringbus.name`: ring bus 名称。
- `exchange.ringbus.cap`: ring bus 的容量。
- `exchange.ringbus.fullOp`: ring bus 满时需要做的动作。

parquet。
- `parquet.compress`: 选择对应的压缩算法，取值：`uncompressed | snappy | gzip | brotli | zstd | lz4` 默认是 `uncompressed`。
- `parquet.encryption`: 选择对应的加密选项。
- `parquet.encryption.key_id`: 密钥检索元数据。
- `parquet.encryption.key`: 秘钥，密钥必须是16、24或32字节。
- `parquet.encryption.key`: 设置加密算法。支持 `AES_GCM_CTR_V1 | AES_GCM_V1` 两种，默认情况下文件将使用`AES_GCM_V1` 进行加密。
- `parquet.dir`: parquet 文件存储的文件夹。
- `parquet.file_name_prefix`: parquet 文件命名前缀。
- `parquet.file_count`: 最大的 parquet 文件个数。
