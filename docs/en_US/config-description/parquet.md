# Parquet

NanoMQ provides scalable and event-driven Parquet functionality, allowing users to configure trigger events or message topics for exchanges through rules. With the help of Parquet, users can persist data in the Parquet format.

Parquet is a columnar storage format known for its efficient compression and query performance. By configuring relevant parameters in Parquet, users have the flexibility to control the storage method, compression algorithm, and encoding to meet specific requirements.

## **Example Configuration**
Below are the rule settings for exchanges and the relevant configurations for Parquet persistence:
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
parquet { # # Parquet compress type.
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

## **Configuration Items**
exchange_client
- exchange_client.\<name>: Exchange client, When multiple exchange_clients need to be started, they can be launched by specifying multiple different names for each exchange.
- `exchange.topic`: MQTT Topic for filtering messages and saving to queue.
- `exchange.name`: Exchange name.
- `exchange.ringbus.name`: ring bus name.
- `exchange.ringbus.cap`: ring bus capacity.
- `exchange.ringbus.fullOp`: the operation when ringbus is full.

parquet
- `parquet.compress`: Compress algorithm. value: `uncompressed | snappy | gzip | brotli | zstd | lz4` default is: `uncompressed`.
- `parquet.encryption`: Encryption option.
- `parquet.encryption.key_id`: Key retrieval metadata.
- `parquet.encryption.key`: Encryption key, key must be either 16, 24 or 32 bytes.
- `parquet.encryption.key`: Encryption algorithm. If not called, files will be encrypted with AES_GCM_V1 (default). value :`AES_GCM_CTR_V1 | AES_GCM_V1` .
- `parquet.dir`: The folder where Parquet files are stored.
- `parquet.file_name_prefix`: The prefix used for naming Parquet files.
- `parquet.file_count`: The maximum number of Parquet files allowed.
