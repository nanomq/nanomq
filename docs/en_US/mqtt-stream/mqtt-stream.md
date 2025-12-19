## MQTT Stream Data Persistence and Query Mechanism

This document is based on the current NanoMQ codebase and explains the **MQTT Stream capability (data persistence based on exchange/ringbus)**. It focuses on:

- **Data pipeline and background**: how MQTT messages flow from the broker into ringbus  
- **Persistence plugins and encoding**: how `streamType` decides which plugin to use and how encode/decode works  
- **Querying persisted data**: how to use `exchange_consumer` to query data from ringbus / parquet files  

---

## I. Background and Data Pipeline

### 1.1 Background and Positioning

In this project, MQTT Stream is primarily positioned for **in-vehicle data closed-loop** scenarios. It provides OEMs and Tier-1s with a robust path for **“from in-vehicle bus → gateway → local persistence → post-incident analysis”**.

In a typical in-vehicle deployment:

- There are multiple buses and data sources in the vehicle, for example:  
  - CAN / CAN-FD frames (reported via topics like `canudp`, `canspi`, etc.)  
  - High-frequency sensor data from subsystems (battery, motor, etc.)  
  - Gateway internal status and diagnostics information  
- These data streams are aggregated by the in-vehicle gateway and then reported to a local NanoMQ instance via MQTT.

In a real production environment, relying solely on “online reporting to the cloud” is not sufficient to meet several key requirements:

- **Traceability for abnormal events**:  
  - When a vehicle experiences anomalies during road tests or in production (e.g. power loss, battery alerts, bus jitter), the OEM needs **a complete window of raw data around the event**;  
  - This usually covers multiple subsystems and buses, and a time span from seconds to minutes, for reproducing the issue, root cause analysis, and subsequent calibration / software updates.

- **Reliability in weak-network / offline conditions**:  
  - Vehicles operate in complex environments, where cellular coverage may be weak or unavailable;  
  - If we only rely on “real-time reporting to cloud”, crucial data at the time of the incident may never reach the backend;  
  - By doing **batch buffering + parquet persistence** locally on the vehicle, we can ensure that critical data is preserved even if cloud connectivity is lost for a long period.

- **Vehicle–cloud closed-loop and feedback**:  
  - Persisted data can be exported locally at plants or test centers, or collected remotely from the fleet;  
  - Combined with cloud analytics and simulation platforms, this enables a complete loop: **vehicle-side data collection → cloud-side analysis → strategy/calibration updates → delivered back to the vehicle**.

To achieve this, NanoMQ introduces an internal **Exchange + Ringbus + Parquet / custom Stream plugin** pipeline inside the broker to:

- Perform side-channel collection and filtering of specific topics (such as `canudp`);  
- Use ringbus for high-performance local buffering, and trigger batch processing once a threshold (e.g. 1000 messages) is reached;  
- Let Stream plugins encode each batch into structured data (e.g. parquet) and write it to local storage;  
- Later, provide query interfaces and tools such as `exchange_consumer` for extracting historical data **by time window or key range**, for debugging, replay, and analysis.

In short, you can think of MQTT Stream as:  
**“A reliable, locally traceable persistence and query pipeline for CAN/diagnostics and other high-frequency data on the in-vehicle NanoMQ, and a core component for vehicle data closed-loop.”**

### 1.2 End-to-end Data Pipeline Overview (High-level)

From a user’s perspective, when MQTT Stream is enabled, a message published on a topic like `canudp` goes through the following stages:

1. **MQTT ingress**  
   - The device publishes a PUBLISH packet to NanoMQ (e.g. topic `canudp`);  
   - The broker receives it and performs the normal MQTT forwarding logic.

2. **Hook copies data into Exchange**  
   - In `webhook_post.c::hook_entry`, the broker clones this PUBLISH message and adds metadata such as timestamp;  
   - It then matches the topic against `exchange_client.mqX.exchange.topic`, and if matched, sends the cloned message to the Exchange Server via a local NNG socket.

3. **Exchange / ringbus buffering**  
   - On the Exchange Server side, each configured exchange maintains its own ringbus;  
   - Received MQTT messages are enqueued into ringbus using a timestamp as the key; the number of buffered messages is limited by `cap`.

4. **fullOp handling and batch output**  
   - When a ringbus accumulates `cap` messages, it triggers the configured `fullOp` behavior;  
   - We **recommend using `RB_FULL_RETURN`**: in this mode, ringbus returns the current batch of messages to the upper layer at once (rather than writing files directly), then clears itself and continues accepting new messages.

5. **Stream plugin encoding and Parquet persistence**  
   - The upper layer (hook callback / Exchange helper logic) receives this batch of messages, builds a `stream_data_in`, and calls `stream_encode(streamType, ...)` which enters the active Stream plugin;  
   - The plugin encodes this batch into a parquet-friendly structure, and then the parquet async APIs write it into files under the configured directory.

If you only care about “**which switch to flip and how data flows**”, the five steps above are enough. For a code-level, step-by-step explanation of each stage and exact call stacks, see the next section: **1.3 End-to-end Data Pipeline (Code-level)**.

### 1.3 End-to-end Data Pipeline (Code-Level)

This section walks through the complete code path:  
**MQTT PUBLISH → Hook → Exchange / ringbus → FULL_RETURN → Stream plugin encoding → Parquet persistence (and later querying)**.

#### 1.3.1 Config Loading and Exchange Initialization

- **Config parsing (`conf_ver2.c::conf_exchange_parse_ver2`)**  
  - Reads each `exchange_client.mqX` node from `nanomq.conf` and fills a `conf_exchange_node`:  
    - `name`: MQ name (e.g. `"exchange_no1"`)  
    - `topic`: MQTT topic to filter (e.g. `"canudp"`)  
    - `streamType`: Stream plugin ID (0 = RAW, 1 = SPI, or a custom value)  
    - `ringbus`: contains `name/cap/fullOp` and other ringbuffer parameters  
  - All `conf_exchange_node` instances are stored in the global `conf.exchange.nodes[]` (`conf_exchange`) for runtime access.

- **Exchange Client / Server setup (`broker.c` + `exchange_server.c`)**  
  - During broker startup, `broker.c` uses `conf_exchange` to:  
    - Create a NNG socket for each `exchange_client.mqX`, and connect to the local Exchange Server via `exchange_url` (see `nng/src/mqtt/protocol/exchange/exchange_server.c`);  
    - Store the created `nng_socket*` in `conf_exchange_node->sock` so it can be used directly by the Hook.  
  - On the Exchange Server side, these sockets are used to create `exchange_t` instances and initialize the corresponding `ringBuffer_t` for each exchange (`exchange.c::exchange_init` + `ringBuffer_init`).

#### 1.3.2 Broker-side Hook: Copying MQTT Flow into Exchange

- **Entry point: `webhook_post.c::hook_entry`**  
  - Every time the broker receives an MQTT PUBLISH (`work->flag == CMD_PUBLISH`), it enters `hook_entry`:  
    - It obtains `conf_exchange` from `work->config->exchange`;  
    - It checks parquet settings via `work->config->parquet`.  
  - The Exchange data flow is triggered only if:
    - `ex_conf->count > 0` (i.e. at least one `exchange_client` is configured);  
    - `parquetconf->enable == true`;  
    - The current message is of type PUBLISH.

- **Message cloning and timestamp setup**  
  - To avoid touching the original MQTT flow, the Hook does the following (see the middle of `hook_entry`):  
    - Allocates a new internal message `msg` with `nng_msg_alloc`;  
    - Copies header and body (`nng_msg_header_append` / `nng_msg_append`);  
    - Adjusts the payload pointer (`nng_msg_set_payload_ptr`) to ensure it points to the correct region;  
    - Sets a timestamp `ts`:
      - `ts = nng_timestamp()`; using `ts_mtx` to enforce monotonicity; finally writes it with `nng_msg_set_timestamp(msg, ts)`;  
    - This timestamp serves as the key for ringbus and parquet queries later on.

- **Topic matching and sending to Exchange**  
  - The Hook iterates all `conf_exchange_node` entries:
    - Uses `topic_filter(ex_conf->nodes[i]->topic, work->pub_packet->var_header.publish.topic_name.body)` to check if the message matches;  
    - If matched, it takes the corresponding async `aio` from `hook_conf->saios[...]` and waits for it to be free;  
    - It then binds the cloned `msg` to the `aio` and sends it to the Exchange Client socket via `nng_send_aio(*ex_sock, aio)` (`ex_sock = ex_conf->nodes[i]->sock`).  
  - At this point, the MQTT PUBLISH has been “side-copied” into the Exchange module, entering the **internal MQ / ringbus pipeline**.

#### 1.3.3 Exchange Server: Enqueuing into Ringbus and Handling Full Conditions

- **Receiving and enqueueing (`exchange_server.c::exchange_sock_send` → `exchange_do_send`)**  
  - When the Exchange Server receives a PUBLISH from the Hook, it calls:
    - `exchange_client_handle_msg(ex_node, msg, aio)`, which in turn uses the message’s timestamp as `key` to call:  
      - `exchange_handle_msg(ex_node->ex, key, msg, aio)` (see `exchange.c`).  
  - `exchange_handle_msg` writes the message into the corresponding ringbuffer:  
    - It actually calls `ringBuffer_enqueue(ex->rbs[i], key, msg, -1, aio)`;  
    - The `key` here is exactly the `nng_msg_timestamp` set in the Hook.

- **Full behavior (`ringbuffer.c::ringBuffer_enqueue`)**  
  - When `rb->size == rb->cap`, `ringBuffer_enqueue` checks `fullOp` and acts as follows:
    - `RB_FULL_NONE`: logs an error and returns enqueue failure; old data is preserved.  
    - `RB_FULL_DROP`: calls `ringBuffer_clean_msgs(rb, 1)` to clear and free all existing messages, then enqueues the new message into an empty buffer.  
    - `RB_FULL_RETURN` (recommended):  
      - Uses `ringBuffer_get_and_clean_msgs` to get all current messages and clear the ringbus, returning them as a `nng_msg** list`;  
      - Sends that list and its length into the supplied `aio` via `put_msgs_to_aio(rb, aio)`, so the upper-layer callback (e.g. `send_exchange_cb` / `hook_last_flush`) can process (encode + persist) them;  
      - After clearing, it enqueues the new message normally.  
    - `RB_FULL_FILE`:  
      - If parquet/BLF is enabled, calls `write_msgs_to_file(rb)` to write the current buffer directly to disk and then clears the ringbus before enqueueing the new message (mainly used for internal testing).

#### 1.3.4 From FULL_RETURN to Stream Encoding and Parquet Persistence

- **Handling FULL_RETURN callback (`webhook_post.c::send_exchange_cb` / `hook_last_flush`)**  
  - When `RB_FULL_RETURN` is triggered, the `aio` holds a batch of `nng_msg**` and the list length:  
    - `get_flush_params()` extracts from `aio` / `msg`:
      - `msgs_del`: the array of messages to persist;  
      - `msgs_len`: its length;  
      - `topic`: the exchange topic;  
      - `streamType`: the Stream plugin ID for this exchange.  
  - Then `flush_smsg_to_disk()` is called:
    - First, `nng_msg**` is wrapped into a `struct stream_data_in` (keys from `nni_msg_get_timestamp`);  
    - Then `stream_encode(streamType, sdata)` is invoked, which dispatches into the plugin’s `encode` implementation (e.g. RAW’s `raw_encode`) to build a parquet-friendly structure (e.g. a `parquet_data*`);  
    - Finally, parquet APIs (`parquet_object_alloc` + `parquet_write_batch_async`) write this batch asynchronously to disk.

Through these stages, **a single MQTT PUBLISH is collected at the broker, side-copied into Exchange/ringbus, and when FULL_RETURN is triggered, the Stream plugin encodes the batch and writes it into parquet files**. This provides a reliable data foundation for later queries and replay. How parquet/ringbus data is read back, decoded via `stream_decode`, and returned to `exchange_consumer` is covered in later sections.

### 1.4 Example Configuration: `canudp`

In `etc/nanomq.conf`, the persistence pipeline is enabled using config like the snippet below (note that we use `fullOp = 2`, i.e. `RB_FULL_RETURN`, as the recommended setting):

```conf
# Exchange configuration for Embedded Messaging Queue
exchange_client.mq1 {
    # Exchange Server URL (local MQ backend)
    exchange_url = "tcp://127.0.0.1:10000"

    # Each "exchange" defines one logical MQ for a given topic
    exchange {
        # MQTT topic to filter and enqueue
        topic = "canudp",
        # Exchange (MQ) name
        name  = "exchange_no1",
        # Optional: specify the Stream plugin type for encoding/decoding
        # streamType = 0  # 0: RAW; 1: SPI; ...

        # MQ category: currently only Ringbus is supported
        ringbus = {
            name = "ringbus",
            # Max number of messages buffered in ringbus
            cap  = 1000,
            # fullOp strategy, 2 = RB_FULL_RETURN (recommended)
            fullOp = 2
        }
    }
}

# Parquet persistence settings (apply to Exchange/Messaging_Queue)
parquet {
    # Parquet compression type: uncompressed | snappy | gzip | brotli | zstd | lz4
    compress         = zstd
    # Directory to store parquet files
    dir              = "./parquet"
    # File name prefix for generated parquet files
    file_name_prefix = "nanomq"
    # Max number of rotated parquet files
    file_count       = 10
    # Max size of each parquet file
    file_size        = 100MB
    # Max number of search operations per second
    limit_frequency  = 5
}
```

In this example:

- PUBLISH messages on topic `canudp` are captured by `hook_entry` and forwarded to the Exchange Server via `exchange_client.mq1`;  
- The ringbus capacity is 1000 messages. Once 1000 messages accumulate, `fullOp = 2 (RB_FULL_RETURN)` is triggered: the ringbuffer returns the current batch to the upper-layer aio, clears itself, and then enqueues the new message;  
- The upper layer uses the returned batch to build `stream_data_in`, calls `stream_encode(streamType, ...)` and then uses the parquet module to write the encoded data into files under `./parquet`, achieving **batched persistence**.

---

## II. Persistence Plugins and Encoding/Decoding Mechanism

### 2.1 Stream Plugin Architecture Overview

In NanoMQ, the actual behavior of “**how MQTT messages are encoded/decoded for persistence**” is governed by the **Stream plugin system**. Core code is located in:

- `nng/exchange/stream/stream.c`  
- `nng/exchange/stream/raw_stream.c`  
- `nanomq/plugin_spi_stream.c` / `nanomq/plugin/plugin_spi_stream.c`

The key abstraction is:

- `stream_register(name, id, decode, encode, cmd_parser)`  
  - Each plugin is uniquely identified by an `id`;  
  - It provides three key callbacks:
    - `encode`: encodes internal message structures into a format suitable for persistence/transport (e.g. parquet columnar data);  
    - `decode`: decodes persisted data back into a structure that upper layers can consume (e.g. a continuous binary buffer);  
    - `cmd_parser`: parses textual query commands from upper layers (e.g. RAW’s `"sync-<start>-<end>"`).

Currently at least two Stream plugins are built-in:

- **Raw Stream (`RAW_STREAM_ID = 0`)**  
  - A simple, generic plugin which mainly passes MQTT payload as-is, suitable for general-purpose use.  
- **SPI Stream (`SPI_STREAM_ID = 0x1`)** (registered in `spi_plugin_init` / `nano_plugin_init`)  
  - Designed for SDV/automotive scenarios, with a custom key structure and query protocol.

The `streamType` field in `conf_exchange_node` tells Exchange **which Stream plugin ID to use** for a specific MQ node.

### 2.2 From Ringbus to Persistence: Encoding Pipeline

Using the recommended `RB_FULL_RETURN` + `flush_smsg_to_disk` path as an example, the core pipeline from ringbus to parquet persistence is (see `ringbuffer.c`, `webhook_post.c`, and `stream.c`):

1. **Build `stream_data_in` from ringbus**  
   - When ringbus is full and `RB_FULL_RETURN` is configured, `ringBuffer_get_and_clean_msgs` retrieves all messages currently in the buffer and clears it;  
   - In `webhook_post.c::flush_smsg_to_disk` / `cb_data_init`, these messages are normalized into a `struct stream_data_in`:
     - `datas[i]` points to each message’s payload;  
     - `lens[i]` is the payload length;  
     - `keys[i]` is the key for each message (using `nni_msg_get_timestamp(msg)`, i.e. the timestamp).

2. **Call Stream plugin `encode`**  
   - The upper layer calls `stream_encode(streamType, sdata)`:
     - For RAW, `raw_encode` converts `stream_data_in` to `stream_data_out`, then uses `parquet_data_alloc` to build the parquet columnar structure;  
     - Other plugins can perform custom logic here: selecting columns, compressing data, normalizing payloads, etc.  
   - The encoded result (typically `parquet_data*`) represents a **batch of messages** and is passed to the backend persistence layer.

3. **Write to Parquet and other backends**  
   - With `SUPP_PARQUET` enabled, the encoded batch is wrapped into a parquet object:  
     - Contains schema (column names/types), payload columns, and a timestamp column (`ts`);  
   - It is then written asynchronously to disk via `parquet_object_alloc` + `parquet_write_batch_async`; the actual path and name prefix are determined by the `parquet { ... }` section in the config.  
   - BLF and other formats are still experimental and not covered in detail here; their data flows are similar: on ringbus full, the batch is forwarded to the corresponding backend for file writing.

Through this pipeline, MQTT messages are normalized and encoded by Stream plugins before landing in parquet files, balancing performance with downstream queryability.

### 2.3 From Persistence Back to Query Results: Decoding Pipeline

When upper layers need to query historical data (for example via `exchange_consumer`), the decoding pipeline is:

1. **Parse query command via `cmd_parser`**  
   - The upper layer sends a textual query command to the Exchange Server over pair0:  
     - For RAW, the format is `sync-<start_key>-<end_key>` or `async-<start_key>-<end_key>`;  
     - Other plugins (like SPI) may define their own command formats.  
   - `exchange_server.c::query_cb` reads the command string `keystr` and calls:  
     - `cmd_data *cmd = stream_cmd_parser(streamType, keystr)`  
   - `cmd_data` generally includes:
     - `is_sync`: whether to use sync or async mode;  
     - `start_key` / `end_key`: the key (timestamp) range to query;  
     - `schema`: which columns to retrieve (RAW defaults to `{"ts", "data"}`, see `raw_stream.c::parse_input_cmd`).

2. **Exchange Server reads data and calls `decode`**  
   - In `query_send_sync` / `query_send_async`, Exchange will:
     - Read in-memory data from ringbus in the given key range (`exchange_client_get_msgs_fuzz`);  
     - And query parquet files using functions like `parquet_get_data_packets_in_range_by_column`, obtaining `parquet_data_ret**`.  
   - For each `parquet_data_ret*` from parquet, it calls:
     - `struct stream_decoded_data *out = stream_decode(streamType, parquet_data_ret_ptr)`  
   - For RAW, `raw_decode`:
     - Computes the total size of all `payload_arr[i][j]` entries;  
     - Allocates a continuous buffer and concatenates each record’s `data` into this buffer, forming a single continuous data stream.

3. **Reassemble and return results**  
   - Exchange merges decoded data from ringbus (in-memory) and parquet (on-disk) and writes them into outgoing NNG messages:  
     - In sync mode, all decoded results may be aggregated into one or a few NNG messages before sending;  
     - In async mode, decoded results are typically split into multiple messages (e.g. per file or per time span) and sent incrementally.  
   - The exact binary format of the reply payload is defined by the Stream plugin:
     - For RAW, it is a continuous binary buffer (multiple payloads concatenated);  
     - For a custom plugin, it could be JSON, TLV, or any proprietary protocol.  
   - Upper-level tools such as `exchange_consumer` only need to parse the byte stream according to the plugin’s agreed format in order to consume historical data.

By combining `encode` and `decode`, NanoMQ supports **“raw MQTT packets → structured persistence → plugin-defined replay/query format”** without hardcoding persistence and query logic into the broker core, making the system both flexible and extensible.

### 2.4 Extending Stream Plugins

Beyond the built-in RAW/SPI plugins, users can implement their own Stream plugins. You only need to implement a few standard interfaces and register them at startup.

#### 2.4.1 Required Data Structures and Interfaces

In `nng/include/nng/exchange/stream/stream.h`, Stream-related shared structures and registration interfaces are defined (excerpted here):

```c
struct stream_data_in {
    void     **datas;  // payload pointer for each message
    uint64_t  *keys;   // key for each message (usually timestamp)
    uint32_t  *lens;   // payload length for each message
    uint32_t   len;    // number of messages
};

struct stream_data_out {
    uint32_t                col_len;     // number of columns
    uint32_t                row_len;     // number of rows
    uint64_t               *ts;          // timestamp column
    char                  **schema;      // column names
    parquet_data_packet ***payload_arr;  // per-column payload (for parquet)
};

struct stream_decoded_data {
    void     *data;   // decoded continuous buffer
    uint32_t  len;    // length of data
};

struct cmd_data {
    bool      is_sync;     // true: sync; false: async
    uint64_t  start_key;   // start key (typically a timestamp)
    uint64_t  end_key;     // end key
    uint32_t  schema_len;  // number of requested columns
    char    **schema;      // column names (e.g. {"ts", "data"})
};

int   stream_register(char *name, uint8_t id,
                      void *(*decode)(void *),
                      void *(*encode)(void *),
                      void *(*cmd_parser)(void *));
void *stream_decode(uint8_t id, void *buf);
void *stream_encode(uint8_t id, void *buf);
void *stream_cmd_parser(uint8_t id, void *buf);
```

Typically, a custom plugin needs to implement three functions (using `my` as an example):

```c
// 1) Encoding: convert batched ringbus messages into a structure suitable for persistence (usually parquet_data)
void *my_encode(void *data);
// data type: struct stream_data_in *
// return: an object for parquet writing (commonly build stream_data_out then call parquet_data_alloc to get parquet_data*)

// 2) Decoding: convert parquet query results (parquet_data_ret*) into a continuous buffer
void *my_decode(void *data);
// data type: struct parquet_data_ret *
// return: struct stream_decoded_data *

// 3) Command parser: parse textual query commands into cmd_data
void *my_cmd_parser(void *data);
// data type: const char * (command string from exchange_consumer)
// return: struct cmd_data *
```

In your plugin initialization, use `stream_register` to register your plugin (see `raw_stream_register` / `spi_plugin_init` for reference):

```c
int my_stream_init() {
    int   ret  = 0;
    char *name = malloc(strlen("my_stream") + 1);
    if (name == NULL) {
        return -1;
    }
    strcpy(name, "my_stream");

    // Suppose we choose 0x2 as our custom ID; ensure it does not conflict with existing ones (0=RAW, 0x1=SPI)
    ret = stream_register(name, 0x2, my_decode, my_encode, my_cmd_parser);
    if (ret != 0) {
        free(name);
        return -1;
    }
    return 0;
}
```

After registration, simply set `streamType = 0x2` in the corresponding `exchange` section of `nanomq.conf`, and the whole pipeline will switch to your plugin.

#### 2.4.2 Where in the Pipeline the Plugin is Called

Based on the earlier data flow, a custom Stream plugin intercepts the pipeline at three critical points:

- **1) Batch encoding before persistence (`encode`)**  
  - Trigger: ringbus is full and `FULL_RETURN` is configured, or when `hook_last_flush` is explicitly called to flush remaining data.  
  - Call stack (simplified):
    - `ringBuffer_enqueue` with `RB_FULL_RETURN` packs all current messages into `aio`;  
    - `webhook_post.c::send_exchange_cb` / `hook_last_flush` uses `get_flush_params` to extract `streamType` and the message list;  
    - It builds a `struct stream_data_in` and then calls:  
      - `stream_encode(streamType, sdata)` → lands in your `my_encode`;  
    - The encoded result (often `parquet_data*`) is passed into `parquet_object_alloc` / `parquet_write_batch_async` to be persisted.

- **2) Query command parsing (`cmd_parser`)**  
  - Trigger: `exchange_consumer` sends a textual query command to Exchange over pair0.  
  - Call stack (simplified):
    - `exchange_consumer` sends a command (e.g. `"sync-<start>-<end>"`) as payload;  
    - `exchange_server.c::query_cb` reads `keystr` and calls:  
      - `cmd_data *cmd = stream_cmd_parser(streamType, keystr)` → lands in your `my_cmd_parser`;  
    - `cmd_data` (with `is_sync/start_key/end_key/schema` etc.) is then used by `query_send_sync` / `query_send_async` to drive ringbus + parquet queries.

- **3) Query result decoding (`decode`)**  
  - Trigger: `query_send_sync` / `query_send_async` retrieve raw records from parquet files or ringbus.  
  - Call stack (simplified):
    - Parquet queries produce a `parquet_data_ret*` array (via `parquet_get_data_packets_in_range_by_column`, etc.);  
    - For each entry, Exchange calls:
      - `stream_decode(streamType, parquet_data_ret_ptr)` → lands in your `my_decode`;  
    - `my_decode` reshapes the columnar structure into the final payload format (e.g. a continuous binary buffer or a JSON blob);  
    - The decoded results (`struct stream_decoded_data`) are appended to NNG messages and returned to `exchange_consumer` or other upper layers via pair0.

With these three extension points, you can:

- Customize the **batch encoding strategy** before persistence (e.g. column selection, compression, payload normalization);  
- Customize the **query protocol and syntax** (not limited to `sync/async-<start>-<end>`);  
- Customize the **response payload format** (raw binary, JSON, proprietary protocol, etc.), without modifying NanoMQ’s broker core.

---

## III. Build and Test Workflow

This section uses scripts and configs from the repository to provide a **build + persistence test** workflow so you can quickly validate the MQTT Stream capability.

### 3.1 Building NanoMQ (Enabling Parquet)

From the repository root, we recommend using the existing `build.sh`:

```bash
./build.sh
```

`build.sh` roughly does:

```bash
mkdir build
cd build
cmake -DENABLE_PARQUET=ON -DENABLE_FILETRANSFER=ON ../
make -j32
```

- **ENABLE_PARQUET=ON**: enables Parquet support, allowing batched ringbus data to be written into parquet files;  
- **ENABLE_FILETRANSFER=ON**: enables file-transfer-related features (useful for future extensions).

After building, the `build/` directory contains the `nanomq` binary and related demo programs.

### 3.2 Recommended Test Config (excerpt from `nanomq.conf`)

Below is a recommended configuration excerpt from `etc/nanomq.conf`, using the `canudp` topic as an example, with ringbus capacity set to 1000 and `fullOp` set to **FULL_RETURN (2)**:

```conf
#====================================================================
# Exchange configuration for Embedded Messaging Queue
#====================================================================
# Initialize multiple MQ exchangers by giving them different names (mq1)
exchange_client.mq1 {
	# Currently NanoMQ only supports one MQ object. URL must be identical.
	exchange_url = "tcp://127.0.0.1:10000"
	# "exchange" contains one or more logical MQ definitions
	exchange {
		# MQTT topic for filtering messages and saving to ringbus
		topic = "canudp",
		# MQ name
		name = "exchange_no1",
		# MQ category. Only Ringbus is supported for now
		ringbus = {
			# ring buffer name
			name = "ringbus",
			# max length of ring buffer (message count)
			cap = 1000,
			#  0: RB_FULL_NONE   - when ringbus is full, no extra action; enqueue fails
			#  1: RB_FULL_DROP   - when ringbus is full, drop existing data in ringbus
			#  2: RB_FULL_RETURN - when ringbus is full, return buffered data via aio (recommended)
			#  3: RB_FULL_FILE   - when ringbus is full, write buffered data into file
			#
			# Value: 0–4
			# Default: 0
			# Note: SDV flow is only applicable to RB_FULL_RETURN (2)
			fullOp = 2
		}
	}
}

#====================================================================
# Parquet configuration (applies to Exchange/Messaging_Queue)
#====================================================================
parquet {
	# Parquet compress type.
	# Value: uncompressed | snappy | gzip | brotli | zstd | lz4
	compress = zstd
	# Directory for parquet files.
	# Value: folder path
	dir = "./parquet"
	# Prefix for parquet file names.
	file_name_prefix = "nanomq"
	# Maximum rotation count of parquet files.
	# Default: 5
	file_count = 10
	# Maximum size of a parquet file.
	# Default: 10M
	# Supported units: KB | MB | GB
	file_size = 100MB
	# Maximum number of searches per second.
	# Default: 5
	limit_frequency = 5
}
```

**Notes and recommendations:**

- For most users, **FULL_RETURN (2)** is the preferred choice: ringbus returns batched messages to upper-layer flows (e.g. SDV logic) which then encode and persist them via parquet;  
- `RB_FULL_FILE (3)` lets ringbus write files directly and is mainly used in internal testing; it is **not recommended as the primary external usage**;  
- You can adjust `dir`, `file_name_prefix`, and related fields according to your deployment environment.

### 3.3 Starting NanoMQ and Sending Test Data

1. **Start NanoMQ**

   From the `build/` directory:

   ```bash
   cd build/
   ./nanomq start --conf=../etc/nanomq.conf
   ```

2. **Send 1000 RAW messages on topic `canudp`**

   You can use any MQTT client (`emqtt_bench`, `mosquitto_pub`, or your own tool). For example, using `emqtt_bench`:

   ```bash
   # Example: send 1000 messages to topic "canudp". Adjust payload as needed.
   emqtt_bench pub \
     -h 127.0.0.1 -p 1883 \
     -c 1 -I 1 -i 1 \
     -t "canudp" \
     -s 16 \
     -n 1000
   ```

   As long as the client publishes 1000 messages on `canudp` and the payload structure meets RAW Stream’s expectations, FULL_RETURN will be triggered.

### 3.4 Observing Logs and Parquet Output

When the ringbus accumulates `cap = 1000` messages:

- NanoMQ logs will show messages indicating ringbus is full and FULL_RETURN has been triggered, meaning:
  - ringbus reached its threshold;  
  - the current batch of messages has been returned to the upper-layer aio.

In the recommended SDV flow, the upper-layer will, upon receiving FULL_RETURN data, drive **Parquet write logic**. You will then see generated parquet files under the `parquet.dir` directory, for example:

```text
./parquet/nanomq-canudp-xxxx.parquet
```

This parquet file contains the 1000 `canudp` messages from the batch that triggered FULL_RETURN. You can inspect and analyze it using any parquet tools, for example:

- `parquet-tools`  
- Pandas / PyArrow (Python)  
- Spark / Flink and other big data engines

---

## IV. Querying Persisted Data Using `exchange_consumer`

### 4.1 Query Channel and Protocol

NanoMQ exposes a **local NNG channel** for querying Exchange data. The repository includes a demo program:

- `nng/demo/exchange_consumer/exchange_consumer.c`

This demo:

- Uses `nng_pair0` to connect to the Exchange Server:  
  - Default address: `tcp://127.0.0.1:10000` (matching `exchange_url`);  
- Sends a **single command string** as the payload to the Exchange Server;  
- Keeps receiving replies until it sees a special EOF message:
  - Length is 2 bytes;  
  - Value is `0x0B 0xAD` (see `exchange_server.c::query_send_eof`).

Every message received before EOF can be treated as **one batch of query results**.

### 4.2 Data Layout in ringbus/files (RAW Stream)

With **RAW Stream (`streamType = 0`)**, data in ringbus/files can be viewed as a **key/value** structure:

- **key**: a 64-bit timestamp set via `nng_msg_set_timestamp` (monotonically increasing in milliseconds), suitable for time-range queries;  
- **value**: the encoded MQTT payload (for RAW, usually the original binary payload; in parquet it corresponds to the `data` column).

This key design offers two direct benefits:

- Easy time-window queries (e.g. covering a specific driving interval);  
- Query commands only need to provide start/end keys to fetch all records in that time range.

### 4.3 Using `exchange_consumer` with the New Command Format

The RAW Stream query format has been updated and now uses:

```text
sync-<start_key>-<end_key>
async-<start_key>-<end_key>
```

Where:

- `sync` / `async` specify the query mode:  
  - `sync`: synchronous query; returns all results for the given key range;  
  - `async`: asynchronous mode; Exchange decides how to split and return batches;  
- `<start_key>`: start key, generally a start timestamp (integer);  
- `<end_key>`: end key, generally an end timestamp (must be ≥ `<start_key>`).

With the key semantics described earlier, common usage patterns include:

- Setting a very small start key (e.g. `0`) and a very large end key (e.g. close to “now”) to approximate a “full dump”;  
- Or using precise timestamps to fetch data for an exact time window of interest.

Assuming NanoMQ is running with MQTT Stream configured:

```bash
nanomq start --conf=/etc/nanomq.conf
```

And data is being continuously written into ringbus/files, you can query them using `exchange_consumer`.

#### 4.3.1 Synchronous Query by Time Range

```bash
$ ./demo/exchange_consumer/exchange_consumer "sync-1700000000000-1700000005000"
Received 1234 bytes
Received 5678 bytes
...
```

Explanation:

- Sends the command `"sync-1700000000000-1700000005000"` to the Exchange Server;  
- RAW’s `raw_cmd_parser` parses it to:
  - `is_sync = true`  
  - `start_key = 1700000000000`  
  - `end_key = 1700000005000`  
- Exchange Server reads all records in this time range from parquet, decodes them, and returns them in one or multiple frames, until EOF (`0x0B 0xAD`) is sent.

#### 4.3.2 Asynchronous Query by Time Range

```bash
$ ./demo/exchange_consumer/exchange_consumer "async-1700000000000-1700000005000"
Received 1024 bytes
Received 2048 bytes
...
```

This is similar to `sync`, except `is_sync = false`. Exchange has more freedom in how it schedules and returns results, which is better suited for longer time windows or large data volumes.

> Note: The exact values for `start_key` / `end_key` can be determined based on your business timestamps, the `ts` column in parquet, or upstream logs. For simple validation, you can use a very large range like `sync-0-9223372036854775807` to approximate “fetch everything”.

In more complex scenarios, you can extend RAW or implement custom Stream plugins + `cmd_parser` to support:

- Custom schema (returning more columns);  
- Compound query conditions;  
- Pagination and cursor-based queries.

### 4.4 Working Together with Online Pipelines

Because the Exchange query channel is decoupled from the online MQTT forwarding, you can combine them flexibly:

- **Online + Offline hybrid**:  
  - Real-time processing via standard MQTT subscriptions;  
  - Historical compensation via Exchange queries.  
- **Offline replay**:  
  - Rewriting `exchange_consumer` output back into MQTT or another bus to replay past data.  
- **Shared data lake for multiple downstream systems**:  
  - The same persisted parquet data can be consumed by different analytics, compliance, or monitoring systems, avoiding duplicated data collection/storage.

---

## V. Summary

- **Clear role in the in-vehicle data closed-loop**:  
  - The MQTT Stream capability, combining Exchange, Ringbus, and Parquet, turns topic-level data (like `canudp`) into a **persisted, queryable, and replayable** data stream at the broker;  
  - Under abnormal conditions and weak/offline networks, it still guarantees that critical data is buffered and persisted locally, providing a solid foundation for OEM debugging and optimization.

- **Controllable, extensible end-to-end pipeline with FULL_RETURN**:  
  - From `webhook_post.c::hook_entry` to `exchange_server.c` (ringbus enqueue), to `RB_FULL_RETURN` triggering `flush_smsg_to_disk`, the path is explicit in the code;  
  - Using `fullOp = 2 (RB_FULL_RETURN)` keeps ringbus focused on buffering and batch return, while letting upper layers handle encoding and persistence via Stream plugins and parquet, making the system easier to debug and extend.

- **Flexible Stream plugin and query model**:  
  - With `stream_register` / `stream_encode` / `stream_decode` / `stream_cmd_parser`, users can go beyond RAW/SPI to define custom persistence formats, query protocols, and response formats;  
  - The current RAW plugin already supports time-based `sync/async-<start>-<end>` range queries, and together with the `exchange_consumer` demo, enables convenient time-window replay and export of in-vehicle parquet data.

- **Practical build and test workflow**:  
  - Using `build.sh` plus the recommended `exchange_client` / `parquet` configuration, you can readily reproduce the full pipeline locally: send 1000 test messages on `canudp` → trigger FULL_RETURN → observe parquet file generation → run `exchange_consumer` for time-range queries, verifying that the MQTT Stream behavior matches expectations.


