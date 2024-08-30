//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is suencoded_datalied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "include/plugin.h"
#include "nng/exchange/stream/stream.h"
#ifdef SUPP_PARQUET
#include "nng/supplemental/nanolib/parquet.h"
#endif

#define SPI_STREAM_NAME "spi"
#define SPI_STREAM_ID	0x1

static char *uint16_to_hexstring(uint16_t num)
{
	char *hex_string = NULL;
	hex_string = nng_alloc(5);
	if (hex_string == NULL) {
		return NULL;
	}
	snprintf(hex_string, 6, "%04x", num);
	return hex_string;
}

static inline void memcpy_bigendian(void *dst, void *src, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++) {
		((uint8_t *)dst)[i] = ((uint8_t *)src)[len - i - 1];
	}

	return;
}

/*
|---------------------------------msg------------------------------------|
|0x55(1byte)|   type+id(2byte)   |  len+update(1byte)   |payload(lenbyte)|
            |type(4bit)|id(12bit)|update(1bit)|len(7bit)|
*/
static inline uint8_t msg_get_len(void *msg)
{
	uint8_t len = 0;

	memcpy_bigendian(&len, msg + 3, 1);
	len = len & 0x7f;

	return len;
}

static inline uint16_t msg_get_packet_type_id(void *msg)
{
	uint16_t packet_type_id = 0;

	memcpy_bigendian(&packet_type_id, msg + 1, 2);

	return packet_type_id;
}

static void schema_free(char **schema, uint32_t len)
{
	if (schema == NULL) {
		return;
	}

	for (uint32_t i = 0; i < len; i++) {
		if (schema[i] != NULL) {
			nng_free(schema[i], strlen(schema[i]) + 1);
		}
	}

	nng_free(schema, len * sizeof(char *));
	return;
}

static int spi_schema_map_add(nng_id_map *spi_schema_map, uint16_t packet_type_id)
{
	uint16_t schema_id = packet_type_id;
	void *schema = NULL;
	schema = nng_id_get(spi_schema_map, schema_id);
	if (schema != NULL) {
		return -1;
	}

	char *schema_hex = uint16_to_hexstring(schema_id);
	if (schema_hex == NULL) {
		return -1;
	}

	nng_id_set(spi_schema_map, schema_id, schema_hex);
	return 0;
}

static inline bool spi_payload_valid(void *payload)
{
	if (((uint8_t *)payload)[0] != 0x55) {
		return false;
	}

	return true;
}

static void get_schema(void *data, uint32_t len, nng_id_map *spi_schema_map, uint32_t *pschema_map_len)
{
	int ret = 0;
	void *payload = NULL;
	int payload_len = 0;

	/* | header(6) | msg1 | ... | msgn |*/
	payload = data + 6;
	payload_len = len - 6;
	while (payload_len > 0) {
		if (payload_len < 4) {
			break;
		}

		uint8_t msg_len = msg_get_len(payload);
		if (spi_payload_valid(payload) == false) {
			payload += msg_len + 4;
			payload_len -= msg_len + 4;
			continue;
		}

		uint16_t packet_type_id = msg_get_packet_type_id(payload);
		ret = spi_schema_map_add(spi_schema_map, packet_type_id);
		if (ret == 0) {
			*pschema_map_len += 1;
		}

		payload += msg_len + 4;
		payload_len -= msg_len + 4;
	}

	return;
}

struct schema_array {
	char **schema;
	nng_id_map *spi_schema_index_map;
	uint32_t len;
};

static void schema_array_cb(void *id, void *data, void *arg)
{
	struct schema_array *sarray = NULL;

	sarray = (struct schema_array *)arg;
	if (sarray == NULL) {
		return;
	}

	/* start with 1 */
	nng_id_set(sarray->spi_schema_index_map, (*(uint16_t *)id), (void *)(uintptr_t)sarray->len);

	sarray->schema[sarray->len++] = data;

	return;
}

static char **spi_get_schemas(void **data,
							  uint32_t *data_len,
							  uint32_t data_size,
							  uint32_t *pschemas_len,
							  nng_id_map *spi_schema_index_map)
{
	int ret = 0;
	char **schemas = NULL;
	struct schema_array sarray;
	uint32_t schema_map_len = 0;

	nng_id_map *spi_schema_map = NULL;
	ret = nng_id_map_alloc(&spi_schema_map, 0, 0xffff, false);
	if (ret != 0) {
		return NULL;
	}

	for (uint32_t i = 0; i < data_size; i++) {
		get_schema(data[i], data_len[i], spi_schema_map, &schema_map_len);
	}

	if (schema_map_len == 0) {
		nng_id_map_free(spi_schema_map);
		return NULL;
	}

	schemas = nng_alloc((schema_map_len + 1) * sizeof(char *));
	if (schemas == NULL) {
		nng_id_map_free(spi_schema_map);
		return NULL;
	}

	schemas[0] = nng_alloc(strlen("ts") + 1);
	strcpy(schemas[0], "ts");

	sarray.schema = schemas;
	sarray.len = 1;

	sarray.spi_schema_index_map = spi_schema_index_map;

	nng_id_map_foreach2(spi_schema_map, schema_array_cb, &sarray);

	nng_id_map_free(spi_schema_map);

	*pschemas_len = schema_map_len;

	return schemas;
}

static inline void payload_arr_free(parquet_data_packet ***payload_arr, uint32_t row_len, uint32_t col_len)
{
	if (payload_arr == NULL) {
		return;
	}

	for (uint32_t i = 0; i < col_len; i++) {
		if (payload_arr[i] != NULL) {
			for (uint32_t j = 0; j < row_len; j++) {
				if (payload_arr[i][j] != NULL) {
					nng_free(payload_arr[i][j], sizeof(parquet_data_packet));
				}
			}
			nng_free(payload_arr[i], sizeof(parquet_data_packet *) * row_len);
		}
	}

	nng_free(payload_arr, sizeof(parquet_data_packet **) * col_len * row_len);

	return;
}

static void spiStream_free(struct stream_data_out *output_stream)
{
	if (output_stream == NULL) {
		return;
	}

	schema_free(output_stream->schema, output_stream->col_len + 1);

	payload_arr_free(output_stream->payload_arr, output_stream->row_len, output_stream->col_len);

	nng_free(output_stream->ts, sizeof(uint64_t) * output_stream->row_len);

	nng_free(output_stream, sizeof(struct stream_data_out));

	return;
}

#define SPI_MSG_PAYLOAD(msg) ((msg) + 4)

static int spi_msg_parse(parquet_data_packet ***data, void *spi_msg, uint32_t spi_msg_len, nng_id_map *spi_schema_index_map, uint32_t row_index)
{
	void *msg = NULL;
	int msg_len = 0;

	msg = spi_msg + 10;
	msg_len = spi_msg_len - 10;

	while (msg_len > 0) {
		if (msg_len < 4) {
			break;
		}
		uint8_t len = msg_get_len(msg);
		if (spi_payload_valid(msg) == false) {
			msg += len + 4;
			msg_len -= len + 4;
			continue;
		}

		uint16_t packet_type_id = msg_get_packet_type_id(msg);
		uint32_t offset = (uint32_t)(uintptr_t)nng_id_get(spi_schema_index_map, packet_type_id);
		if (offset == 0) {
			msg += len + 4;
			msg_len -= len + 4;
			continue;
		}

		/* id_map start with 1 */
		offset -= 1;

		data[offset][row_index] = nng_alloc(sizeof(parquet_data_packet));
		if (data[offset][row_index] == NULL) {
			return -1;
		}
		data[offset][row_index]->size = len;
		data[offset][row_index]->data = SPI_MSG_PAYLOAD(msg);
		msg += len + 4;
		msg_len -= len + 4;
	}

	return 0;
}

static struct stream_data_out *spiStream_init(void *data)
{
	int ret = 0;
	struct stream_data_out *output_stream = NULL;
	struct stream_data_in *input_stream = NULL;
	void *encoded_data = NULL;

	input_stream = (struct stream_data_in *)data;
	if (input_stream == NULL || input_stream->len == 0) {
		log_error("input_stream is NULL");
		return NULL;
	}

	output_stream = nng_alloc(sizeof(struct stream_data_out));
	if (output_stream == NULL) {
		log_error("output_stream is NULL");
		return NULL;
	}
	output_stream->schema = NULL;
	output_stream->payload_arr = NULL;
	output_stream->ts = NULL;

	output_stream->row_len = input_stream->len;

	nng_id_map *spi_schema_index_map = NULL;
	nng_id_map_alloc(&spi_schema_index_map, 0, 0xffff, false);
	if (spi_schema_index_map == NULL) {
		spiStream_free(output_stream);
		log_error("spi_schema_index_map is NULL");
		return NULL;
	}

	output_stream->schema = spi_get_schemas(input_stream->datas, input_stream->lens, input_stream->len, &output_stream->col_len, spi_schema_index_map);
	if (output_stream->schema == NULL) {
		spiStream_free(output_stream);
		nng_id_map_free(spi_schema_index_map);
		log_error("output_stream->schema is NULL");
		return NULL;
	}

	output_stream->ts = nng_alloc(sizeof(uint64_t) * output_stream->row_len);
	if (output_stream->ts == NULL) {
		spiStream_free(output_stream);
		nng_id_map_free(spi_schema_index_map);
		log_error("output_stream->ts is NULL");
		return NULL;
	}

	output_stream->payload_arr = nng_alloc(sizeof(parquet_data_packet **) * output_stream->col_len);
	if (output_stream->payload_arr == NULL) {
		spiStream_free(output_stream);
		nng_id_map_free(spi_schema_index_map);
		log_error("output_stream->payload_arr is NULL");
		return NULL;
	}

	for (uint32_t i = 0; i < output_stream->row_len; i++) {
		output_stream->ts[i] = input_stream->keys[i];
	}

	for (uint32_t i = 0; i < output_stream->col_len; i++) {
		output_stream->payload_arr[i] = nng_alloc(sizeof(parquet_data_packet *) * output_stream->row_len);
		if (output_stream->payload_arr[i] == NULL) {
			spiStream_free(output_stream);
			nng_id_map_free(spi_schema_index_map);
			log_error("output_stream->payload_arr[i] is NULL");
			return NULL;
		}
		for (uint32_t j = 0; j < output_stream->row_len; j++) {
			output_stream->payload_arr[i][j] = NULL;
		}
	}

	for (uint32_t i = 0; i < output_stream->row_len; i++) {
		ret = spi_msg_parse(output_stream->payload_arr, input_stream->datas[i], input_stream->lens[i], spi_schema_index_map, i);
		if (ret != 0) {
			spiStream_free(output_stream);
			nng_id_map_free(spi_schema_index_map);
			log_error("spi_msg_parse failed");
			return NULL;
		}
	}

	nng_id_map_free(spi_schema_index_map);

	encoded_data = parquet_data_alloc(output_stream->schema, output_stream->payload_arr, output_stream->ts, output_stream->col_len, output_stream->row_len);
	if (encoded_data == NULL) {
		log_error("parquet_data_alloc failed");
		spiStream_free(output_stream);
		return NULL;
	}

	nng_free(output_stream, sizeof(struct stream_data_out));

	return encoded_data;
}

static inline uint16_t hexstringToUInt16(const char *hexstr)
{
	uint16_t value = 0;
	if (hexstr == NULL) {
		return 0;
	}

	while (*hexstr) {
		char c = *hexstr++;
		uint8_t digit;
	
		if (isdigit(c)) {
			digit = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			digit = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			digit = c - 'A' + 10;
		} else {
			return 0;
		}

		value = (value << 4) | digit;
	}

	return value;
}

static struct stream_decoded_data *spi_stream_decode(struct parquet_data_ret *parquet_data)
{
	struct stream_decoded_data *decoded_data = NULL;

	if (parquet_data == NULL) {
		return NULL;
	}

	decoded_data = nng_alloc(sizeof(struct stream_decoded_data));
	if (decoded_data == NULL) {
		return NULL;
	}

	decoded_data->data = NULL;
	decoded_data->len = 0;

	uint32_t row_len[parquet_data->row_len];
	for (uint32_t i = 0; i < parquet_data->row_len; i++) {
		row_len[i] = 0;
		for (uint32_t j = 0; j < parquet_data->col_len; j++) {
			if (parquet_data->payload_arr[j][i] != NULL && parquet_data->payload_arr[j][i]->size != 0) {
				row_len[i] += parquet_data->payload_arr[j][i]->size + 4;
				decoded_data->len += parquet_data->payload_arr[j][i]->size + 4;
			}
		}
		if (row_len[i] != 0) {
			decoded_data->len += 8;
			decoded_data->len += 2;
		}
	}

	if (decoded_data->len == 0) {
		nng_free(decoded_data, sizeof(struct stream_decoded_data));
		return NULL;
	}

	decoded_data->data = nng_alloc(decoded_data->len);
	if (decoded_data->data == NULL) {
		return NULL;
	}

	uint32_t decoded_data_index = 0;
	for (uint32_t i = 0; i < parquet_data->row_len; i++) {
		if (row_len[i] == 0) {
			continue;
		}
		memcpy_bigendian(decoded_data->data + decoded_data_index, &parquet_data->ts[i], 8);
		decoded_data_index += 8;
		memcpy_bigendian(decoded_data->data + decoded_data_index, &row_len[i], 2);
		decoded_data_index += 2;
		for (uint32_t j = 0; j < parquet_data->col_len; j++) {
			if (parquet_data->payload_arr[j][i] == NULL) {
				continue;
			}
			if (parquet_data->payload_arr[j][i]->size == 0) {
				continue;
			}
			/* for header */
			uint8_t header = 0x55;
			memcpy_bigendian(decoded_data->data + decoded_data_index, &header, 1);
			decoded_data_index += 1;
			/* type+id */
			uint16_t packet_type_id = 0;
			packet_type_id = hexstringToUInt16(parquet_data->schema[j]);
			memcpy_bigendian(decoded_data->data + decoded_data_index, &packet_type_id, 2);
			decoded_data_index += 2;
			/* update+len */
			memcpy_bigendian(decoded_data->data + decoded_data_index, &parquet_data->payload_arr[j][i]->size, 1);
			decoded_data_index += 1;

			memcpy_bigendian(decoded_data->data + decoded_data_index, parquet_data->payload_arr[j][i]->data, parquet_data->payload_arr[j][i]->size);
			decoded_data_index += parquet_data->payload_arr[j][i]->size;
		}
	}

	return decoded_data;
}

void *spi_decode(void *data)
{
	struct parquet_data_ret *parquet_data = (struct parquet_data_ret *)data;
	if (parquet_data == NULL) {
		return NULL;
	}

	struct stream_decoded_data *decoded_data = NULL;

	decoded_data = spi_stream_decode(parquet_data);

	return decoded_data;
}

void *spi_encode(void *data)
{
	struct stream_data_out *output_stream = NULL;
	output_stream = spiStream_init(data);
	if (output_stream == NULL) {
		return NULL;
	}

	return output_stream;
}

static int checkInput(const char *input,
					  uint32_t *start_key_index,
					  uint32_t *end_key_index,
					  uint32_t *schema_index)
{
	int count = 0;

	*start_key_index = 0;
	*end_key_index = 0;
	*schema_index = 0;

	if (strncmp(input, "sync", 4) != 0 && strncmp(input, "async", 5) != 0) {
		log_error("Error: Invalid input format\n");
		return -1;
	}

	for (unsigned int i = 0; i < strlen(input); i++) {
		if (input[i] == '-') {
			if (count == 0) {
				*start_key_index = i + 1;
			} else if (count == 1) {
				*end_key_index = i + 1;
			} else if (count == 2) {
				*schema_index = i + 1;
			}
			count++;
		}
	}

	if (count != 2 && count != 3) {
		log_error("Error: Invalid input format\n");
		return -1;
	}

	for (unsigned int i = *start_key_index; i < *end_key_index - 1; i++) {
		if (input[i] < '0' || input[i] > '9') {
			log_error("Error: Invalid input format\n");
			return -1;
		}
	}

	for (unsigned int i = *end_key_index; i < (*schema_index == 0 ? strlen(input) : *schema_index - 1); i++) {
		if (input[i] < '0' || input[i] > '9') {
			log_error("Error: Invalid input format\n");
			return -1;
		}
	}

	return 0;
}

static char **schema_parse(const char *schema_str, uint32_t schema_str_len, uint32_t *schema_len)
{
	char **schema = NULL;

	*schema_len = schema_str_len / 4;

	schema = nng_alloc(sizeof(char *) * (*schema_len));
	if (schema == NULL) {
		return NULL;
	}

	for (uint32_t i = 0; i < *schema_len; i++) {
		schema[i] = nng_alloc(5);
		if (schema[i] == NULL) {
			schema_free(schema, i);
			return NULL;
		}
		memcpy(schema[i], schema_str + i * 4, 4);
		schema[i][4] = '\0';
	}

	return schema;
}

static struct cmd_data *parse_input_cmd(const char *input)
{
	struct cmd_data *cmd_data = NULL;
	uint32_t start_key_index = 0;
	uint32_t end_key_index = 0;
	uint32_t schema_index = 0;

	cmd_data = (struct cmd_data *)nng_alloc(sizeof(struct cmd_data));
	if (cmd_data == NULL) {
		return NULL;
	}
	cmd_data->schema = NULL;
	cmd_data->schema_len = 0;

	if (checkInput(input, &start_key_index, &end_key_index, &schema_index) != 0) {
		log_error("checkInput failed\n");
		nng_free(cmd_data, sizeof(struct cmd_data));
		return NULL;
	}

	if (strncmp(input, "sync", 4) == 0) {
		cmd_data->is_sync = true;
	} else if (strncmp(input, "async", 5) == 0) {
		cmd_data->is_sync = false;
	} else {
		log_error("Error: Invalid input format\n");
		nng_free(cmd_data, sizeof(struct cmd_data));
		return NULL;
	}

	cmd_data->start_key = (uint64_t)atoll(input + start_key_index);
	cmd_data->end_key = (uint64_t)atoll(input + end_key_index);

	if (schema_index != 0) {
		cmd_data->schema = schema_parse(input + schema_index, strlen(input) - schema_index, &cmd_data->schema_len);
	}
	log_info("start_key: %ld end_key: %ld schema_len: %d", cmd_data->start_key, cmd_data->end_key, cmd_data->schema_len);

	return cmd_data;
}

void *spi_cmd_parser(void *data)
{
	struct cmd_data *cmd_data = NULL;

	cmd_data = parse_input_cmd((const char *)data);
	if (cmd_data == NULL) {
		return NULL;
	}

	return cmd_data;
}

int spi_plugin_init()
{
	int ret = 0;
	char *name = NULL;

	name = (char *)malloc(strlen(SPI_STREAM_NAME) + 1);
	if (name == NULL) {
		return -1;
	}

	strcpy(name, SPI_STREAM_NAME);

	ret = stream_register(name, SPI_STREAM_ID, spi_decode, spi_encode, spi_cmd_parser);
	if (ret != 0) {
		log_error("stream_register %s failed", name);
		free(name);

		return -1;
	}

	return ret;
}
