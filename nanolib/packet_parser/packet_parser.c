#include "packet_parser.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t
packet_parse_uint8(struct mqtt_packet *packet)
{
	assert(packet && packet->remaining_length >= packet->pos + 1);
	return packet->binary[packet->pos++];
}

uint16_t
packet_parse_uint16(struct mqtt_packet *packet)
{
	assert(packet && packet->remaining_length >= packet->pos + 2);
	uint16_t res = packet->binary[packet->pos++];
	return (res << 8) + packet->binary[packet->pos++];
}

/* TODO judge endian */
// uint16_t packet_parse_uint16(struct mqtt_packet *packet)
//{
//    assert(packet && packet->remaining_length >= packet->pos+2);
//
//    uint16_t res = 0;
//    memcpy((uint16_t*)&res, (uint16_t*)&(packet->binary[packet->pos]),
//    sizeof(res)); printf("res is: %#X\n", res); packet->pos+=2; return res;
//}

uint32_t
packet_parse_uint32(struct mqtt_packet *packet)
{
	assert(packet && packet->remaining_length >= packet->pos + 4);
	uint32_t res = packet->binary[packet->pos++];

	if (res) {
		while ((0xFF000000 & res) == 0) {
			res = (res << 8) + packet->binary[packet->pos++];
		}
	} else {
		int i = 4;
		while (--i > 0) {
			res = (res << 8) + packet->binary[packet->pos++];
		}
	}

	return res;
}

void
packet_parse_string(struct mqtt_packet *packet, char str[], uint32_t length)
{
	assert(packet && packet->remaining_length >= packet->pos + length);
	memcpy(str, &(packet->binary[packet->pos]), length);
	packet->pos += length;
}

uint32_t
packet_parse_var(struct mqtt_packet *packet)
{
	assert(packet);
	int      i          = 4;
	uint32_t res        = 0;
	uint32_t multiplier = 1;
	uint8_t  byte;
	do {
		assert(packet->remaining_length >= packet->pos);

		byte = packet->binary[packet->pos++];

		res += (byte & 127) * multiplier;
		multiplier *= 128;
	} while (i-- && (byte & 128));
	return res;
}

void
packet_write_uint8(struct mqtt_packet *packet, uint8_t input)
{
	assert(packet && packet->remaining_length >= packet->pos + 1);
	packet->binary[packet->pos++] = input;
}

void
packet_write_uint16(struct mqtt_packet *packet, uint16_t input)
{
	assert(packet && packet->remaining_length >= packet->pos + 2);
	packet->binary[packet->pos++] = (input & 0xFF00) >> 8;
	packet->binary[packet->pos++] = input & 0x00FF;
}

void
packet_write_uint32(struct mqtt_packet *packet, uint32_t input)
{
	assert(packet && packet->remaining_length >= packet->pos + 4);
	packet->binary[packet->pos++] = (input & 0xFF000000) >> 24;
	packet->binary[packet->pos++] = (input & 0x00FF0000) >> 16;
	packet->binary[packet->pos++] = (input & 0x0000FF00) >> 8;
	packet->binary[packet->pos++] = (input & 0x000000FF);
}

void
packet_write_string(struct mqtt_packet *packet, char str[], uint32_t length)
{
	assert(packet && packet->remaining_length >= packet->pos + length);
	memcpy(&(packet->binary[packet->pos]), str, length);
	packet->pos += length;
}

void
packet_write_var(struct mqtt_packet *packet, uint32_t input)
{
	assert(packet);
	uint8_t byte;
	do {
		assert(packet->remaining_length >= packet->pos);
		/* Can be optimized */
		byte = input % 128;
		input /= 128;
		if (input > 0) {
			byte |= 128;
		}
		packet->binary[packet->pos++] = byte;

	} while (input);
}
