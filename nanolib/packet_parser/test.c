#include "packet_parser.h"
#include <stdio.h>
#include <stdlib.h>

/* =======================================================================
 * TEST
 * =======================================================================*/

static void
uint8_write_read(uint8_t input, int remaining_length)
{
	struct mqtt_packet packet;

	memset(&packet, 0, sizeof(struct mqtt_packet));

	packet.remaining_length = remaining_length;
	packet.binary = (uint8_t *) malloc(remaining_length * sizeof(uint8_t));
	packet_write_uint8(&packet, input);
	packet.pos = 0;

	uint8_t res = packet_parse_uint8(&packet);
	if (input == res) {
		printf("Bingle, uint8  %#X is OK!\n", input);
	}
	free(packet.binary);
	packet.binary = NULL;
}

static void
uint16_write_read(uint16_t input, uint32_t remaining_length)
{
	struct mqtt_packet packet;
	memset(&packet, 0, sizeof(struct mqtt_packet));
	packet.remaining_length = remaining_length;
	packet.binary = (uint8_t *) malloc(remaining_length * sizeof(uint8_t));
	packet_write_uint16(&packet, input);
	packet.pos   = 0;
	uint16_t res = packet_parse_uint16(&packet);
	if (input == res) {
		printf("Bingle, uint16 %#X is OK!\n", input);
	}

	free(packet.binary);
	packet.binary = NULL;
}

static void
uint32_write_read(uint32_t input, uint32_t remaining_length)
{
	struct mqtt_packet packet;
	memset(&packet, 0, sizeof(struct mqtt_packet));
	packet.remaining_length = remaining_length;
	packet.binary = (uint8_t *) malloc(remaining_length * sizeof(uint8_t));
	packet_write_uint32(&packet, input);
	packet.pos = 0;

	uint32_t res = packet_parse_uint32(&packet);
	if (input == res) {
		printf("Bingle, uint32 %#X is OK!\n", input);
	}
	free(packet.binary);
	packet.binary = NULL;
}

static void
string_write_read(char *input, uint32_t remaining_length)
{
	struct mqtt_packet packet;
	memset(&packet, 0, sizeof(struct mqtt_packet));
	packet.remaining_length = remaining_length;
	packet.binary = (char *) malloc(sizeof(char) * remaining_length);
	packet_write_string(&packet, input, remaining_length);

	packet.pos = 0;
	char str[remaining_length];
	packet_parse_string(&packet, str, remaining_length);
	printf("\npacket_parse_string output: %s\n", str);

	free(packet.binary);
	packet.binary = NULL;
}

static void
var_write_read(uint32_t input, uint32_t remaining_length)
{
	struct mqtt_packet packet;
	memset(&packet, 0, sizeof(packet));
	packet.remaining_length = remaining_length;
	packet.binary = (char *) malloc(sizeof(char) * remaining_length);
	packet_write_var(&packet, input);
	packet.pos = 0;

	uint32_t res = packet_parse_var(&packet);
	if (res == input) {
		printf("Bingle, var length %#X is OK!\n", input);
	}

	free(packet.binary);
	packet.binary = NULL;
}

static void
TEST_uint8_write_read(void)
{
	/* Empty packet */
	// byte_write_read(NULL, 0);

	uint8_t binary = 0;

	/* 0 value */
	// memset(binary, 0, sizeof(binary));
	binary = 0x00;
	uint8_write_read(binary, 1);

	/* Middle */
	//  memset(binary, 0, sizeof(binary));
	binary = 0x1F;
	uint8_write_read(binary, 1);

	/* 255 value */
	// memset(binary, 0, sizeof(binary));
	binary = 0xFF;
	uint8_write_read(binary, 1);
}

static void
TEST_uint16_write_read(void)
{

	/* Empty packet */
	// uint16_write_read(NULL, 0);
	uint16_t binary = 0;

	/* 0 value */
	// memset(binary, 0, sizeof(binary));
	binary = 0x0000;
	uint16_write_read(binary, 2);

	/* Endian check */
	// memset(binary, 0, sizeof(binary));
	binary = 0x38F3;
	uint16_write_read(binary, 2);

	/* 65,535 value */
	// memset(binary, 0, sizeof(binary));
	binary = 0xFFFF;
	uint16_write_read(binary, 2);
}

static void
TEST_uint32_write_read(void)
{
	/* Empty packet */
	// uint32_write_read(NULL, 0);
	uint32_t binary = 0;

	/* 0 value */
	binary = 0x00000000;
	uint32_write_read(binary, 4);

	/* Endian check */
	binary = 0x12345678;
	uint32_write_read(binary, 4);

	/* Biggest value */
	binary = 0xFFFFFFFF;
	uint32_write_read(binary, 4);
}

static void
TEST_string_write_read(void)
{
	// char *binary = "This is a string!";
	char binary[18];
	memset(binary, 0, sizeof(binary));
	binary[0]  = 'T';
	binary[1]  = 'h';
	binary[2]  = 'i';
	binary[3]  = 's';
	binary[4]  = ' ';
	binary[5]  = 'i';
	binary[6]  = 's';
	binary[7]  = ' ';
	binary[8]  = 'a';
	binary[9]  = ' ';
	binary[10] = 's';
	binary[11] = 't';
	binary[12] = 'r';
	binary[13] = 'i';
	binary[14] = 'n';
	binary[15] = 'g';
	binary[16] = '!';
	binary[17] = '\0';
	string_write_read(binary, 18);
}

static void
TEST_var_write_read(void)
{
	uint32_t binary = 0;

	/* 0 value */
	binary = 0x00000000;
	var_write_read(binary, 4);

	/* Endian check */
	binary = 0x12;
	var_write_read(binary, 4);

	/* Endian check */
	binary = 0x1234;
	var_write_read(binary, 4);
	/* Endian check */
	binary = 0x128456;
	var_write_read(binary, 4);
	/* Endian check */
	binary = 0x12348678;
	var_write_read(binary, 4);

	/* Biggest value */
	binary = 0x7FFFFFFF;
	var_write_read(binary, 4);
}

void
test(void)
{
	TEST_uint8_write_read();
	TEST_uint16_write_read();
	TEST_uint32_write_read();
	TEST_string_write_read();
	TEST_var_write_read();
}
