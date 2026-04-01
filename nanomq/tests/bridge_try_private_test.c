#include "include/bridge.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/supplemental/nanolib/conf.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int
main()
{
	conf_bridge_node node;
	conf_bridge_node_init(&node);

	node.clientid  = "test-bridge";
	node.username  = "user";
	node.password  = "pass";
	node.proto_ver = 4;
	node.keepalive = 60;

	uint8_t *body;

	// Test 1: try_private = true should set bridge bit (0x84)
	node.try_private = true;
	nng_msg *msg1 = create_connect_msg(&node);
	assert(msg1 != NULL);
	nng_mqtt_msg_encode(msg1);
	body = nng_msg_body(msg1);
	// Protocol version byte at offset 6: 2 (name len) + 4 ("MQTT")
	printf("try_private=true:  proto byte = 0x%02x (expected 0x84)\n", body[6]);
	assert(body[6] == 0x84);
	nng_msg_free(msg1);

	// Test 2: try_private = false should not set bridge bit (0x04)
	node.try_private = false;
	nng_msg *msg2 = create_connect_msg(&node);
	assert(msg2 != NULL);
	nng_mqtt_msg_encode(msg2);
	body = nng_msg_body(msg2);
	printf("try_private=false: proto byte = 0x%02x (expected 0x04)\n", body[6]);
	assert(body[6] == 0x04);
	nng_msg_free(msg2);

	// Test 3: try_private = true with proto_ver 5 should be 0x85
	node.proto_ver   = 5;
	node.try_private = true;
	nng_msg *msg3 = create_connect_msg(&node);
	assert(msg3 != NULL);
	nng_mqtt_msg_encode(msg3);
	body = nng_msg_body(msg3);
	printf("try_private=true v5: proto byte = 0x%02x (expected 0x85)\n", body[6]);
	assert(body[6] == 0x85);
	nng_msg_free(msg3);

	// Test 4: try_private = false with proto_ver 5 should be 0x05
	node.proto_ver   = 5;
	node.try_private = false;
	nng_msg *msg4 = create_connect_msg(&node);
	assert(msg4 != NULL);
	nng_mqtt_msg_encode(msg4);
	body = nng_msg_body(msg4);
	printf("try_private=false v5: proto byte = 0x%02x (expected 0x05)\n", body[6]);
	assert(body[6] == 0x05);
	nng_msg_free(msg4);



	printf("All try_private tests passed.\n");
	return 0;
}
