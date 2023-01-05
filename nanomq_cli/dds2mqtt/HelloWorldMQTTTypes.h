#ifndef _MQTT_DDS_HELLOWORLD_TYPES_H_
#define _MQTT_DDS_HELLOWORLD_TYPES_H_

#include "HelloWorld.h"

// It should not be changed
typedef struct fixed_mqtt_msg {
	char    *payload;
	uint32_t len;
} fixed_mqtt_msg;

void HelloWorld_to_MQTT(example_struct *m1, fixed_mqtt_msg *m2);

void MQTT_to_HelloWorld(fixed_mqtt_msg *m1, example_struct *m2);

#endif
