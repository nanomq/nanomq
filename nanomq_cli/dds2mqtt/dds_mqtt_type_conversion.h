#ifndef _MQTT_DDS_HELLOWORLD_TYPES_H_
#define _MQTT_DDS_HELLOWORLD_TYPES_H_

#if defined(SUPP_DDS_PROXY)

#include "dds_type.h"

// It should not be changed
typedef struct fixed_mqtt_msg {
	char    *payload;
	uint32_t len;
} fixed_mqtt_msg;

void dds_to_mqtt_type_convert(DDS_TYPE_NAME *m1, fixed_mqtt_msg *m2);

void mqtt_to_dds_type_convert(fixed_mqtt_msg *m1, DDS_TYPE_NAME *m2);

#endif

#endif
