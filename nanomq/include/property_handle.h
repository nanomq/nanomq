#ifndef MQTT_PROPERTY_HANDLE_H
#define MQTT_PROPERTY_HANDLE_H

#include <string.h>
#include <nng/nng.h>
#include "include/packet.h"

int type_of_variable_property(uint8_t id);
void property_list_init(struct mqtt_property * list);
int property_list_insert(struct mqtt_property * list, uint8_t id, uint8_t * bin);
int property_list_free(struct mqtt_property * list);
struct property * property_list_head(struct mqtt_property * list);
struct property * property_list_end(struct mqtt_property * list);
struct property * property_list_get_element(struct mqtt_property * list, int pos);
struct property * property_list_find_element(struct mqtt_property * list, uint8_t id);

#endif
