#ifndef __IDL_CONVERT_H__
#define __IDL_CONVERT_H__

#include "nng/supplemental/nanolib/cJSON.h"
#include "dds_type.h"

extern cJSON *dds_to_mqtt_test_enum_convert(test_enum *num);
extern cJSON *dds_to_mqtt_test_struct_convert(test_struct *st);
extern cJSON *dds_to_mqtt_example_struct_convert(example_struct *st);
extern test_enum mqtt_to_dds_test_enum_convert(cJSON *obj);
extern test_struct *mqtt_to_dds_test_struct_convert(cJSON *obj);
extern example_struct *mqtt_to_dds_example_struct_convert(cJSON *obj);

#endif