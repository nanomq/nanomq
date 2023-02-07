// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include <stdio.h>
#include <string.h>

#include "dds_type.h"
#include "dds_mqtt_type_conversion.h"
#include "supplemental/nanolib/cJSON.h"

void
dds_to_mqtt_type_convert(DDS_TYPE_NAME *m1, fixed_mqtt_msg *m2)
{
	cJSON *obj     = NULL;
	cJSON *sub_obj = NULL;
	char  *str;

	/* Assemble cJSON* obj with *m1. */
	obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(obj, "int8_test", m1->int8_test);
	cJSON_AddNumberToObject(obj, "uint8_test", m1->uint8_test);
	cJSON_AddNumberToObject(obj, "int16_test", m1->int16_test);
	cJSON_AddNumberToObject(obj, "uint16_test", m1->uint16_test);
	cJSON_AddNumberToObject(obj, "int32_test", m1->int32_test);
	cJSON_AddNumberToObject(obj, "uint32_test", m1->uint32_test);
	cJSON_AddNumberToObject(obj, "int64_test", m1->int64_test);
	cJSON_AddNumberToObject(obj, "uint64_test", m1->uint64_test);
	cJSON_AddStringToObject(obj, "message", m1->message);
	cJSON_AddNumberToObject(obj, "example_enum", m1->example_enum);
	sub_obj = cJSON_CreateObject();
	cJSON_AddStringToObject(sub_obj, "message", m1->example_stru.message);
	cJSON_AddItemToObject(obj, "example_stru", sub_obj);

	/* Convert cJSON* to char* to fill m2->payload. */
	str         = cJSON_Print(obj);
	m2->payload = str;
	m2->len     = strlen(str);
	cJSON_Delete(obj);
}

void
mqtt_to_dds_type_convert(fixed_mqtt_msg *m1, DDS_TYPE_NAME *m2)
{
	cJSON              *cjson_obj  = NULL;
	cJSON              *cjson_tmp  = NULL;
	cJSON              *cjson_tmp2 = NULL;
	struct test_struct *es         = &m2->example_stru;
	char               *str        = m1->payload;

	/* Get cJSON handle. */
	cjson_obj = cJSON_Parse(str);
	if (cjson_obj == NULL) {
		printf("Parse fail!\n");
		return;
	}
	/* Fill the struct DDS_TYPE_NAME *m2. */
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "int8_test");
	m2->int8_test   = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "uint8_test");
	m2->uint8_test  = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "int16_test");
	m2->int16_test  = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "uint16_test");
	m2->uint16_test = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "int32_test");
	m2->int32_test  = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "uint32_test");
	m2->uint32_test = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "int64_test");
	m2->int64_test  = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "uint64_test");
	m2->uint64_test = cjson_tmp->valueint;
	cjson_tmp       = cJSON_GetObjectItem(cjson_obj, "message");
	strcpy(m2->message, cjson_tmp->valuestring);
	cjson_tmp        = cJSON_GetObjectItem(cjson_obj, "example_enum");
	m2->example_enum = cjson_tmp->valueint;
	cjson_tmp        = cJSON_GetObjectItem(cjson_obj, "example_stru");
	cjson_tmp2       = cJSON_GetObjectItem(cjson_tmp, "message");
	strcpy(es->message, cjson_tmp2->valuestring);
	m2->example_stru = *es;
	cJSON_Delete(cjson_obj);
}

#endif
