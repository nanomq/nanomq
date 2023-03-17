#include "idl_convert.h"
#include "stdio.h"
#include <stdlib.h>
#include <string.h>

cJSON *dds_to_mqtt_test_enum_convert(test_enum *num)
{

	return cJSON_CreateNumber(*num);

}

cJSON *dds_to_mqtt_test_struct_convert(test_struct *st)
{

 	cJSON *obj = NULL;
 	/* Assemble cJSON* obj with *st. */
 	obj = cJSON_CreateObject();

	// ARRAY_NUMBER_uint8_256
	cJSON *message = cJSON_CreateDoubleArray((const double *)st->message, 256);
	
	cJSON_AddItemToObject(obj, "message", message);


	return obj;
}



cJSON *dds_to_mqtt_example_struct_convert(example_struct *st)
{

 	cJSON *obj = NULL;
 	/* Assemble cJSON* obj with *st. */
 	obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(obj, "int8_test", st->int8_test);
	cJSON_AddNumberToObject(obj, "uint8_test", st->uint8_test);
	cJSON_AddNumberToObject(obj, "int16_test", st->int16_test);
	cJSON_AddNumberToObject(obj, "uint16_test", st->uint16_test);
	cJSON_AddNumberToObject(obj, "int32_test", st->int32_test);
	cJSON_AddNumberToObject(obj, "uint32_test", st->uint32_test);
	cJSON_AddNumberToObject(obj, "int64_test", st->int64_test);
	cJSON_AddNumberToObject(obj, "uint64_test", st->uint64_test);


	st->message
	// ARRAY_NUMBER_uint8_256
	cJSON *message = cJSON_CreateDoubleArray((const double *)st->message, 256);
	cJSON_AddItemToObject(obj, "message", message);


	cJSON_AddItemToObject(obj, "example_enum", dds_to_mqtt_test_enum_convert(&st->example_enum));

	cJSON_AddItemToObject(obj, "example_stru", dds_to_mqtt_test_struct_convert(&st->example_stru));

	return obj;
}



test_enum mqtt_to_dds_test_enum_convert(cJSON *obj)
{

	return cJSON_GetNumberValue(obj);

}


test_struct *mqtt_to_dds_test_struct_convert(cJSON *obj)
{
	test_struct *st = (test_struct*) calloc(1, sizeof(test_struct));
	cJSON *item = NULL;
	item = cJSON_GetObjectItem(obj, "message");

	// ARRAY_NUMBER_uint8_256
	switch (item->type)
	{
	case cJSON_String:;
		int cap = sizeof(st->message) / sizeof(uint8_t);
		int len = strlen(item->valuestring);
		memcpy(st->message, item->valuestring, len < cap ? len : cap);
		printf("value: %s %s\n", st->message, item->valuestring);
		break;
	case cJSON_Array:;
		int i0 = 0;
		cJSON *message0 = NULL;
		cJSON_ArrayForEach(item, message0) {
			st->message[i0] = (uint8_t) message0->valuedouble;
			printf("%d %d", st->message[i0], (uint8_t) message0->valuedouble);
			i0++;
		}
		break;
	
	default:
		break;
	}



	return st;
}



example_struct *mqtt_to_dds_example_struct_convert(cJSON *obj)
{
	example_struct *st = (example_struct*) malloc(sizeof(example_struct));
	cJSON *item = NULL;
	item = cJSON_GetObjectItem(obj, "int8_test");
	st->int8_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "uint8_test");
	st->uint8_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "int16_test");
	st->int16_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "uint16_test");
	st->uint16_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "int32_test");
	st->int32_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "uint32_test");
	st->uint32_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "int64_test");
	st->int64_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "uint64_test");
	st->uint64_test = item->valuedouble;

	item = cJSON_GetObjectItem(obj, "message");

	// ARRAY_NUMBER_uint8_256
	switch (item->type)
	{
	case cJSON_String:;
		int cap = sizeof(st->message) / sizeof(uint8_t);
		int len = strlen(item->valuestring);
		memcpy(st->message, item->valuestring, len < cap ? len : cap);
		printf("value: %s %s\n", st->message, item->valuestring);
		break;
	case cJSON_Array:;
		int i0 = 0;
		cJSON *message0 = NULL;
		cJSON_ArrayForEach(item, message0) {
			st->message[i0] = (uint8_t) message0->valuedouble;
			printf("%d %d", st->message[i0], (uint8_t) message0->valuedouble);
			i0++;
		}
		break;
	
	default:
		break;
	}


	item = cJSON_GetObjectItem(obj, "example_enum");

	st->example_enum = mqtt_to_dds_test_enum_convert(item);

	item = cJSON_GetObjectItem(obj, "example_stru");

	st->example_stru = *mqtt_to_dds_test_struct_convert(item);


	return st;
}


