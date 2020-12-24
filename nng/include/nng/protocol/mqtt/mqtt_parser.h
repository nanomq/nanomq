
#ifndef NNG_MQTT_H
#define NNG_MQTT_H

#include <stdlib.h>
#include <nng/nng.h>

//int hex_to_oct(char *str);
//
//uint32_t htoi(char *str);


//MQTT CONNECT
int32_t conn_handler(uint8_t *packet, conn_param *conn_param);
void destroy_conn_param(conn_param * cparam);
int fixed_header_adaptor(uint8_t *packet, nng_msg *dst);

//parser 
NNG_DECL uint8_t put_var_integer(uint8_t *dest, uint32_t value);

NNG_DECL uint32_t get_var_integer(const uint8_t *buf, uint32_t *pos);

NNG_DECL int32_t get_utf8_str(char **dest, const uint8_t *src, uint32_t *pos);
NNG_DECL uint8_t * copy_utf8_str(const uint8_t *src, uint32_t *pos, int *str_len);

NNG_DECL int utf8_check(const char *str, size_t length);

NNG_DECL uint16_t get_variable_binary(uint8_t **dest, const uint8_t *src);

NNG_DECL uint32_t DJBHash(char *str);
NNG_DECL uint64_t nano_hash(char *str);
#endif // NNG_MQTT_H
