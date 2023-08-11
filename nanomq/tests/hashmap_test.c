#include "include/hashmap.h"
#include <assert.h>

int main()
{
	unsigned init_size = 2;
	hashmap_s *hashmap = NULL;
	char      *key1 = "key1";
	char      *key2 = "key2";
	char      *key3 = "key3";
	uint32_t   value1 = 1;
	uint32_t   value2 = 2;
	uint32_t   value3 = 3;
    
	hashmap = (hashmap_s *) malloc(sizeof(hashmap_s));

	assert(nano_hashmap_create(init_size, hashmap) == 0);

	assert(nano_hashmap_put(hashmap, key1, strlen(key1), value1) == 0);
	assert(nano_hashmap_put(hashmap, key2, strlen(key2), value2) == 0);
	assert(nano_hashmap_put(hashmap, key3, strlen(key3), value3) == 0);

	assert(nano_hashmap_get(hashmap, key1, strlen(key1)) == value1);
	assert(nano_hashmap_get(hashmap, key2, strlen(key2)) == value2);
	assert(nano_hashmap_get(hashmap, key3, strlen(key3)) == value3);

	assert(nano_hashmap_remove(hashmap, key1, strlen(key1)) == 0);
	assert(nano_hashmap_get(hashmap, key1, strlen(key1)) == HASHMAP_NULL);

	nano_hashmap_destroy(hashmap);

	free(hashmap);

	return 0;
}