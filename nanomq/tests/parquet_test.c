// #include "core/nng_impl.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/parquet.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "string.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nanomq_test.h"

// #include <nuts.h>

#define DO_IT_IF_NOT_NULL(func, arg1, arg2) \
	if (arg1) {                         \
		func(arg1, arg2);           \
	}

#define FREE_IF_NOT_NULL(free, size) DO_IT_IF_NOT_NULL(nng_free, free, size)

#define DATASIZE 10
#define NUM_KEYS 5
#define STRING_LENGTH 12
static uint64_t keys_test[NUM_KEYS][DATASIZE] = { 
	{ 10, 21, 32, 43, 54, 65, 76, 87, 98, 109 },
	{ 110, 121, 132, 143, 154, 165, 176, 187, 198, 1109 },
	{ 220, 222, 232, 243, 254, 265, 276, 287, 298, 2209 },
	{ 330, 333, 333, 343, 354, 365, 376, 387, 398, 3309 },
	{ 440, 444, 444, 444, 454, 465, 476, 487, 498, 4409 } 
};

static uint64_t find_keys_test[NUM_KEYS] = {
	10, 110, 220, 330, 440
};

static char *filenames[NUM_KEYS] = {
	"/tmp/parquet/ly-10~109.parquet",
	"/tmp/parquet/ly-110~1109.parquet",
	"/tmp/parquet/ly-220~2209.parquet",
	"/tmp/parquet/ly-330~3309.parquet",
	"/tmp/parquet/ly-440~4409.parquet"
};

typedef struct {
	nng_aio *aio;
} work;

uint64_t *
keys_allocate(uint64_t keys[], uint32_t size)
{
	uint32_t  i          = 0;
	uint64_t *keys_alloc = malloc(size * sizeof(uint64_t));
	while (i < size) {
		keys_alloc[i] = keys[i];
		i++;
	}
	return keys_alloc;
}

uint8_t **
data_array_allocate(uint32_t **dsize, uint32_t size)
{
	uint32_t  i           = 0;
	uint32_t *dsize_alloc = malloc(size * sizeof(uint32_t));
	while (i < size) {
		dsize_alloc[i] = STRING_LENGTH;
		i++;
	}

	char **darray = malloc(size * sizeof(char *));

	if (darray == NULL) {
		printf("Memory allocation failed. Exiting...\n");
		return NULL;
	}

	for (uint32_t i = 0; i < size; i++) {
		darray[i] = malloc((STRING_LENGTH + 1) * sizeof(char));

		if (darray[i] == NULL) {
			printf("Memory allocation failed for element %d. "
			       "Exiting...\n",
			    i);

			// Free previously allocated memory before exiting
			for (uint32_t j = 0; j < i; j++) {
				free(darray[j]);
			}
			free(darray);

			return NULL;
		}

		sprintf(darray[i], "hello world%d", i);
	}
	*dsize = dsize_alloc;

	return (uint8_t**) darray;
}

void works_free(work **works)
{
	for (size_t i = 0; i < cvector_size(works); i++) {
		nng_aio_free(works[i]->aio);
		nng_free(works[i], sizeof(work));
	}
	cvector_free(works);
}

void
aio_test_cb(void *arg)
{
	work	        *w           = (work *) arg;
	nng_aio             *aio         = w->aio;
    static int test_index = 0;
	parquet_file_ranges *file_ranges = nng_aio_get_output(aio, 1);
	char **data_array = nng_aio_get_prov_data(aio);
	uint32_t             *len         = (uint32_t *) nng_aio_get_msg(aio);

	for (uint32_t i = 0; i < *len; i++) {
		if (data_array[i]) nng_strfree(data_array[i]);
	}
	free(len);

    check(file_ranges->size == 1, "file_ranges size error");

	for (int i = 0; i < file_ranges->size; i++) {
		parquet_file_range *range = file_ranges->range[i];
		check_mem(range);
		check(range->start_idx == 0, "Start Index error");
		check(range->end_idx == 9, "End Index error");
		check(nng_strcasecmp(range->filename, filenames[test_index]) ==
		        0,
		    "Filename error: %s != %s", range->filename,
		    filenames[test_index]);
	}
    test_index++;
    return;
error:
    abort();
}


