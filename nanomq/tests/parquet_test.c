// #include "core/nng_impl.h"
#include "nanomq_test.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "nng/supplemental/nanolib/parquet.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <nuts.h>

#define DO_IT_IF_NOT_NULL(func, arg1, arg2) \
	if (arg1) {                         \
		func(arg1, arg2);           \
	}

#define FREE_IF_NOT_NULL(free, size) DO_IT_IF_NOT_NULL(nng_free, free, size)

#define DATASIZE 10
#define NUM_KEYS 5
#define STRING_LENGTH 12
static uint64_t keys_test[NUM_KEYS][DATASIZE] = { { 10, 21, 32, 43, 54, 65, 76,
	                                              87, 98, 109 },
	{ 110, 121, 132, 143, 154, 165, 176, 187, 198, 1109 },
	{ 220, 222, 232, 243, 254, 265, 276, 287, 298, 2209 },
	{ 330, 333, 333, 343, 354, 365, 376, 387, 398, 3309 },
	{ 440, 444, 444, 444, 454, 465, 476, 487, 498, 4409 } };

static uint64_t find_keys_test[NUM_KEYS] = { 10, 110, 220, 330, 440 };

static char *filenames[NUM_KEYS] = { "/tmp/parquet/ly-10~109.parquet",
	"/tmp/parquet/ly-110~1109.parquet", "/tmp/parquet/ly-220~2209.parquet",
	"/tmp/parquet/ly-330~3309.parquet",
	"/tmp/parquet/ly-440~4409.parquet" };

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

	return (uint8_t **) darray;
}

void
works_free(work **works)
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
	static int           test_index  = 0;
	parquet_file_ranges *file_ranges = nng_aio_get_output(aio, 1);
	char	       **data_array  = nng_aio_get_prov_data(aio);
	uint32_t            *len         = (uint32_t *) nng_aio_get_msg(aio);

	for (uint32_t i = 0; i < *len; i++) {
		if (data_array[i])
			nng_strfree(data_array[i]);
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

void
aio_test_write_tmp_cb(void *arg)
{
	work	        *w           = (work *) arg;
	nng_aio             *aio         = w->aio;
	static int           test_index  = 0;
	parquet_file_ranges *file_ranges = nng_aio_get_output(aio, 1);
	char	       **data_array  = nng_aio_get_prov_data(aio);
	uint32_t            *len         = (uint32_t *) nng_aio_get_msg(aio);

	for (uint32_t i = 0; i < *len; i++) {
		if (data_array[i])
			nng_strfree(data_array[i]);
	}
	free(len);

	check(file_ranges->size == 1, "file_ranges size error");

	for (int i = 0; i < file_ranges->size; i++) {
		parquet_file_range *range = file_ranges->range[i];
		check_mem(range);
		check(range->start_idx == 0, "Start Index error");
		check(range->end_idx == 9, "End Index error");
		log_test("Filename: %s", range->filename);
	}
	test_index++;
	return;
error:
	abort();
}

work *
parquet_write_batch_async_test1(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[0], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_async(elem);
	return w;
}

work *
parquet_write_batch_async_test2(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[1], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_async(elem);
	return w;
}

work *
parquet_write_batch_async_test3(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[2], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_async(elem);
	return w;
}

work *
parquet_write_batch_async_test4(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[3], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_async(elem);

	return w;
}

work *
parquet_write_batch_async_test5(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[4], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_async(elem);

	return w;
}

work *
parquet_write_batch_tmp_async_test1(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[0], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_write_tmp_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_tmp_async(elem);

	return w;
}

work *
parquet_write_batch_tmp_async_test2(void)
{
	uint32_t *dsize;
	uint64_t *keys   = keys_allocate(keys_test[1], DATASIZE);
	uint8_t **darray = data_array_allocate(&dsize, DATASIZE);

	work *w  = ALLOC_STRUCT(w);
	int   rv = 0;
	if ((rv = nng_aio_alloc(&w->aio, aio_test_write_tmp_cb, w)) != 0) {
		printf("nng_aio_alloc failed\n");
	}

	parquet_object *elem = parquet_object_alloc(
	    keys, (uint8_t **) darray, dsize, DATASIZE, w->aio, darray);

	parquet_write_batch_tmp_async(elem);

	return w;
}

void
clear_folder(const char *folderPath)
{
	DIR *dir = opendir(folderPath);
	if (dir == NULL) {
		fprintf(stderr, "Failed to open directory: %s\n", folderPath);
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		char filePath[512];
		snprintf(filePath, sizeof(filePath), "%s/%s", folderPath,
		    entry->d_name);

		if (remove(filePath) != 0) {
			fprintf(stderr,
			    "Failed to remove file/directory: %s\n", filePath);
		}
	}

	closedir(dir);
}

conf_parquet *
conf_parquet_init()
{

	conf_parquet *conf      = ALLOC_STRUCT(conf);
	conf->enable            = true;
	conf->dir               = strdup("/tmp/parquet");
	conf->file_name_prefix  = strdup("ly");
	conf->comp_type         = UNCOMPRESSED;
	conf->file_count        = 5;
	conf->file_index        = 0;
	conf->file_size         = 4000;
	conf->encryption.enable = true;
	conf->encryption.key    = "0123456789012345";
	conf->encryption.key_id = "kf";
	conf->encryption.type   = AES_GCM_V1;
	clear_folder(conf->dir);

	return conf;
}

void
conf_parquet_free(conf_parquet *conf)
{
	if (conf) {
		nng_strfree(conf->dir);
		nng_strfree(conf->file_name_prefix);
		nng_free(conf, sizeof(conf_parquet));
	}

	return;
}

void
parquet_write_batch_async_test(void)
{
	work **works = NULL;
	cvector_push_back(works, parquet_write_batch_async_test1());
	cvector_push_back(works, parquet_write_batch_async_test2());
	cvector_push_back(works, parquet_write_batch_async_test3());
	cvector_push_back(works, parquet_write_batch_async_test4());
	cvector_push_back(works, parquet_write_batch_async_test5());

	nng_msleep(100);
	works_free(works);
}

void
parquet_write_batch_async_tmp_test(void)
{
	work **works = NULL;
	cvector_push_back(works, parquet_write_batch_tmp_async_test1());
	cvector_push_back(works, parquet_write_batch_tmp_async_test2());

	nng_msleep(100);
	works_free(works);
}

void
parquet_find_span_test()
{

	char *value = (char *) parquet_find(4000);
	check_mem(value);
	check_str(value, filenames[4]);
	nng_strfree(value);

	// Test normal case
	uint32_t size  = 0;
	char   **array = (char **) parquet_find_span(0, 4000, &size);
	check_mem(array);
	for (uint32_t i = 0; i < size; i++) {
		if (array[i]) {
			check_mem(array[i]);
			check_str(array[i], filenames[i]);
			nng_strfree(array[i]);
		}
	}
	check(size == 5, "find span size error");
	nng_free(array, size);

	// Test illegal case
	array = (char **) parquet_find_span(4000, 100, &size);
	check(array == NULL, "find span error");
	check(size == 0, "find span size error");

	array = (char **) parquet_find_span(5000, 8000, &size);
	check(size == 0, "find span size error");
	for (uint32_t i = 0; i < size; i++) {
		if (array[i]) {
			puts(array[i]);
			check_mem(array[i]);
			check_str(array[i], filenames[i]);
			nng_strfree(array[i]);
		}
	}

	nng_free(array, size);

	return;

error:
	abort();
}

void
parquet_find_data_packet_test()
{
	parquet_data_packet *pack = parquet_find_data_packet(
	    NULL, "/tmp/parquet/ly-110~1109.parquet", 1109);
	check_mem(pack);
	check(pack->size == strlen("hello world9"), "size error");
	check_nstr(pack->data, "hello world9", pack->size);

	parquet_data_packet **packs = parquet_find_data_packets(
	    NULL, filenames, find_keys_test, NUM_KEYS);
	check_mem(packs);
	for (int i = 0; i < NUM_KEYS; i++) {
		if (packs[i]) {
			check(pack->size == strlen("hello world0"),
			    "size error");
			check_nstr(
			    packs[i]->data, "hello world0", packs[i]->size);
			FREE_STRUCT(packs[i]->data);
			FREE_STRUCT(packs[i]);
		}
	}
	free(packs);

	return;

error:
	abort();
}

int
main(int argc, char **argv)
{

	conf_parquet *conf = conf_parquet_init();

	parquet_write_launcher(conf);
	puts("parquet write batch async passed!");
	parquet_write_batch_async_test();
	puts("parquet write batch tmp async passed!");
	parquet_write_batch_async_tmp_test();
	puts("parquet_find_span_test passed!");
	parquet_find_span_test();
	puts("parquet_find_data_packet_test passed!");
	parquet_find_data_packet_test();

	return 0;
}
