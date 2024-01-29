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