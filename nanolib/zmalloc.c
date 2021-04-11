//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__sun)
#define PREFIX_SIZE sizeof(long long)
#else
#define PREFIX_SIZE sizeof(size_t)
#endif

#define increment_used_memory(__n)                                      \
	do {                                                            \
		size_t _n = (__n);                                      \
		if (_n & (sizeof(long) - 1))                            \
			_n += sizeof(long) - (_n & (sizeof(long) - 1)); \
		used_memory += _n;                                      \
	} while (0)

#define decrement_used_memory(__n)                                      \
	do {                                                            \
		size_t _n = (__n);                                      \
		if (_n & (sizeof(long) - 1))                            \
			_n += sizeof(long) - (_n & (sizeof(long) - 1)); \
		used_memory -= _n;                                      \
	} while (0)

static size_t used_memory = 0;

static void
zmalloc_oom(size_t size)
{
	fprintf(stderr,
	    "zmalloc: Out of memory trying to allocate %zu bytes\n", size);
	fflush(stderr);
	abort();
}

void *
zmalloc(size_t size)
{
	void *ptr = malloc(size + PREFIX_SIZE);

	if (!ptr)
		zmalloc_oom(size);
#ifdef HAVE_MALLOC_SIZE
	increment_used_memory(redis_malloc_size(ptr));
	return ptr;
#else
	*((size_t *) ptr) = size;
	increment_used_memory(size + PREFIX_SIZE);
	return (char *) ptr + PREFIX_SIZE;
#endif
}

void *
zrealloc(void *ptr, size_t size)
{
#ifndef HAVE_MALLOC_SIZE
	void *realptr;
#endif
	size_t oldsize;
	void * newptr;

	if (ptr == NULL)
		return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE
	oldsize = redis_malloc_size(ptr);
	newptr  = realloc(ptr, size);
	if (!newptr)
		zmalloc_oom(size);

	decrement_used_memory(oldsize);
	increment_used_memory(redis_malloc_size(newptr));
	return newptr;
#else
	realptr = (char *) ptr - PREFIX_SIZE;
	oldsize = *((size_t *) realptr);
	newptr  = realloc(realptr, size + PREFIX_SIZE);
	if (!newptr)
		zmalloc_oom(size);

	*((size_t *) newptr) = size;
	decrement_used_memory(oldsize);
	increment_used_memory(size);
	return (char *) newptr + PREFIX_SIZE;
#endif
}

void
zfree(void *ptr)
{
#ifndef HAVE_MALLOC_SIZE
	void * realptr;
	size_t oldsize;
#endif

	if (ptr == NULL)
		return;
#ifdef HAVE_MALLOC_SIZE
	decrement_used_memory(redis_malloc_size(ptr));
	free(ptr);
#else
	realptr = (char *) ptr - PREFIX_SIZE;
	oldsize = *((size_t *) realptr);
	decrement_used_memory(oldsize + PREFIX_SIZE);
	free(realptr);
#endif
}

char *
zstrdup(const char *s)
{
	size_t l = strlen(s) + 1;
	char * p = zmalloc(l);

	memcpy(p, s, l);
	return p;
}

size_t
zmalloc_used_memory(void)
{
	size_t um;

	um = used_memory;

	return um;
}
