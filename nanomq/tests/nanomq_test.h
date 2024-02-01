#ifndef __NANOMQ_TEST_H__
#define __NANOMQ_TEST_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>

// Structure allocation conveniences.
#define ALLOC_STRUCT(s) nng_zalloc(sizeof(*s))
#define FREE_STRUCT(s) nng_free((s), sizeof(*s))
#define ALLOC_STRUCTS(s, n) nng_zalloc(sizeof(*s) * n)
#define FREE_STRUCTS(s, n) nng_free(s, sizeof(*s) * n)

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr,\
        "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__,\
        clean_errno(), ##__VA_ARGS__)

#define log_test(M, ...) fprintf(stderr,\
        "[INFO] (%s:%d) " M "\n",\
        __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if(!(A)) {\
    log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__);\
    errno=0; goto error; }

#define check_mem(A) check((A), "Memory error.")

#define check_str(s1, s2) check((0 == strcmp(s1, s2)), "%s != %s", s1, s2)
#define check_nstr(s1, s2, n) check((0 == strncmp(s1, s2, n)), "%s != %s", s1, s2)

#define check_debug(A, M, ...) if(!(A)) { debug(M, ##__VA_ARGS__);\
    errno=0; goto error; }


#endif // __NANOMQ_TEST_H__