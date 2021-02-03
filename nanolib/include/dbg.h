#ifndef __dbg_h__
#define __dbg_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static inline char *nano_get_time()
{ char *buffer;
	time_t now;

	now = time(NULL);
	buffer = ctime(&now);
	if (!buffer)
		return NULL;

	if (buffer[strlen(buffer) - 1] == '\n')
		buffer[strlen(buffer) - 1] = '\0';

	return buffer;
}

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "[DEBUG] %s:%d: " M "\n",\
		__FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr,\
		"[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__,\
		clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) fprintf(stderr,\
		"[WARN] (%s:%d: errno: %s) " M "\n",\
		__FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define NOLOG
#ifdef NOLOG
#define log(M, ...)
#define log_info(M, ...)
#else
#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) =========>> " M "\n",\
		__FILE__, __LINE__, ##__VA_ARGS__)

#define log(M, ...) fprintf(stderr, "[INFO] %s (%lu:%s:%d) " M "\n",\
		nano_get_time(), pthread_self(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define check(A, M, ...) if(!(A)) {\
	log_err(M, ##__VA_ARGS__); errno=0; goto error; }

#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__);\
	errno=0; goto error; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if(!(A)) { debug(M, ##__VA_ARGS__);\
	errno=0; goto error; }

#endif
