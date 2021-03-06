#ifndef __dbg_h__
#define __dbg_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static inline char *nano_get_time()
{
	char *buffer;
	time_t now;

	now = time(NULL);
	buffer = ctime(&now);
	if (!buffer)
		return NULL;

	if (buffer[strlen(buffer) - 1] == '\n')
		buffer[strlen(buffer) - 1] = '\0';

	return buffer;
}

// debug
#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "[DEBUG] %s:%d: " M "\n",\
		__FILE__, __LINE__, ##__VA_ARGS__)
#endif

// log
#ifdef NOLOG
#define log(M, ...)
#define log_info(M, ...)

#ifdef NOWARNING
#define log_warn(M, ...)
#else
#define log_warn(M, ...) fprintf(stderr,\
		"[WARN] (%s:%s:%d) " M "\n", __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#else

#define log_info(M, ...) fprintf(stderr,\
		"[INFO] (%s:%s:%d) ===>> " M "\n", __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)
#define log_warn(M, ...) fprintf(stderr,\
		"[WARN] (%s:%s:%d) " M "\n", __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)
#define log(M, ...) fprintf(stderr, "[INFO] %s (%lu:%s:%d) " M "\n",\
		nano_get_time(), pthread_self(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define log_err(M, ...) fprintf(stderr,\
		"\n[ERROR] (%s:%s:%d) " M "\n\n", __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)

// Test
#ifdef NOLOG
#define CHECK(A) if(A){};
#define RUN_TESTS(name) int main(int argc, char *argv[]) {\
	fprintf(stderr, "----[RUN_TESTS(NOLOG)]----\n");\
	do{\
		name();\
	}while(0);\
	exit(0);\
}
#else
#define CHECK(A) if(!(A)) {fprintf(stderr,\
		"[CHECK] [FAIL] (%s:%d) \n", __FUNCTION__, __LINE__);}\
		else{fprintf(stderr,\
		"[CHECK] [SUCCESS] \n");}

#define RUN_TESTS(name) int main(int argc, char *argv[]) {\
	argc = 1; \
	fprintf(stderr, "----[RUN_TESTS]----\n");\
	do{\
		name();\
	}while(0);\
	exit(0);\
}
#endif
#endif

