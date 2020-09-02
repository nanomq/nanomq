
#define _GNU_SOURCE
#define DEBUG_FILE_PATH "/tmp/debug_nanomq.log"

// later expose on makefile
/**/
#if defined(NOLOG)
#undef DEBUG_CONSOLE
#undef DEBUG_FILE
#undef DEBUG_SYSLOG
#else 
#define DEBUG_CONSOLE
#define DEBUG_FILE
#define DEBUG_SYSLOG
#endif

#undef LIBNANO_DEBUG
#if defined(DEBUG_CONSOLE) || defined(DEBUG_FILE) || defined(DEBUG_SYSLOG)
#define LIBNANO_DEBUG

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <syslog.h>

static inline char *nanomq_time_str()
{
	char *buff;
	time_t now;

	now = time(NULL);
	buff = ctime(&now);
	if (!buff)
		return NULL;

	if (buff[strlen(buff) - 1] == '\n')
		buff[strlen(buff) - 1] = '\0';

	return buff;
}

#endif

#if defined(DEBUG_CONSOLE)
#define debug_console(fmt, arg...) do {\
	char *_t = nanomq_time_str();\
	fprintf(stderr, "%s %s: " fmt "\n", _t, __FUNCTION__, ## arg);\
} while (0)
#else
#define debug_console(fmt, arg...) do { } while (0)
#endif

#if defined(DEBUG_FILE)
#define debug_file(fmt, arg...) do {\
	char *_t = nanomq_time_str();\
	FILE *file = fopen(DEBUG_FILE_PATH, "a");\
	fprintf(file, "%s [%i] %s: " fmt "\n", _t, getpid(), __FUNCTION__, ## arg);\
	fclose(file);\
} while(0)
#else
#define debug_file(fmt, arg...) do { } while (0)
#endif

#if defined(DEBUG_SYSLOG)
#define debug_syslog(fmt, arg...) do {\
	openlog("nanomq", LOG_PID, LOG_DAEMON | LOG_EMERG);\
	syslog(0, "%s: " fmt, __FUNCTION__, ## arg);\
	closelog();\
} while (0)
#else
#define debug_syslog(fmt, arg...) do { } while (0)
#endif


#if defined(LIBNANO_DEBUG)
#define debug_msg(fmt, arg...) do {			\
	debug_console(fmt, ## arg);			\
	debug_file(fmt, ## arg);			\
	debug_syslog(fmt, ## arg);			\
} while (0)
#else
#define debug_msg(fmt, arg...) do { } while (0)
#endif

#define NNI_PUT16(ptr, u)                                    \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint16_t)(u)) >> 8u); \
		(ptr)[1] = (uint8_t)((uint16_t)(u));         \
	} while (0)

#define NNI_PUT32(ptr, u)                                     \
	do {                                                  \
		(ptr)[0] = (uint8_t)(((uint32_t)(u)) >> 24u); \
		(ptr)[1] = (uint8_t)(((uint32_t)(u)) >> 16u); \
		(ptr)[2] = (uint8_t)(((uint32_t)(u)) >> 8u);  \
		(ptr)[3] = (uint8_t)((uint32_t)(u));          \
	} while (0)

#define NNI_PUT64(ptr, u)                                     \
	do {                                                  \
		(ptr)[0] = (uint8_t)(((uint64_t)(u)) >> 56u); \
		(ptr)[1] = (uint8_t)(((uint64_t)(u)) >> 48u); \
		(ptr)[2] = (uint8_t)(((uint64_t)(u)) >> 40u); \
		(ptr)[3] = (uint8_t)(((uint64_t)(u)) >> 32u); \
		(ptr)[4] = (uint8_t)(((uint64_t)(u)) >> 24u); \
		(ptr)[5] = (uint8_t)(((uint64_t)(u)) >> 16u); \
		(ptr)[6] = (uint8_t)(((uint64_t)(u)) >> 8u);  \
		(ptr)[7] = (uint8_t)((uint64_t)(u));          \
	} while (0)

#define NNI_GET16(ptr, v)                             \
	v = (((uint16_t)((uint8_t)(ptr)[0])) << 8u) + \
	    (((uint16_t)(uint8_t)(ptr)[1]))

#define NNI_GET32(ptr, v)                              \
	v = (((uint32_t)((uint8_t)(ptr)[0])) << 24u) + \
	    (((uint32_t)((uint8_t)(ptr)[1])) << 16u) + \
	    (((uint32_t)((uint8_t)(ptr)[2])) << 8u) +  \
	    (((uint32_t)(uint8_t)(ptr)[3]))

#define NNI_GET64(ptr, v)                              \
	v = (((uint64_t)((uint8_t)(ptr)[0])) << 56u) + \
	    (((uint64_t)((uint8_t)(ptr)[1])) << 48u) + \
	    (((uint64_t)((uint8_t)(ptr)[2])) << 40u) + \
	    (((uint64_t)((uint8_t)(ptr)[3])) << 32u) + \
	    (((uint64_t)((uint8_t)(ptr)[4])) << 24u) + \
	    (((uint64_t)((uint8_t)(ptr)[5])) << 16u) + \
	    (((uint64_t)((uint8_t)(ptr)[6])) << 8u) +  \
	    (((uint64_t)(uint8_t)(ptr)[7]))



#define NANO_UNUSED(x) (x)__attribute__((unused))
