#ifndef NANOMQ_NANOMQ_H
#define NANOMQ_NANOMQ_H

#include <stddef.h>
#include <string.h>

#include "nng/supplemental/nanolib/log.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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

#define NANO_UNUSED(x) (x) __attribute__((unused))

#define NANO_NNG_FATAL(s, rv)				\
	do {									\
		log_fatal(s);						\
		nng_fatal((s), (rv));				\
	} while(0)

extern int    get_cache_argc();
extern char **get_cache_argv();

// $SYS/... topics/filters bypass mount_point handling entirely (a wildcard
// subscription never matches a $-prefixed topic per MQTT-3.1.1 4.7.2, so the
// mounted tree would otherwise become unreachable via '#').
static inline bool
nmq_is_sys_topic(const char *topic, size_t len)
{
	static const char prefix[] = "$SYS";
	size_t            prefix_len = sizeof(prefix) - 1;

	if (topic == NULL || len < prefix_len ||
	    strncmp(topic, prefix, prefix_len) != 0) {
		return false;
	}
	// must be exactly "$SYS" or "$SYS/...", not e.g. "$SYStenant/..."
	return len == prefix_len || topic[prefix_len] == '/';
}

// Prefix a plain publish topic (or a non-shared subscribe/unsubscribe
// filter) with the listener's mount_point. Returns a newly nng_alloc'd
// string the caller must free with nng_free(ptr, strlen(ptr) + 1), or NULL
// if no rewrite is needed (mount_point unset/empty, or a $SYS topic). On
// allocation failure also returns NULL, but sets *oom to true (when oom is
// non-NULL) so the caller can reject the operation instead of silently
// falling back to the un-rewritten topic.
static inline char *
nmq_mount_point_prepend(
    const char *mount_point, const char *topic, size_t len, bool *oom)
{
	size_t mp_len, out_len;
	char  *out;

	if (mount_point == NULL || mount_point[0] == '\0' ||
	    nmq_is_sys_topic(topic, len)) {
		return NULL;
	}
	mp_len  = strlen(mount_point);
	out_len = mp_len + 1 + len;
	if ((out = nng_alloc(out_len + 1)) == NULL) {
		if (oom != NULL) {
			*oom = true;
		}
		return NULL;
	}
	memcpy(out, mount_point, mp_len);
	out[mp_len] = '/';
	memcpy(out + mp_len + 1, topic, len);
	out[out_len] = '\0';
	return out;
}

// Like nmq_mount_point_prepend, but a shared-subscription filter
// ($share/<group>/<filter>) is rewritten to
// $share/<group>/<mount_point>/<filter>: the group name is left untouched,
// so the shared-subscription pool stays distinct per mount_point. See
// nmq_mount_point_prepend for the *oom out-parameter contract.
static inline char *
nmq_mount_point_rewrite_filter(
    const char *mount_point, const char *filter, bool *oom)
{
	static const char share_prefix[] = "$share/";
	size_t            filter_len, head_len, mp_len, tail_len, out_len;
	const char       *group_end;
	char             *out;

	if (mount_point == NULL || mount_point[0] == '\0' || filter == NULL) {
		return NULL;
	}
	filter_len = strlen(filter);
	if (nmq_is_sys_topic(filter, filter_len)) {
		return NULL;
	}
	if (strncmp(filter, share_prefix, sizeof(share_prefix) - 1) == 0 &&
	    (group_end = strchr(filter + sizeof(share_prefix) - 1, '/')) !=
	        NULL) {
		head_len = (size_t) (group_end + 1 - filter);
		mp_len   = strlen(mount_point);
		tail_len = filter_len - head_len;
		out_len  = head_len + mp_len + 1 + tail_len;
		if ((out = nng_alloc(out_len + 1)) == NULL) {
			if (oom != NULL) {
				*oom = true;
			}
			return NULL;
		}
		memcpy(out, filter, head_len);
		memcpy(out + head_len, mount_point, mp_len);
		out[head_len + mp_len] = '/';
		memcpy(out + head_len + mp_len + 1, group_end + 1, tail_len);
		out[out_len] = '\0';
		return out;
	}
	return nmq_mount_point_prepend(mount_point, filter, filter_len, oom);
}

#endif
