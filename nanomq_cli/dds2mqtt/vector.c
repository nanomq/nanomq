// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "vector.h"
#include <stdint.h>
#include <pthread.h>

struct _vec {
	size_t          cap; // capicity
	size_t          len; // number of elements
	size_t          low; // elements stored from here
	void          **vec;
	pthread_mutex_t mtx;
};

static int
resize(nftp_vec *v) // TODO
{
	return (0);
}

int
nftp_vec_alloc(nftp_vec **vp)
{
	nftp_vec *v;

	if ((v = malloc(sizeof(*v))) == NULL)
		return (NFTP_ERR_MEM);
	if ((v->vec = malloc(sizeof(void *) * NFTP_SIZE)) == NULL)
		return (NFTP_ERR_MEM);
	pthread_mutex_init(&v->mtx, NULL);

	v->len = 0;
	v->cap = NFTP_SIZE;
	v->low = v->cap/4;

	*vp = v;
	return (0);
}

int
nftp_vec_free(nftp_vec *v)
{
	if (!v) return (NFTP_ERR_VEC);
	if (v->vec) free(v->vec);
	pthread_mutex_destroy(&v->mtx);
	free(v);
	return (0);
}

int
nftp_vec_append(nftp_vec *v, void *entry)
{
	return nftp_vec_push(v, entry, NFTP_TAIL);
}

int
nftp_vec_insert(nftp_vec *v, void *entry, int pos)
{
	if (!v) return (NFTP_ERR_VEC);

	if (v->low + v->len + 1 > v->cap)
		return (NFTP_ERR_OVERFLOW); // Resize TODO

	if (pos > v->len)
		return nftp_vec_push(v, entry, NFTP_TAIL);

	pthread_mutex_lock(&v->mtx);
	for (int i = v->low + v->len; i > v->low + pos; --i)
		v->vec[i] = v->vec[i-1];
	v->vec[v->low + pos] = entry;

	v->len ++;
	pthread_mutex_unlock(&v->mtx);

	return (0);
}

int
nftp_vec_delete(nftp_vec *v, void **entryp, int pos)
{
	if (!v) return (NFTP_ERR_VEC);

	if (pos < 0 || pos > v->len-1)
		return (NFTP_ERR_OVERFLOW);

	pthread_mutex_lock(&v->mtx);
	*entryp = v->vec[v->low + pos];
	for (int i = v->low + pos + 1; i < v->low + v->len; ++i)
		v->vec[i-1] = v->vec[i];
	v->len --;
	pthread_mutex_unlock(&v->mtx);

	return (0);
}

int
nftp_vec_push(nftp_vec *v, void *entry, int flag)
{
	size_t pos = 0;

	if (!v) return (NFTP_ERR_VEC);

	pthread_mutex_lock(&v->mtx);
	if (NFTP_HEAD == flag) {
		if (v->low == 0) {
			pthread_mutex_unlock(&v->mtx);
			return (NFTP_ERR_OVERFLOW);
		}
		v->low --;
		pos = v->low;
	} else if (NFTP_TAIL == flag) {
		if (v->len >= v->cap) {
			pthread_mutex_unlock(&v->mtx);
			return (NFTP_ERR_OVERFLOW);
		}
		pos = (v->low + v->len) % v->cap;
	} else {
		pthread_mutex_unlock(&v->mtx);
		return (NFTP_ERR_FLAG);
	}
	v->len ++;
	v->vec[pos] = entry;
	pthread_mutex_unlock(&v->mtx);

	return (0);
}

int
nftp_vec_pop(nftp_vec *v, void **entryp, int flag)
{
	size_t pos = 0;

	if (!v) return (NFTP_ERR_VEC);

	if (v->len == 0) return (NFTP_ERR_EMPTY);

	pthread_mutex_lock(&v->mtx);
	if (NFTP_HEAD == flag) {
		pos = v->low;
		v->low = (v->low + 1) % v->cap;
	} else if (NFTP_TAIL == flag) {
		pos = v->low + v->len - 1;
	} else {
		pthread_mutex_unlock(&v->mtx);
		return (NFTP_ERR_FLAG);
	}
	*entryp = v->vec[pos];
	v->vec[pos] = NULL;

	v->len --;
	pthread_mutex_unlock(&v->mtx);

	return (0);
}

int
nftp_vec_get(nftp_vec *v, int idx, void **entryp)
{
	if (!v) return (NFTP_ERR_VEC);
	if (idx >= v->len) return (NFTP_ERR_OVERFLOW);
	if (idx < 0) return (NFTP_ERR_OVERFLOW);

	*entryp = v->vec[v->low + idx];

	return (0);
}

int
nftp_vec_getidx(nftp_vec *v, void *entry, int *idxp)
{
	if (!v) return (NFTP_ERR_VEC);
	for (int i = v->low; i < v->low + v->len; ++i)
		if (v->vec[i] == entry) {
			*idxp = i - v->low;
			return (0);
		}
	return (NFTP_ERR_EMPTY);
}

int
nftp_vec_cat(nftp_vec *dv, nftp_vec *sv)
{
	if (!dv) return (NFTP_ERR_VEC);
	if (!sv) return (0); // Do not change the destination vector

	if (dv->low + dv->len + sv->len > dv->cap)
		return (NFTP_ERR_OVERFLOW);

	pthread_mutex_lock(&dv->mtx);
	pthread_mutex_lock(&sv->mtx);

	size_t idx = dv->low + dv->len;
	for (uint32_t i = 0; i < sv->len; ++i)
		dv->vec[idx + i] = sv->vec[sv->low + i];

	dv->len += sv->len;

	pthread_mutex_unlock(&sv->mtx);
	pthread_mutex_unlock(&dv->mtx);

	return (0);
}

size_t
nftp_vec_cap(nftp_vec *v)
{
	return v->cap;
}

size_t
nftp_vec_len(nftp_vec *v)
{
	return v->len;
}

#endif
