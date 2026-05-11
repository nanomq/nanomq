// SPDX-License-Identifier: MIT

#include "nano_skill.h"

#include <stdlib.h>
#include <string.h>

struct nano_skill_window {
	uint32_t window_ms;
	uint64_t first_ts;
	uint64_t last_ts;
	uint32_t count;
	double   sum;
	double   max;
	double   min;
	bool     has_samples;
	bool     ready;
};

nano_skill_window *
nano_skill_window_tumbling_ms(uint32_t window_ms)
{
	if (window_ms == 0) {
		return NULL;
	}
	nano_skill_window *w = (nano_skill_window *) malloc(sizeof(*w));
	if (w == NULL) {
		return NULL;
	}
	memset(w, 0, sizeof(*w));
	w->window_ms = window_ms;
	return w;
}

void
nano_skill_window_reset(nano_skill_window *w)
{
	if (w == NULL) {
		return;
	}
	w->first_ts    = 0;
	w->last_ts     = 0;
	w->count       = 0;
	w->sum         = 0.0;
	w->max         = 0.0;
	w->min         = 0.0;
	w->has_samples = false;
	w->ready       = false;
}

void
nano_skill_window_push(nano_skill_window *w, uint64_t ts_ms, double v)
{
	if (w == NULL) {
		return;
	}
	if (w->ready) {
		nano_skill_window_reset(w);
	}

	if (!w->has_samples) {
		w->first_ts    = ts_ms;
		w->last_ts     = ts_ms;
		w->count       = 1;
		w->sum         = v;
		w->max         = v;
		w->min         = v;
		w->has_samples = true;
	} else {
		w->last_ts = ts_ms;
		w->count++;
		w->sum += v;
		if (v > w->max) {
			w->max = v;
		}
		if (v < w->min) {
			w->min = v;
		}
	}

	if (ts_ms >= w->first_ts &&
	    (ts_ms - w->first_ts) >= (uint64_t) w->window_ms) {
		w->ready = true;
	}
}

bool
nano_skill_window_ready(nano_skill_window *w)
{
	return (w != NULL) && w->ready;
}

double
nano_skill_window_avg(nano_skill_window *w)
{
	if (w == NULL || w->count == 0) {
		return 0.0;
	}
	return w->sum / (double) w->count;
}

double
nano_skill_window_max(nano_skill_window *w)
{
	return (w != NULL && w->has_samples) ? w->max : 0.0;
}

double
nano_skill_window_min(nano_skill_window *w)
{
	return (w != NULL && w->has_samples) ? w->min : 0.0;
}

uint32_t
nano_skill_window_count(nano_skill_window *w)
{
	return (w != NULL) ? w->count : 0;
}

void
nano_skill_window_free(nano_skill_window *w)
{
	free(w);
}

