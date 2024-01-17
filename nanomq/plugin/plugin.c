//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include "include/plugin.h"
#include "include/nanomq.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/cvector.h"
#include <dlfcn.h>

struct nano_plugin **g_plugins;
struct plugin_hook **g_hooks;

int plugin_hook_register(unsigned int point, int (*cb)(void *data))
{
	struct plugin_hook *hook = NULL;

	/* already existed */
	for (int i = 0; i < cvector_size(g_hooks); i++) {
		if (g_hooks[i]->point == point) {
			g_hooks[i]->cb = cb;
			log_warn("plugin_hook_register: %d already existed and replace with new callback", point);
			return 0;
		}
	}

	if ((hook = nng_alloc(sizeof(struct plugin_hook))) == NULL) {
		return NNG_ENOMEM;
	}

	hook->point = point;
	hook->cb = cb;

	cvector_push_back(g_hooks, hook);

	return 0;
}

int plugin_hook_call(unsigned int point, void *data)
{
	for (int i = 0; i < cvector_size(g_hooks); i++) {
		if (g_hooks[i]->point == point) {
			return g_hooks[i]->cb(data);
		}
	}

	return 0;
}

int plugin_register(char *path)
{
	struct nano_plugin *plugin = NULL;

	if (path == NULL) {
		return NNG_EINVAL;
	}

	if ((plugin = nng_alloc(sizeof(struct nano_plugin))) == NULL) {
		return NNG_ENOMEM;
	}

	if ((plugin->path = nng_strdup(path)) == NULL) {
		nng_free(plugin, sizeof(struct nano_plugin));
		return NNG_ENOMEM;
	}

	if (plugin_init(plugin) != 0) {
		nng_free(plugin->path, strlen(plugin->path));
		nng_free(plugin, sizeof(struct nano_plugin));
		return NNG_EINVAL;
	}

	cvector_push_back(g_plugins, plugin);

	log_info("plugin_register: %s successfully", path);

	return 0;
}

void plugins_clear()
{
	struct nano_plugin *plugin = NULL;
	for (int i = 0; i < cvector_size(g_plugins); i++) {
		struct nano_plugin *plugin = g_plugins[i];
		nng_free(plugin->path, strlen(plugin->path));
		nng_free(plugin, sizeof(struct nano_plugin));
	}
	cvector_free(g_plugins);

	return;
}

int plugin_init(struct nano_plugin *plugin)
{
	void *handle = NULL;
	/* open plugin */
	handle = dlopen(plugin->path, RTLD_NOW);
	if (handle == NULL) {
		log_error("plugin_init: open: %s failed", plugin->path);
		return NNG_EINVAL;
	}

	/* get init function */
	if ((plugin->init = dlsym(handle, "nano_plugin_init")) == NULL) {
		log_error("plugin_init: parse: %s failed", plugin->path);
		return NNG_EINVAL;
	}

	/* call init function */
	if (plugin->init() != 0) {
		log_error("plugin_init init: %s failed", plugin->path);
		return NNG_EINVAL;
	}

	log_info("plugin_init init: %s successfully", plugin->path);
	return 0;
}
