#include "include/conf_api.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void
free_entries(conf_auth *auth)
{
	for (size_t i = 0; i < cvector_size(auth->usernames); i++) {
		nng_strfree(auth->usernames[i]);
	}
	for (size_t i = 0; i < cvector_size(auth->passwords); i++) {
		nng_strfree(auth->passwords[i]);
	}
	cvector_free(auth->usernames);
	cvector_free(auth->passwords);
}

static void
check_pair(cJSON *array, size_t index, const char *user, const char *pass)
{
	cJSON *entry = cJSON_GetArrayItem(array, (int) index);
	assert(cJSON_IsObject(entry));
	cJSON *login = cJSON_GetObjectItem(entry, "login");
	cJSON *password = cJSON_GetObjectItem(entry, "password");
	assert(cJSON_IsString(login) && cJSON_IsString(password));
	assert(strcmp(login->valuestring, user) == 0);
	assert(strcmp(password->valuestring, pass) == 0);
}

static void
test_bounds(void)
{
	// count, username length, password length, expected JSON length.
	const size_t sizes[][4] = {
		{ 0, 0, 0, 0 }, { 5, 0, 0, 0 }, { 8, 2, 1, 1 },
		{ 8, 1, 2, 1 }, { 1, 3, 3, 1 }, { 1, 1, 0, 0 },
		{ 1, 0, 1, 0 }, { 0, 1, 1, 0 }, { 2, 2, 2, 2 }
	};
	for (unsigned with_mutex = 0; with_mutex < 2; with_mutex++) {
		for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
			conf_auth auth = { .count = sizes[i][0] };
			if (with_mutex) {
				assert(nng_mtx_alloc(&auth.mtx) == 0);
			}
			for (size_t j = 0; j < sizes[i][1]; j++) {
				cvector_push_back(auth.usernames, nng_strdup("u"));
			}
			for (size_t j = 0; j < sizes[i][2]; j++) {
				cvector_push_back(auth.passwords, nng_strdup("p"));
			}
			cJSON *array = get_auth_config(&auth);
			assert(cJSON_IsArray(array));
			assert(cJSON_GetArraySize(array) == (int) sizes[i][3]);
			for (size_t j = 0; j < sizes[i][3]; j++) {
				check_pair(array, j, "u", "p");
			}
			cJSON_Delete(array);
			free_entries(&auth);
			if (with_mutex) {
				nng_mtx_free(auth.mtx);
			}
		}
	}
}

static void
make_entries(conf_auth *auth, unsigned generation)
{
	size_t count = generation % 2 == 0 ? 1 : 4;
	for (size_t i = 0; i < count; i++) {
		char user[64], pass[64];
		snprintf(user, sizeof(user), "user-%u-%zu", generation, i);
		snprintf(pass, sizeof(pass), "pass-%u-%zu", generation, i);
		char *username = nng_strdup(user);
		char *password = nng_strdup(pass);
		assert(username != NULL && password != NULL);
		cvector_push_back(auth->usernames, username);
		cvector_push_back(auth->passwords, password);
		auth->count++;
	}
}

static void
check_snapshot(cJSON *array)
{
	assert(cJSON_IsArray(array));
	int count = cJSON_GetArraySize(array);
	assert(count == 1 || count == 4);
	cJSON *first = cJSON_GetObjectItem(cJSON_GetArrayItem(array, 0), "login");
	assert(cJSON_IsString(first));
	unsigned generation;
	size_t index;
	assert(sscanf(first->valuestring, "user-%u-%zu", &generation, &index) == 2);
	assert(index == 0);
	assert(count == (generation % 2 == 0 ? 1 : 4));
	for (int i = 0; i < count; i++) {
		char user[64], pass[64];
		snprintf(user, sizeof(user), "user-%u-%d", generation, i);
		snprintf(pass, sizeof(pass), "pass-%u-%d", generation, i);
		check_pair(array, (size_t) i, user, pass);
	}
}

static void
test_owned_snapshot(void)
{
	conf_auth auth = { 0 };
	conf_auth next = { 0 };
	assert(nng_mtx_alloc(&auth.mtx) == 0);
	make_entries(&auth, 0);
	make_entries(&next, 1);
	cJSON *snapshot = get_auth_config(&auth);
	reload_auth_config(&auth, &next);
	free_entries(&next);
	// The response must retain its strings after the retired list is freed.
	check_snapshot(snapshot);
	check_pair(snapshot, 0, "user-0-0", "pass-0-0");
	cJSON_Delete(snapshot);
	free_entries(&auth);
	nng_mtx_free(auth.mtx);
}

typedef struct {
	conf_auth auth;
	nng_atomic_int *ready;
	nng_atomic_int *start;
} race_state;

static void
start_together(race_state *state)
{
	nng_atomic_inc(state->ready);
	while (!nng_atomic_get(state->start)) {
		nng_msleep(0);
	}
}

static void
reload_entries(void *arg)
{
	race_state *state = arg;
	start_together(state);
	for (unsigned i = 1; i <= 1000; i++) {
		conf_auth next = { 0 };
		make_entries(&next, i);
		reload_auth_config(&state->auth, &next);
		free_entries(&next);
	}
}

static void
read_entries(void *arg)
{
	race_state *state = arg;
	start_together(state);
	for (unsigned i = 0; i < 1000; i++) {
		cJSON *array = get_auth_config(&state->auth);
		check_snapshot(array);
		cJSON_Delete(array);
	}
}

static void
test_concurrent_reload(void)
{
	race_state state = { 0 };
	assert(nng_mtx_alloc(&state.auth.mtx) == 0);
	assert(nng_atomic_alloc(&state.ready) == 0);
	assert(nng_atomic_alloc(&state.start) == 0);
	nng_atomic_set(state.ready, 0);
	nng_atomic_set(state.start, 0);
	make_entries(&state.auth, 0);
	nng_thread *writer, *readers[2];
	assert(nng_thread_create(&writer, reload_entries, &state) == 0);
	for (unsigned i = 0; i < 2; i++) {
		assert(nng_thread_create(&readers[i], read_entries, &state) == 0);
	}
	while (nng_atomic_get(state.ready) != 3) {
		nng_msleep(0);
	}
	nng_atomic_set(state.start, 1);
	nng_thread_destroy(writer);
	for (unsigned i = 0; i < 2; i++) {
		nng_thread_destroy(readers[i]);
	}
	free_entries(&state.auth);
	nng_mtx_free(state.auth.mtx);
	nng_atomic_free(state.ready);
	nng_atomic_free(state.start);
}

int
main(int argc, char **argv)
{
	if (argc == 1 || strcmp(argv[1], "race") != 0) {
		test_bounds();
		test_owned_snapshot();
	}
	test_concurrent_reload();
	nng_fini();
	return 0;
}
