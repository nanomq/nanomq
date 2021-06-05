
#define APP_NAME_MAX 25

struct nanomq_app {
	char name[APP_NAME_MAX];
	int (*dflt)(int argc, char **argv);
	int (*start)(int argc, char **argv);
	int (*stop)(int argc, char **argv);
	int (*restart)(int argc, char **argv);
};

#define NANOMQ_APP(_name, _dflt, _start, _stop, _restart) \
const struct nanomq_app nanomq_app_##_name = {            \
	.name = #_name,                                       \
	.dflt = _dflt,                                        \
	.start = _start,                                      \
	.stop = _stop,                                        \
	.restart = _restart,                                  \
}

extern const struct nanomq_app *edge_apps[];
