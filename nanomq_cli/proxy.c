#include "include/proxy.h"

proxy_info *
proxy_info_alloc(const char *name, void *conf, char *conf_path,
    conf_http_server *http_conf, int argc, char **argv)
{
	proxy_info *info  = nng_zalloc(sizeof(proxy_info));
	info->proxy_name  = name;
	info->conf        = conf;
	info->conf_path   = conf_path;
	info->http_server = http_conf;
	info->args.argc   = argc;
	info->args.argv   = argv;

	return info;
}