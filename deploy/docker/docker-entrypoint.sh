#!/bin/sh
set -e

_main() {
	if [ -f "/tmp/nanomq/nanomq.pid" ];then
		rm -f /tmp/nanomq/nanomq.pid
	fi

	if [ "${1#-}" != "$1" ]; then
		set -- nanomq broker start "$@"
	fi
    exec "$@"
}

_main "$@"
