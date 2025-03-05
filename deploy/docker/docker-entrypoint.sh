#!/bin/sh

if [ -n "$DEBUG" ]; then
    set -ex
else
    set -e
fi

_main() {
	if [ -f "/tmp/nanomq/nanomq.pid" ];then
		rm -f /tmp/nanomq/nanomq.pid
	fi

	if [ "$#" -eq 0 ];then
		set -- nanomq start
	elif [ "${1#-}" != "$1" ]; then
		set -- nanomq start "$@"
	fi

  exec "$@"
}

_main "$@"
