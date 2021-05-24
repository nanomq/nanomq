#!/bin/sh
set -e

_main() {
	if [ "${1#-}" != "$1" ]; then
		set -- nanomq broker start "$@"
	fi
    exec "$@"
}

_main "$@"
