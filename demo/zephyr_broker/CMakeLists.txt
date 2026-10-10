# NanoMQ → Zephyr broker demo.
#
# Cross-compiles the NanoNNG submodule (nng/) with ExternalProject exactly
# like the NanoNNG zephyr_mqtt demo does, then compiles the NanoMQ broker
# core sources (nanomq/nanomq/) against it.
#
# Build:  west build -b qemu_x86 demo/zephyr_broker
# Run:    west build -t run  (SLIRP hostfwd: host tcp:1883 -> guest)

cmake_minimum_required(VERSION 3.20.0)
if(NOT DEFINED ZEPHYR_BASE)
  set(ZEPHYR_BASE $ENV{ZEPHYR_BASE})
endif()
find_package(Zephyr REQUIRED HINTS ${ZEPHYR_BASE})
project(nanomq_zephyr_broker)

# Repo layout: this demo is <repo>/demo/zephyr_broker; the NanoNNG
# submodule (nng fork incl. nanolib) lives at <repo>/nng.
set(NANOMQ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(NNG_ROOT ${NANOMQ_ROOT}/nng)

# ── NanoMQ broker core ──────────────────────────────────────────
# Mirror of the SOURCES list in nanomq/nanomq/CMakeLists.txt with three
# deviations:
#   * process.c excluded — pure POSIX (fork/kill/<paths.h>); its symbols
#     (process.h) are provided by src/process_stub.c instead.
#   * plugin/plugin.c excluded — NNG_ENABLE_PLUGIN off.
#   * tests/ excluded — NANOMQ_TESTS off.
target_sources(app PRIVATE
  src/main.c
  src/process_stub.c
  ${NANOMQ_ROOT}/nanomq/bridge.c
  ${NANOMQ_ROOT}/nanomq/pub_handler.c
  ${NANOMQ_ROOT}/nanomq/sub_handler.c
  ${NANOMQ_ROOT}/nanomq/unsub_handler.c
  ${NANOMQ_ROOT}/nanomq/hashmap.c
  ${NANOMQ_ROOT}/nanomq/rest_api.c
  ${NANOMQ_ROOT}/nanomq/web_server.c
  ${NANOMQ_ROOT}/nanomq/webhook_inproc.c
  ${NANOMQ_ROOT}/nanomq/webhook_post.c
  ${NANOMQ_ROOT}/nanomq/aws_bridge.c
  ${NANOMQ_ROOT}/nanomq/nanomq_rule.c
  ${NANOMQ_ROOT}/nanomq/conf_api.c
  ${NANOMQ_ROOT}/nanomq/cmd_proc.c
  ${NANOMQ_ROOT}/nanomq/acl_handler.c
  ${NANOMQ_ROOT}/nanomq/acl_hazard.c
  ${NANOMQ_ROOT}/nanomq/mqtt_api.c
  ${NANOMQ_ROOT}/nanomq/nanomq.c
  ${NANOMQ_ROOT}/nanomq/apps/broker.c
  ${NANOMQ_ROOT}/nanomq/apps/nng_bridge.c
)

target_include_directories(app PRIVATE
  ${NANOMQ_ROOT}/nanomq
  ${NANOMQ_ROOT}/nanomq/include
  ${NNG_ROOT}/include
)

# Upstream platform/capability macros (root CMakeLists.txt has no Zephyr
# branch and falls into the POSIX else-clause, so it is not reused here):
#   ACL_SUPP      — ENABLE_ACL default ON; conf struct fields follow it
#   ENABLE_LOG    — log calls enabled (SUPP_SYSLOG deliberately NOT set:
#                   Zephyr has no syslog(); nanolib log.c has __ZEPHYR__
#                   output support instead)
#   SUPP_NANO_LIB — hides nanomq.c's main(); keeps get_cache_argc/argv
#                   which rest_api.c references
#   NNG_STATIC_LIB — NNG_DECL decoration (imported lib carries no usage
#                   requirements)
target_compile_definitions(app PRIVATE
  ACL_SUPP
  ENABLE_LOG
  SUPP_NANO_LIB
  NNG_STATIC_LIB
)

# NanoNNG broker-side protocol/transports (upstream sets these as plain
# variables before add_subdirectory(nng); ExternalProject needs them
# passed explicitly as cache vars).
set(NNG_EXTRA_ARGS
  -DNNG_PROTO_MQTT_BROKER=ON
  -DNNG_TRANSPORT_MQTT_BROKER_TCP=ON
  -DNNG_TRANSPORT_MQTT_BROKER_WS=ON
)

# ENABLE_LOG must reach the nng build as a compiler flag (nng's CMake
# only reacts to -DNNG_* cache vars): nanolib conf.c gates conf_log_init()
# on it and nanolib log.h compiles log_*() to no-ops without it — a
# libnng built without ENABLE_LOG leaves conf->log.type unset (broker
# logging dead) even though the app side defines it.
#
# ACL_SUPP likewise gates the conf_acl fields of struct conf
# (conf.h: #ifdef ACL_SUPP → conf_acl acl / acl_nomatch / acl_deny_action,
# 20 bytes).  It is defined on the app side above, so the conf.c compiled
# into libnng MUST see it too, or struct conf layouts disagree between
# libnng and the broker .c files — auth_http lands 20 bytes early in
# libnng's view and start_rest_server() locks a garbage
# auth_http.acl_cache_mtx (pthread_mutex_lock: Invalid argument → nni_panic).
set(NNG_EXTRA_CFLAGS "-DENABLE_LOG -DACL_SUPP")

include(../cmake/nanonng_external.cmake)
