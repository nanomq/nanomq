# NanoMQ → ESP32-S3 broker demo (sibling of demo/nanomq_zephyr_qemu_x86, the
# qemu_x86 version of the same app).
#
# Cross-compiles the NanoNNG submodule (nng/) with ExternalProject exactly
# like the NanoNNG zephyr_mqtt demo does, then compiles the NanoMQ broker
# core sources (nanomq/nanomq/) against it.
#
# Board: esp32s3_devkitc/esp32s3/procpu — the ESP32-S3-LCD-EV-Board has no
# Zephyr board of its own; module differences (16 MB flash + PSRAM) are in
# boards/<target>.overlay.
#
# Build:  west build -b esp32s3_devkitc/esp32s3/procpu demo/nanomq_zephyr_esp32s3
#          (add:  -- -DEXTRA_CONF_FILE=local.conf   for Wi-Fi credentials)
# Flash:  west flash -d build/nanomq_zephyr_esp32s3

cmake_minimum_required(VERSION 3.20.0)
if(NOT DEFINED ZEPHYR_BASE)
  set(ZEPHYR_BASE $ENV{ZEPHYR_BASE})
endif()

# Board-specific device tree: ESP32-S3-LCD-EV-Board module differences
# (16 MB flash + 16 MB PSRAM) vs the esp32s3_devkitc default (N8, no
# PSRAM).  Named with Zephyr's shortened-board form, so it would normally
# be auto-discovered from boards/ — pulled in explicitly to be robust
# across Zephyr revisions' qualifier naming.
set(DTC_OVERLAY_FILE
  ${CMAKE_CURRENT_SOURCE_DIR}/boards/esp32s3_devkitc_procpu.overlay
  CACHE STRING "Board overlay: ESP32-S3-LCD-EV-Board module (N16R16V)" FORCE)

find_package(Zephyr REQUIRED HINTS ${ZEPHYR_BASE})
project(nanomq_zephyr_esp32s3)

# Repo layout: this demo is <repo>/demo/nanomq_zephyr_qemu_x86; the NanoNNG
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
  # nanolib's broker log_init(conf_log *) (mqtt_api.c) collides with the
  # Zephyr logging subsystem's log_init() once CONFIG_LOG=y (needed for
  # esp32 wifi driver diagnostics) — rename every app-side use so the two
  # keep separate symbols.
  log_init=nanomq_log_init
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
#
# NNG_ZEPHYR_ALLOC_SMH switches the nng Zephyr allocator from libc malloc
# (SRAM-bounded) to the PSRAM-backed shared multi-heap — required on
# ESP32-S3, where internal SRAM (~512 KB) cannot hold the broker data
# plane.  See nng/src/platform/zephyr/zephyr_alloc.c.
set(NNG_EXTRA_CFLAGS "-DNNG_ZEPHYR_ALLOC_SMH -DENABLE_LOG -DACL_SUPP")

include(../cmake/nanonng_external.cmake)
