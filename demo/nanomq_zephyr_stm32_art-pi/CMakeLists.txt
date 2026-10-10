# NanoMQ → ART-Pi (STM32H750XBH6) broker demo — sibling of
# demo/nanomq_zephyr_qemu_x86 and demo/nanomq_zephyr_esp32s3.
#
# Cross-compiles the NanoNNG submodule (nng/) with ExternalProject exactly
# like the sibling demos do, then compiles the NanoMQ broker core sources
# (nanomq/nanomq/) against it.
#
# Board: art_pi (Ruiside Electronic ART-Pi, STM32H750XBH6, 1 MB SRAM,
# 32 MB SDRAM, 8 MB QSPI flash, RMII Ethernet with a LAN8720A PHY).
#
# The broker is ~0.9 MB of code while the STM32H750 has only 128 KB of
# internal flash — occupied by the ART-Pi factory bootloader — so the image
# links into the QSPI memory-mapped window at 0x90000000.  The overlay below
# redirects zephyr,flash there; the factory bootloader maps the QUADSPI and
# jumps to the vector table at 0x90000000.  See
# docs/adr/0001-qspi-xip-behind-art-pi-factory-bootloader.md.
#
# The broker data plane does not fit in internal SRAM either: it is served
# from a k_heap over the SDRAM1 devicetree region (see src/artpi_ext_ram.ld
# and docs/adr/0002-...).
#
# Build:  west build -b art_pi demo/nanomq_zephyr_stm32_art-pi
#          (add:  -- -DEXTRA_CONF_FILE=local.conf   for REST credentials)
# Flash:  demo/nanomq_zephyr_stm32_art-pi/tools/flash.sh

cmake_minimum_required(VERSION 3.20.0)
if(NOT DEFINED ZEPHYR_BASE)
  set(ZEPHYR_BASE $ENV{ZEPHYR_BASE})
endif()

# Mandatory: without it a plain `west build -b art_pi` links into the 128 KB
# internal flash (which cannot hold the broker) and the demo overlay also
# disables the display controller, whose framebuffer would otherwise sit in
# the SDRAM window the broker heap uses.
set(DTC_OVERLAY_FILE
  ${CMAKE_CURRENT_SOURCE_DIR}/boards/art_pi.overlay
  CACHE STRING "Board overlay: QSPI XIP + display off" FORCE)

find_package(Zephyr REQUIRED HINTS ${ZEPHYR_BASE})
project(nanomq_zephyr_stm32_art_pi)

# Repo layout: this demo is <repo>/demo/nanomq_zephyr_stm32_art-pi; the
# NanoNNG submodule (nng fork incl. nanolib) lives at <repo>/nng.
set(NANOMQ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(NNG_ROOT ${NANOMQ_ROOT}/nng)

# ── NanoMQ broker core ──────────────────────────────────────────
# Mirror of the SOURCES list in nanomq/nanomq/CMakeLists.txt with the same
# three deviations as the sibling demos:
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
#   NNG_STATIC_LIB — NNG_DECL decoration
#   log_init=...  — nanolib's log_init(conf_log *) (mqtt_api.c) collides with
#                   Zephyr's logging subsystem once CONFIG_LOG=y, so every
#                   app-side use is renamed.
target_compile_definitions(app PRIVATE
  ACL_SUPP
  ENABLE_LOG
  SUPP_NANO_LIB
  NNG_STATIC_LIB
  log_init=nanomq_log_init
)

# Broker heap bounds.  NanoNNG's external-RAM allocator (built with
# NNG_ZEPHYR_ALLOC_SMH below) externs _ext_ram_heap_start/_end and hands that
# range to a plain k_heap.  The fragment aliases those symbols to the SDRAM1
# devicetree region, which keeps the nng submodule unmodified.
zephyr_linker_sources(SECTIONS src/artpi_ext_ram.ld)

# NanoNNG broker-side protocol/transports (upstream sets these as plain
# variables before add_subdirectory(nng); ExternalProject needs them passed
# explicitly as cache vars).
set(NNG_EXTRA_ARGS
  -DNNG_PROTO_MQTT_BROKER=ON
  -DNNG_TRANSPORT_MQTT_BROKER_TCP=ON
  -DNNG_TRANSPORT_MQTT_BROKER_WS=ON
)

# ENABLE_LOG and ACL_SUPP must reach the nng build as compiler flags: nng's
# CMake only reacts to -DNNG_* cache vars, so plain macros have to go through
# CMAKE_C_FLAGS.  A libnng built without ENABLE_LOG leaves the broker's log
# module dead; built without ACL_SUPP it lays struct conf out differently
# from the app side (auth_http shifts by the conf_acl fields) and
# start_rest_server() locks a garbage mutex — the qemu demo's issue #11.
#
# NNG_ZEPHYR_ALLOC_SMH switches the nng Zephyr allocator from libc malloc to
# a k_heap over external RAM — here the SDRAM window — as the broker data
# plane cannot live in the ART-Pi's 1 MB of internal SRAM.
set(NNG_EXTRA_CFLAGS "-DNNG_ZEPHYR_ALLOC_SMH -DENABLE_LOG -DACL_SUPP")

include(../cmake/nanonng_external.cmake)
