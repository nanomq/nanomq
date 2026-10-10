# Shared NanoNNG ExternalProject build logic for Zephyr demos.
#
# Usage from demo CMakeLists.txt:
#   set(NNG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
#   set(NNG_EXTRA_ARGS -DNNG_TRANSPORT_MQTT_TCP=ON)   # optional
#   include(../cmake/nanonng_external.cmake)
#
# The calling CMakeLists.txt must:
#   - call find_package(Zephyr) before including this file
#   - set NNG_ROOT to the NanoNNG source root
#   - optionally set NNG_EXTRA_ARGS for demo-specific cache vars
#   - optionally set NNG_EXTRA_CFLAGS for demo-specific compiler flags
#     (nng's CMakeLists does not consume arbitrary -D cache vars, so
#     plain macros like ENABLE_LOG must come through CMAKE_C_FLAGS)

# ── Architecture-specific flags ──────────────────────────────────
# Only 32-bit x86 needs special help for 64-bit atomics (cmpxchg8b).
# 32-bit ARM (Cortex-M, Cortex-R) lacks native 64-bit atomics — use
# the pthread-mutex fallback (nni_atomic_u64 has a mutex member).
# 64-bit architectures (AArch64, RISC-V 64, x86_64) have native
# 64-bit atomics and need no special handling.
zephyr_get_compile_options_for_lang_as_string(C options)
set(arch_flags "")
if(CONFIG_X86 AND NOT CONFIG_64BIT)
  if(CONFIG_SOC_ATOM)
    set(arch_flags "-march=atom")
  elseif(BOARD MATCHES "qemu_x86")
    # QEMU uses "-cpu qemu32" which lacks SSE2+ and movbe.  i686 gives
    # us cmpxchg8b (for 64-bit atomics) without SSE2+/movbe.
    # Zephyr's SoC-level flags may add "-march=atom" — strip it;
    # we supply the correct -march below.
    set(arch_flags "-march=i686 -mno-sse2 -mno-sse3 -mno-ssse3 -mno-movbe")
  elseif(CONFIG_SOC_INTEL_ISH)
    set(arch_flags "-march=pentium-m")
  elseif(CONFIG_SOC_QUARK_SE)
    # Quark lacks cmpxchg8b — atomics will call libatomic
    set(arch_flags "-march=i586")
  else()
    # Safe default: i686 has cmpxchg8b
    set(arch_flags "-march=i686")
  endif()
elseif(NOT CONFIG_64BIT AND NOT CONFIG_X86)
  # Any 32-bit non-x86 target (ARM, RISC-V, Xtensa/esp32s3, ...):
  # __sync_*_8 emits calls its libatomic cannot resolve on bare-metal
  # (xtensa-esp32s3: undefined __sync_fetch_and_add_8 at link).  Use the
  # pthread-mutex atomic fallback instead.  x86_32 has cmpxchg8b; 64-bit
  # targets have native 64-bit atomics — both unaffected.
  list(APPEND NNG_EXTRA_ARGS -DNNG_ZEPHYR_NO_STDATOMIC=ON)
endif()

# ── Zephyr build flags ───────────────────────────────────────────
zephyr_get_include_directories_for_lang_as_string(       C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(       C definitions)

# Zephyr's qemu_x86/atom SoC sets "-march=atom" which enables "movbe"
# (Move Big-Endian, an Intel Atom instruction).  QEMU's "-cpu qemu32"
# does NOT support movbe — execute it and you get #UD.
# Strip -march=atom from the Zephyr options; our arch_flags below
# supply the correct -march for each board.
string(REGEX REPLACE "-march=atom" "" options "${options}")

set(build_includes
  -I${PROJECT_BINARY_DIR}/zephyr/include/generated
  -I${PROJECT_BINARY_DIR}/zephyr/include/generated/zephyr
)
string(REPLACE ";" " " build_includes_str "${build_includes}")

set(NNG_ROOT ${NNG_ROOT})  # ensure it's visible in this scope

# Zephyr's qemu_x86/atom SoC enables "-march=atom" which includes "movbe"
# (Move Big-Endian).  QEMU's "-cpu qemu32" does NOT support movbe and
# raises #UD when it hits one — so x86 builds get -mno-movbe.  Other
# targets (e.g. xtensa esp32s3) must NOT see it: their gcc rejects the
# option outright.
set(mno_movbe "")
if(CONFIG_X86)
  set(mno_movbe " -mno-movbe")
endif()
set(external_cflags
  "${includes} ${system_includes} ${definitions} ${options} ${arch_flags} ${build_includes_str} -DNDEBUG ${NNG_EXTRA_CFLAGS}${mno_movbe}")

# ── ExternalProject ──────────────────────────────────────────────
include(ExternalProject)

ExternalProject_Add(nanonng
  SOURCE_DIR     ${NNG_ROOT}
  BINARY_DIR     ${CMAKE_BINARY_DIR}/nanonng_build
  CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_AR=${CMAKE_AR}
    -DCMAKE_SYSTEM_NAME=Generic
    -DCMAKE_C_COMPILER_WORKS=TRUE
    -DCMAKE_CXX_COMPILER_WORKS=TRUE
    -DCMAKE_C_FLAGS=${external_cflags}
    -DNNG_PLATFORM_POSIX=ON
    -DNNG_PLATFORM_ZEPHYR=ON
    -DNNG_STATIC_LIB=ON
    -DNNG_TESTS=OFF
    -DNNG_TOOLS=OFF
    -DNNG_ENABLE_TLS=OFF
    -DNNG_ENABLE_QUIC=OFF
    -DNNG_TRANSPORT_IPC=OFF
    -DNNG_TRANSPORT_TLS=OFF
    -DNNG_TRANSPORT_WS=ON
    -DNNG_ENABLE_HTTP=ON
    -DNNG_ENABLE_SQLITE=OFF
    -DNNG_ENABLE_COMPAT=OFF
    -DNNG_MAX_TASKQ_THREADS=2
    -DNNG_MAX_POLLER_THREADS=1
    -DNNG_MAX_EXPIRE_THREADS=1
    ${NNG_EXTRA_ARGS}
  # Source edits inside the nng tree do not bump ExternalProject stamps,
  # so without this a changed zephyr_alloc.c etc. silently stays unbuilt
  # (observed: stale libnng.a served for several demo builds).  With
  # BUILD_ALWAYS the sub-build runs each time and ninja no-ops when
  # nothing changed.
  BUILD_ALWAYS TRUE
  BUILD_COMMAND     ${CMAKE_COMMAND} --build <BINARY_DIR> --target nng
  INSTALL_COMMAND   ""
  BUILD_BYPRODUCTS  <BINARY_DIR>/libnng.a
  EXCLUDE_FROM_ALL
)

# Ensure Zephyr generated headers (syscall_list.h, etc.) are available
# before the external project starts compiling NanoNNG sources.
if(TARGET syscall_list_h_target)
  add_dependencies(nanonng syscall_list_h_target)
endif()

# ── Import built library ─────────────────────────────────────────
add_library(nng STATIC IMPORTED GLOBAL)
set_property(TARGET nng PROPERTY IMPORTED_LOCATION
  ${CMAKE_BINARY_DIR}/nanonng_build/libnng.a)
add_dependencies(nng nanonng)

target_include_directories(app PRIVATE ${NNG_ROOT}/include)
target_link_libraries(app PRIVATE nng)
