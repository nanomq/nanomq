/*
 * Broker heap bounds — see
 * docs/adr/0002-broker-heap-in-sdram-through-the-external-ram-allocator.md.
 *
 * The board devicetree declares a 6 MB memory region named SDRAM1 at
 * 0xC0000000 (zephyr,memory-region), so the linker always emits its output
 * section together with the __SDRAM1_start/__SDRAM1_end symbols, and
 * CONFIG_MEM_ATTR programs the matching MPU region as Normal write-back
 * cacheable RAM (not the ARMv7-M default "Device" attributes for that
 * address).
 *
 * NanoNNG's Zephyr external-RAM allocator — built with NNG_ZEPHYR_ALLOC_SMH,
 * nng/src/platform/zephyr/zephyr_alloc.c — externs exactly these two symbols
 * and hands the range to a plain k_heap (deliberately not
 * shared_multi_heap_alloc: its unsynchronised sys_heap corrupted the heap
 * under the ESP32-S3 port's concurrent traffic).  Aliasing them here keeps
 * the nng submodule unmodified.
 *
 * 4 MB of the 6 MB window is handed to the heap, leaving 2 MB spare.
 */
_ext_ram_heap_start = __SDRAM1_start;
_ext_ram_heap_end   = __SDRAM1_start + (4 * 1024 * 1024);
