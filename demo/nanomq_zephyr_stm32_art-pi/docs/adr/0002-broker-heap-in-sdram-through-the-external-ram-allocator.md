# Broker heap lives in SDRAM, reached through the external-RAM allocator

The NanoMQ data plane does not fit in the ART-Pi's 1 MB of internal SRAM
(the ESP32-S3 sibling gives it a 4 MB window), but the board has 32 MB of
FMC SDRAM, of which the devicetree already declares a 6 MB
`zephyr,memory-region` named `SDRAM1` at 0xC0000000. The demo enables
`MEMC_STM32_SDRAM`, initialises a plain `k_heap` over that region at boot
(`shared_multi_heap_alloc()` is deliberately avoided — its unsynchronised
`sys_heap` corrupted the heap under the S3 port's multi-threaded traffic),
and routes NanoNNG's `nni_alloc`/`nni_free` to it. The display controller is
disabled so its framebuffer does not compete for the same region.

## Considered Options

- **Give NanoNNG a new, explicitly named external-memory allocator** —
  clearer than reusing the ESP32-era macro, but it means an nng submodule
  commit plus a superproject bump.
- **Reuse `NNG_ZEPHYR_ALLOC_SMH` unchanged and define its
  `_ext_ram_heap_start`/`_ext_ram_heap_end` symbols in an application linker
  fragment** (chosen). The symbol names are already generic external-RAM
  names, so no submodule change is needed; the macro's "SMH" name is the
  only misleading part.

## Consequences

- The heap covers the devicetree region, so its size is a devicetree
  property, not a Kconfig value: 4 MB of the 6 MB window is handed to the
  k_heap, leaving 2 MB spare.
- NanoMQ's libc-side allocations (cJSON, REST buffers) still come from the
  internal-SRAM heap; only NanoNNG allocations move to SDRAM. A DMA-capable
  consumer of that memory would need cache maintenance — none does today.
