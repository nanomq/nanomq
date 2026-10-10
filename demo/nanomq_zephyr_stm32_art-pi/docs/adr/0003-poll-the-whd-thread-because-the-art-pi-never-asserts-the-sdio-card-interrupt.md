# ART-Pi Wi-Fi polls the WHD thread; the SDIO card interrupt never arrives

The ART-Pi's AP6212 (Infineon CYW43438) never drives the SDIO card interrupt
on this board, so Infineon's WHD — which only enters its receive path when
that interrupt wakes its worker thread — wrote every WLAN ioctl to the chip
and then timed out without reading the reply
(`iovar "cap" -> 101580800`, 5 s each, `airoc_wifi_init_primary failed
ret = -19`). The demo therefore pokes `whd_thread_notify_irq()` from a 20 ms
timer (`CONFIG_AIROC_WIFI_WHD_POKE`), which gives the thread the wake-up the
interrupt would have delivered so that its poll reads the queued frames.

## Considered Options

- **Fix the in-band path in the host controller.** The STM32 SDHC driver had
  no SDIO card-interrupt support at all (`enable_interrupt` was
  unimplemented), so that was added, and `DCTRL.SDIOEN` — the peripheral's
  "SD I/O enable", the bit that makes DAT1 an interrupt line — was tried too.
  Measured on hardware with both in place: `SDMMC_MASK.SDIOITIE` set and
  `DCTRL.SDIOEN` set, yet `SDMMC_STA.SDIOIT` stayed clear for whole boots.
  Worse, with `SDIOEN` set the 4-bit data path starts failing as soon as
  traffic flows (`sdhc_stm32: Command response timeout` flood), so it is
  deliberately *not* set.  A 1-bit configuration (`bus-width = <1>` plus
  WHD's `sdio_1bit_mode`) with `SDIOEN` behaved the same: no `SDIOIT`, no
  link.  The card-interrupt plumbing itself stays, because
  `sdhc_enable_interrupt()` succeeding is a precondition for WHD's init.
- **Use the chip's out-of-band host-wake (WL_HOST_WAKE).** The schematic
  carries a `GPIO_WIFI_HOST_WAKE` net and the vendor NVRAM sets
  `muxenab=0x11` (bit `0x10` = "HW OOB"), so this was tried as
  `wifi-host-wake-gpios = <&gpioe 3 GPIO_ACTIVE_HIGH>` (PE3 is the only MCU
  pin the schematic text plausibly pairs with that net — the PI14/PI15 hits
  are the LCD's LTDC_CLK/LTDC_R0).  It never produced a wake-up, and with
  traffic flowing the same CMD-timeout flood appeared.  Left commented out;
  the pin is unconfirmed without a scope.
- **Poll instead** (chosen).  This is what the board's own vendor stack does:
  `libraries/drivers/drv_sdio.c` in the ART-Pi SDK never enables
  `SDMMC_MASK.SDIOITIE` and registers no card-interrupt callback, so the
  vendor's WICED-based driver gets its interrupts by polling the chip's
  status registers rather than by being interrupted.

## Consequences

- The link costs one periodic wake-up of WHD's worker thread (a backplane
  status read when idle); it is a Kconfig option, so boards whose chip *does*
  assert the interrupt can leave it off.
- The dependency is documented at the call site and here, because it is
  invisible in the driver: WHD's SDIO transport reports
  `whd_bus_use_status_report_scheme() == WHD_FALSE`, so nothing else in its
  thread loop would ever poll.
- The SDIO host controller's card-interrupt support is still worth having
  upstream (it is the standard path for SDIO function drivers), but on this
  board + chip combination it is inert.
- Consequence of polling: after the link has been up for a few minutes the
  backplane status reads start failing and the console floods with
  `sdhc_stm32: Command response timeout`.  Measured on hardware, that state is
  **not** fatal — the whole functional suite passes while it floods, and a
  board reset clears it — but ICMP can fail in it, so liveness has to be
  judged over TCP.  This is the price of not having the interrupt, and it is
  why the board is reset between long runs on the bench.
