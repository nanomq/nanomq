# NanoMQ Zephyr port demos

The `demo/nanomq_zephyr_*` applications run the NanoMQ broker core on Zephyr
RTOS. Each sibling demo uses the same broker sources with a different target
and network layer.

## Language

**Zephyr broker demo**:
One of the sibling applications that builds the NanoMQ broker core plus
NanoNNG for a Zephyr target.
_Avoid_: "the Zephyr port" (that is the whole `__ZEPHYR__` platform work, not
one demo)

**ART-Pi**:
The Ruiside (RT-Thread team) STM32H750XBH6 board that is the hardware target
of this demo.
_Avoid_: "RT-Thread ART-Pi" when the RTOS is what is meant

**Acceptance tier**:
How far a Zephyr broker demo is proven: buildable, board-verified, or at
functional parity with the functional test suite.

**ART-Pi factory bootloader**:
The Ruiside/RT-Thread first-stage shipped in the ART-Pi's internal flash: it
maps the QSPI flash and jumps to the vector table at 0x90000000.
_Avoid_: "the bootloader" (ambiguous with MCUboot or a Zephyr first-stage)

**Broker heap**:
The memory NanoNNG's allocator serves the broker's data plane from — on the
ART-Pi, a `k_heap` over the SDRAM region, not the internal SRAM.
_Avoid_: "the heap" (ambiguous with the kernel heap and the libc arena)

**Wi-Fi link supervisor**:
The ART-Pi demo's thread that watches the Wi-Fi join state after the bounded
boot-time association and re-associates (then re-requests a lease) when the
link is gone.
_Avoid_: "watchdog" (that is the hardware timer, and it resets the board)

## Relationships

- The **Zephyr broker demo** family has three siblings: qemu_x86
  (simulation), ESP32-S3, and ART-Pi.
- Each **Zephyr broker demo** claims one **Acceptance tier**.
- The ART-Pi demo starts through the **ART-Pi factory bootloader**.
- The **Broker heap** lives in SDRAM; the kernel heap and libc arena stay in
  internal SRAM.
- The ART-Pi demo's **Wi-Fi link supervisor** polls the driver's join state; it
  does not depend on the driver's disconnect event, which only an explicit
  disconnect raises.

## Example dialogue

> **Dev:** "Does the ART-Pi demo need RT-Thread?"
> **Domain expert:** "No — ART-Pi is the board. The demo is a
> **Zephyr broker demo**, same as the ESP32-S3 sibling."

## Flagged ambiguities

- The porting brief says "RT-Thread ART-Pi". Resolved: that names the board
  (Ruiside is RT-Thread's hardware arm); the port runs Zephyr on it, not
  NanoMQ on the RT-Thread kernel.
