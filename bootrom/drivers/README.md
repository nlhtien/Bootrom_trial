# Hardware Drivers

This directory contains stub implementations of hardware drivers used by the BootROM.

## Contents

- `flash.c/h`: Flash memory driver (QSPI/NAND interface)
- `uart.c/h`: UART driver for debugging output
- `watchdog.c/h`: Watchdog timer driver

## Implementation Notes

These are currently stub implementations. In production:
- Flash driver should interface with the actual flash controller
- UART driver should configure hardware UART peripherals
- Watchdog driver should control the hardware watchdog timer

## Usage

Drivers are initialized in `main.c` and used for:
- Reading boot images from flash
- Outputting debug messages via UART
- Managing watchdog resets</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/bootrom/drivers/README.md