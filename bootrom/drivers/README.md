# Hardware Drivers

This directory contains implementations of hardware drivers used by the BootROM.

## Contents

- `flash.c/h`: Basic Flash memory driver (QSPI/NAND interface)
- `sd.c/h`: Basic SD memory driver (SD Card interface)
- `uart.c/h`: UART driver for debugging output (QEMU and HW)
- `watchdog.c/h`: Basic Watchdog timer driver

## Usage

Drivers are initialized in `main.c` and used for:
- Reading boot images from flash/SD
- Outputting debug messages via UART/QEMU
- Managing watchdog resets