# Architecture-Specific Code

This directory contains architecture-specific code for ARM Cortex-R5F.

## Contents

  - `arm/r5f/`: ARM Cortex-R5F specific implementation
  - `startup.S`: Assembly startup code for Stages 1 & 2 (hardware init, watchdog disable, stack setup)
  - `linker.ld`: Linker script defining memory layout
  - `sys_registers.h`: System register definitions
