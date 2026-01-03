# BootROM Testing Guide

This document provides instructions for testing the BootROM firmware using QEMU, including basic execution and GDB debugging. It covers key test scenarios, expected outputs, and troubleshooting tips.

## Prerequisites

- QEMU ARM emulator installed (`qemu-system-arm`)
- ARM GCC toolchain (for rebuilding if needed)
- GDB with ARM support (`arm-none-eabi-gdb`) for debugging
- Built BootROM binary (`bootrom.bin` in `build/` directory)

## Basic QEMU Execution

Run the BootROM in QEMU without GUI:

```bash
cd /home/kora/tiennlh/project/Bootrom_trial/build
qemu-system-arm -M none -cpu cortex-r5 -bios bootrom.bin -nographic -serial stdio -monitor none
```

- `-M none`: Bare-metal machine
- `-cpu cortex-r5`: ARM Cortex-R5F CPU
- `-bios bootrom.bin`: Load binary at reset vector (0x0)
- `-nographic`: No GUI
- `-serial stdio`: UART output to terminal
- `-monitor none`: Disable QEMU monitor to avoid conflicts

## GDB Debugging

For debugging the BootROM in QEMU:

1. Start QEMU with GDB server:
```bash
qemu-system-arm -M none -cpu cortex-r5 -bios bootrom.bin -nographic -serial stdio -monitor none -s -S
```
   - `-s`: Listen on TCP port 1234 for GDB
   - `-S`: Pause execution at start (wait for GDB attach)

2. In another terminal, start GDB:
```bash
arm-none-eabi-gdb bootrom.elf
```

3. In GDB console:
```gdb
target remote localhost:1234
break main
continue
```

- Load symbols from `bootrom.elf` for debugging
- Set breakpoints (e.g., `break crypto_init`, `break secure_boot_verify`)
- Step through code with `step` or `next`

## Test Cases

### 1. **Boot Sequence Test**
   - **Description**: Verify the 4-stage boot process executes without errors.
   - **Command**: Basic QEMU command above.
   - **Expected Output**:
     ```
     BootROM: Hardware initialization complete
     BootROM: Crypto subsystem initialized
     BootROM: Secure boot verification passed
     BootROM: Image decryption successful
     BootROM: Handing off to application...
     ```
   - **Pass Criteria**: No crashes, all stages print success messages.

### 2. **Crypto Initialization Test**
   - **Description**: Check MbedTLS initialization and key loading.
   - **Command**: Same as basic, or add GDB breakpoint at `crypto_init`.
   - **Expected Output**:
     ```
     Crypto: MbedTLS initialized
     Crypto: Keys loaded successfully
     ```
   - **Pass Criteria**: No "failed" messages, GDB shows successful memory allocation.

### 3. **Secure Boot Verification Test**
   - **Description**: Test image signature verification (RSA) and anti-rollback.
   - **Command**: Use GDB to inspect `secure_boot_verify` function.
   - **Expected Output**:
     ```
     Secure Boot: Image header parsed
     Secure Boot: Signature verification passed
     Secure Boot: Anti-rollback check passed
     ```
   - **Pass Criteria**: Verification succeeds; fails gracefully on invalid signatures.

### 4. **AES Decryption Test**
   - **Description**: Verify AES CBC decryption of the image.
   - **Command**: GDB breakpoint at `crypto_aes_decrypt`.
   - **Expected Output**:
     ```
     Crypto: AES decryption completed
     ```
   - **Pass Criteria**: Decryption completes without errors; check decrypted data integrity.

### 5. **Error Handling Test**
   - **Description**: Test failure scenarios (invalid image, crypto errors).
   - **Command**: Modify image or keys in GDB, or use corrupted binary.
   - **Expected Output**:
     ```
     BootROM: Error - Invalid signature
     BootROM: Halting system
     ```
   - **Pass Criteria**: System halts safely, no undefined behavior.

### 6. **Memory Usage Test**
   - **Description**: Check memory regions don't overflow.
   - **Command**: Run and monitor QEMU output or GDB memory inspection.
   - **Expected Output**: Linker memory usage (BOOT_ROM < 256KB, OCRAM < 1MB, TCM < 64KB).
   - **Pass Criteria**: No out-of-memory errors.

## Expected Outputs Summary

- **Successful Boot**: Sequential stage messages, ends with handoff.
- **Crypto Success**: "initialized", "loaded", "passed" messages.
- **Errors**: "Error - [reason]", system halt.
- **GDB**: Breakpoints hit at expected functions, registers/memory inspectable.

## Troubleshooting

- **QEMU Crashes**: Check binary integrity (`arm-none-eabi-objdump -d bootrom.elf`).
- **No Output**: Ensure UART is configured; add `uart_puts("Test\n");` in code.
- **GDB Connection Fails**: Verify port 1234 is free, QEMU started with `-s -S`.
- **Crypto Fails**: Check key provisioning in `crypto_wrapper.c`.
- **Memory Issues**: Review linker script and static buffers.

## Notes

- Current code has stub implementations (e.g., flash read returns dummy data). Implement fully for real testing.
- Add more UART logging for better observability.
- For automated testing, consider scripts to parse QEMU output.</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/README_TEST.md