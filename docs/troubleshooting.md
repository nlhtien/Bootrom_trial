# BootROM Troubleshooting Guide

## Build Issues

### CMake Configuration Errors

#### "Could not find ARM GCC toolchain"
**Symptoms:**
```
-- The C compiler identification is unknown
-- The CXX compiler identification is unknown
CMake Error at CMakeLists.txt:XX: The CMAKE_C_COMPILER:
  arm-none-eabi-gcc
  is not a full path and was not found in the PATH.
```

**Solutions:**
1. Install ARM GCC toolchain:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install gcc-arm-none-eabi

   # macOS
   brew install arm-none-eabi-gcc

   # Windows: Download from developer.arm.com
   ```

2. Add to PATH:
   ```bash
   export PATH=$PATH:/path/to/arm-none-eabi-gcc/bin
   ```

3. Verify installation:
   ```bash
   arm-none-eabi-gcc --version
   ```

#### "MbedTLS submodule not initialized"
**Symptoms:**
```
CMake Error: MbedTLS headers not found
```

**Solutions:**
```bash
# Initialize submodules
git submodule update --init --recursive

# Update to latest
git submodule update --remote
```

### Compilation Errors

#### "undefined reference to `mbedtls_*` functions"
**Symptoms:**
```
undefined reference to `mbedtls_rsa_init'
```

**Solutions:**
1. Check MbedTLS configuration in `bootrom/secure_boot/mbedtls_config.h`
2. Ensure all required MbedTLS modules are enabled
3. Verify CMake finds MbedTLS sources correctly

#### "region `ROM' overflowed"
**Symptoms:**
```
region `ROM' overflowed by XXX bytes
```

**Solutions:**
1. Check `linker.ld` memory regions
2. Reduce MbedTLS features in `mbedtls_config.h`
3. Optimize code size with `-Os` flag
4. Review static buffer sizes

## Runtime Issues

### QEMU Testing Problems

#### "qemu-system-arm: No machine specified"
**Symptoms:**
```
qemu-system-arm: No machine specified, and there is no default
```

**Solutions:**
```bash
# Use virt machine for Cortex-R5F
qemu-system-arm -M virt -kernel bootrom.elf

# For specific SoC emulation
qemu-system-arm -M xilinx-zynqmp-rpu -kernel bootrom.elf
```

#### UART output not visible
**Symptoms:** No console output in QEMU

**Solutions:**
1. Enable semihosting:
   ```bash
   cmake -DENABLE_QEMU_SEMIHOSTING=ON ..
   ```

2. Add QEMU options:
   ```bash
   qemu-system-arm -M virt -kernel bootrom.elf -nographic
   ```

3. Check UART configuration in `platform.c`

### Secure Boot Verification Failures

#### "SECURE_BOOT_INVALID_HEADER"
**Symptoms:** Boot fails with invalid header error

**Causes & Solutions:**
1. **Wrong image format:**
   - Verify image created with signing tool
   - Check magic number (0x5442524D)

2. **Corrupted header:**
   - Regenerate signed image
   - Check flash integrity

#### "SECURE_BOOT_SIGNATURE_FAIL"
**Symptoms:** RSA signature verification fails

**Causes & Solutions:**
1. **Wrong public key:**
   - Ensure BootROM has correct RSA public key
   - Match keys between signing tool and BootROM

2. **Key format mismatch:**
   - Use DER format for keys
   - Verify key conversion: `openssl rsa -in key.pem -outform DER -out key.der`

3. **Image corruption:**
   - Check flash read operations
   - Verify image integrity before signing

#### "SECURE_BOOT_DECRYPT_FAIL"
**Symptoms:** AES decryption fails

**Causes & Solutions:**
1. **Wrong AES key:**
   - Ensure same AES key in signing tool and BootROM
   - Check key format (32 bytes, binary)

2. **IV mismatch:**
   - Verify IV handling in signing/verification
   - Check for endianness issues

3. **Padding errors:**
   - Ensure PKCS#7 padding in signing tool
   - Check payload size alignment

#### "SECURE_BOOT_ROLLBACK_DETECTED"
**Symptoms:** Anti-rollback check fails

**Causes & Solutions:**
1. **NV counter not initialized:**
   - Set initial counter value in OTP/eFuse
   - Implement counter persistence

2. **Image version too low:**
   - Increase image version number
   - Check version field in image header

### Hardware Testing Issues

#### Flash Read Failures
**Symptoms:** Unable to read from external flash

**Solutions:**
1. Check flash initialization in `platform.c`
2. Verify QSPI pin connections
3. Test flash chip compatibility
4. Check voltage levels and timing

#### Watchdog Resets
**Symptoms:** System resets during boot

**Solutions:**
1. Increase watchdog timeout
2. Feed watchdog regularly during crypto operations
3. Disable watchdog for debugging
4. Check watchdog configuration

#### UART Communication Issues
**Symptoms:** No debug output

**Solutions:**
1. Verify UART pin connections
2. Check baud rate settings
3. Test UART loopback
4. Enable UART in platform init

## Signing Tool Issues

### Build Failures

#### "OpenSSL not found"
**Symptoms:**
```
Could NOT find OpenSSL
```

**Solutions:**
```bash
# Install OpenSSL dev libraries
sudo apt-get install libssl-dev

# Or use MbedTLS backend
cmake -DUSE_MBEDTLS=ON ..
```

#### "MbedTLS headers not found"
**Symptoms:**
```
fatal error: mbedtls/pk.h: No such file or directory
```

**Solutions:**
1. Fix MbedTLS path in CMakeLists.txt:
   ```cmake
   set(MBEDTLS_ROOT "${CMAKE_SOURCE_DIR}/../../external/mbedtls")
   ```

2. Ensure MbedTLS submodule is initialized

### Runtime Errors

#### "Cannot open private key file"
**Solutions:**
1. Check file path and permissions
2. Verify key format (PEM for OpenSSL, DER for MbedTLS)
3. Generate keys correctly:
   ```bash
   openssl genrsa -out private_key.pem 2048
   openssl rsa -in private_key.pem -outform DER -out private_key.der
   ```

#### "AES key must be 32 bytes"
**Solutions:**
```bash
# Generate correct size AES key
openssl rand -out aes_key.bin 32

# Verify size
ls -la aes_key.bin  # Should be 32 bytes
```

#### "Signature generation failed"
**Solutions:**
1. Verify private key validity
2. Check OpenSSL/MbedTLS installation
3. Ensure sufficient entropy for crypto operations

## Performance Issues

### Slow Boot Times
**Symptoms:** Boot takes longer than expected

**Optimization Steps:**
1. **Enable hardware crypto acceleration** (if available)
2. **Use faster flash memory**
3. **Optimize MbedTLS configuration** - disable unused features
4. **Implement DMA for memory operations**
5. **Cache frequently used data**

### Memory Issues
**Symptoms:** Stack overflow or heap exhaustion

**Solutions:**
1. **Increase stack size** in `linker.ld`
2. **Use static allocation** instead of dynamic
3. **Reduce buffer sizes** where possible
4. **Profile memory usage** with debugger

## Security Issues

### Key Management Problems
**Symptoms:** Keys not loading correctly

**Solutions:**
1. **Verify key formats:**
   - RSA: DER encoded
   - AES: 32 bytes binary

2. **Check secure storage:**
   - OTP/eFuse programming
   - Key backup and recovery

3. **Test key operations:**
   - Sign/verify test vectors
   - Encrypt/decrypt known data

### Tamper Detection
**Symptoms:** System doesn't detect tampering

**Debug Steps:**
1. Test with known good/bad images
2. Verify signature calculation
3. Check hash functions
4. Test AES encryption/decryption

## Advanced Debugging

### Using GDB with QEMU
```bash
# Start QEMU with GDB server
qemu-system-arm -M virt -kernel bootrom.elf -s -S

# Connect GDB in another terminal
arm-none-eabi-gdb bootrom.elf
(gdb) target remote localhost:1234
(gdb) continue
```

### Memory Dumping
```bash
# Dump memory regions
(gdb) x/64xb 0x20000000  # SRAM
(gdb) x/64xb 0x40000000  # Flash

# Dump image header
(gdb) x/128xb image_buffer
```

### Logging Enhancement
Add debug prints in critical functions:
```c
#define DEBUG_PRINT 1
#if DEBUG_PRINT
    uart_printf("DEBUG: Function %s, line %d\n", __func__, __LINE__);
#endif
```

## Common Pitfalls

### 1. Endianness Issues
- ARM is little-endian
- Ensure proper byte ordering for multi-byte values
- Test on actual hardware vs QEMU

### 2. Timing Dependencies
- Crypto operations have timing requirements
- Watchdog feeding during long operations
- Flash access timing constraints

### 3. Memory Alignment
- Ensure buffers are properly aligned
- Check linker script alignment requirements
- Use `__attribute__((aligned(4)))` for structures

### 4. Compiler Optimizations
- `-O0` for debugging, `-Os` for production
- Volatile keyword for hardware registers
- No optimization of security-critical code

## Getting Help

### Debug Information to Collect
1. **Build logs:** Full CMake and make output
2. **Runtime logs:** UART output or QEMU console
3. **GDB traces:** Backtraces and memory dumps
4. **Hardware details:** SoC, flash chip, connections
5. **Test cases:** Steps to reproduce the issue

### Support Resources
- Check existing issues in repository
- Review documentation in `docs/` folder
- Test with known working configurations
- Isolate problems to specific components

### Escalation Path
1. Check documentation and examples
2. Search existing issues/bugs
3. Create minimal reproduction case
4. Provide full debug information
5. Contact maintainers with complete details</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/docs/troubleshooting.md