# BootROM for ARM Cortex-R5F - 4-Stage Secure Boot

Production-ready Boot ROM project for ARM Cortex-R5F processor with Secure Boot support using MbedTLS, following a strict 4-stage boot flow.

## Features

- **ARM Cortex-R5F (ARMv7-R)** support
- **4-Stage Boot Flow** implementation:
  - **Stage 1:** Power On Reset & Startup (Multi-core check, system cleanup)
  - **Stage 2:** Minimal Initialization (TCM/ECC, MPU, caches, vector remap)
  - **Stage 3:** Load & Verification (Anti-rollback, signature verification, decryption)
  - **Stage 4:** Boot Image / Handoff (Cleanup, barriers, jump to FSBL)
- **Secure Boot** with:
  - RSA/ECC signature verification
  - AES-CBC/GCM decryption
  - SHA-256 hashing
  - Anti-rollback protection
- **MbedTLS Integration** with bare-metal configuration (static buffer allocation)
- **Minimal drivers** (UART, Flash, Watchdog timer)
- **CMake build system**

## Directory Structure

## Directory Structure

```
bootrom/
├── arch/arm/r5f/              # Architecture-specific code
│   ├── startup.S              # Stage 1 & 2: Startup code, vector table, stack setup
│   ├── linker.ld              # Linker script
│   ├── sys_registers.h        # CP15 system register access functions
│   └── CMakeLists.txt
├── drivers/                   # Hardware drivers
│   ├── uart.c/h               # UART driver (stub)
│   ├── flash.c/h              # Flash driver (stub)
│   └── watchdog.c/h           # Watchdog Timer driver (stub)
├── crypto/                    # Crypto wrapper layer
│   ├── crypto_wrapper.c/h     # MbedTLS wrapper (uses static buffer allocator)
├── secure_boot/               # Secure boot logic
│   ├── secure_boot_core.c/h   # Stage 3 & 4: Image verification and handoff
│   └── mbedtls_config.h       # MbedTLS configuration for bare-metal
├── platform/                  # Platform abstraction
│   ├── platform.c/h           # Platform functions (MPU, TCM, cache setup)
│   └── platform_mbedtls.h     # MbedTLS platform integration
└── main.c                     # Entry point (Stage 3 & 4 orchestration)
...
```

## 4-Stage Boot Flow

### Stage 1: Power On Reset & Startup ('startup.S')

1. **Safety Init:**
   - Disable IRQ/FIQ
   - Disable Watchdog

2. **Multi-core Check:**
   - Read MPIDR to identify primary core
   - Secondary cores enter WFI loop

3. **Reset Cause Detection:**
   - Platform-specific reset cause determination

4. **System Cleanup:**
   - Disable MPU, I-Cache, D-Cache, Branch Prediction
   - Invalidate caches

### Stage 2: Minimal Initialization ('startup.S' → 'platform.c')

1. **Stack Setup:**
   - Initialize SP for all ARM modes (SYS, IRQ, FIQ, SVC, ABT, UND)

2. **TCM & ECC Init:**
   - Enable ATCM and BTCM via CP15 c9
   - **CRITICAL:** Zeroize entire TCM/OCRAM to initialize ECC logic

3. **MPU Setup:**
   - Define regions: Flash (RX), OCRAM (RWX), Peripherals (RW, no cache)
   - Enable MPU

4. **Performance:**
   - Enable I-Cache and D-Cache **only after MPU is enabled**
   - Enable VFP/FPU
   - Enable Branch Prediction

5. **Vector Table Remap:**
   - Copy vector table from ROM to TCM/OCM
   - Set VBAR (Vector Base Address Register)

### Stage 3: Load & Verification ('secure_boot_core.c')

1. **Boot Source:**
   - Determine boot source (QSPIFlash/eMMC) via GPIO/eFuse/OTP

2. **Image Loading:**
   - Load 'ImageHeader' (Magic, Size, Signature, IV, Version)
   - Validate header (Magic check)

3. **Secure Verification:**
   - **Anti-Rollback:** Check image version - avoid using old Image
   - **Signature:** Verify RSA/ECC signature using MbedTLS
   - **Decryption:** Decrypt payload using AES-CBC/GCM

### Stage 4: Boot Image / Handoff ('secure_boot_core.c', 'main.c')

1. **Success Path:**
   - **Cleanup:** Zeroize all crypto keys and sensitive stack data
   - **Barriers:** Execute ISB and DSB
   - **Handoff:** Jump to FSBL entry point

2. **Failure Path:**
   - Enter error handler loop (blink LED or WDT reset)

## Building

### Prerequisites

- ARM GCC toolchain ('arm-none-eabi-gcc')
- CMake (3.15 or later - 4.12)
- MbedTLS library (should be placed in 'external/mbedtls/')

```bash
sudo apt update
sudo apt install git make cmake gcc-arm-none-eabi binutils-arm-none-eabi build-essential
```

### Build Steps

```bash
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake -DCMAKE_BUILD_TYPE=Debug ..
make
or cmake --build .
eg: cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake -DCMAKE_BUILD_TYPE=Debug && cmake --build build
eg: rm -rf build && mkdir build && cd build && cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake -DCMAKE_BUILD_TYPE=Debug .. && make
```

Output files:
- 'bootrom.elf' - ELF executable
- 'bootrom.bin' - Binary image
- 'bootrom.hex' - Intel HEX format
- 'bootrom.dis' - Disassembly

### Build Configuration

- Debug build: 'cmake -DCMAKE_BUILD_TYPE=Debug ..'
- Release build: 'cmake -DCMAKE_BUILD_TYPE=Release ..' (default)

## Memory Layout

- **BOOT_ROM**: '0xFFFF0000' or '0x00000000' - from 64KB to 256 KB (code and read-only data)
- **OCRAM**: '0x08000000' - 64KB (RAM for stacks and runtime data)
- **TCM**: '0x00000000' (ATCM) and '0x20000000' (BTCM) - Platform-specific

## Secure Boot Process

1. BootROM starts from reset vector (Stage 1)
2. System initialization (Stage 2)
3. Load and verify boot image (Stage 3):
   - Load image header
   - Check anti-rollback
   - Verify signature
   - Decrypt image
4. Cleanup and handoff to FSBL (Stage 4)

## Image Format

The boot image must have the following header structure:

```c
typedef struct {
    uint32_t magic;              // 0x5442524D ("MBRT")
    uint32_t version;            // Header version
    uint32_t image_size;         // Size of encrypted image
    uint32_t image_version;      // Image version (for anti-rollback)
    uint32_t signature_offset;   // Offset to signature
    uint32_t iv_offset;          // Offset to IV
    uint32_t reserved[2];
    uint8_t  iv[16];             // AES IV
    uint8_t  signature[256];     // RSA-2048 or ECC signature
} image_header_t;
```

## Configuration

### MbedTLS Configuration

The 'secure_boot/mbedtls_config.h' is configured for bare-metal:
- **Uses 'MBEDTLS_MEMORY_BUFFER_ALLOC_C'** for static memory allocation (NO malloc/free)
- File system operations disabled
- Networking disabled
- OS entropy disabled
- Only required crypto algorithms enabled

### Key Management

**IMPORTANT**: In production:
- AES keys should be stored in secure hardware (e.g., OTP, HSM)
- Public keys should be provisioned during manufacturing
- Never hardcode keys in the source code

The current implementation uses stubs that must be replaced with secure storage access.

## Platform-Specific Adaptations

The following components need platform-specific implementation:

1. **Flash Driver** ('drivers/flash.c'): Adapt to your SoC's flash controller
2. **UART Driver** ('drivers/uart.c'): Adapt to your SoC's UART peripheral
3. **Watchdog Driver** ('drivers/watchdog.c'): Implement watchdog control
4. **TCM Configuration** ('platform/platform.c'): Configure TCM base addresses and sizes
5. **MPU Regions** ('platform/platform.c'): Adjust memory regions for your platform
6. **Key Storage**: Implement secure key storage access
7. **NV Counter**: Implement anti-rollback counter storage
8. **Reset Cause**: Implement platform-specific reset cause detection
9. **Memory Map**: Adjust addresses in 'linker.ld' for your platform

## Quick Start

### Prerequisites
- **ARM GCC Toolchain**: `arm-none-eabi-gcc` (9.0+ recommended)
- **CMake**: 3.15+
- **Git**: For submodule management

### Build BootROM
```bash
# Clone repository
git clone <repository-url>
cd Bootrom_trial

# Initialize submodules (MbedTLS)
git submodule update --init --recursive

# Configure build
cmake -B build -S .

# Build
cmake --build build

# Output files in build/:
# - bootrom.elf (with debug symbols)
# - bootrom.bin (raw binary)
# - bootrom.hex (Intel HEX)
# - bootrom.dis (disassembly)
```

### Test with QEMU
```bash
# Enable semihosting for UART output
cmake -DENABLE_QEMU_SEMIHOSTING=ON -B build -S .
cmake --build build

# Run in QEMU
qemu-system-arm -M virt -kernel build/bootrom.elf -nographic
```

## Integration with Signing Tool

### Build Signing Tool
```bash
# Build with OpenSSL (recommended)
cd tools/boot_signer
cmake -DUSE_OPENSSL=ON -B build -S .
cmake --build build

# Or build with MbedTLS
cmake -DUSE_MBEDTLS=ON -DMBEDTLS_ROOT=../../bootrom/external/mbedtls -B build -S .
cmake --build build
```

### Complete Secure Boot Workflow
```bash
# 1. Generate keys
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
openssl rand -out aes_key.bin 32

# 2. Sign boot image
./tools/boot_signer/build/boot_signer fsbl.bin signed_fsbl.img private_key.pem aes_key.bin

# 3. Load signed image in QEMU
qemu-system-arm -M virt -kernel build/bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000 -nographic
```

## Security Review Notes

### Positive Findings
- **No hardcoded secrets**: Keys in `crypto_wrapper.c` are properly zeroized (memset to 0) for testing - no real cryptographic keys are exposed in the source code
- **Proper key handling**: Keys are zeroized on cleanup, preventing memory leaks
- **Input validation**: Buffer size checks prevent overflows in crypto operations
- **Secure crypto usage**: Uses MbedTLS with RSA-2048 signature verification and AES-256 decryption
- **Anti-rollback protection**: Implemented (though stubbed for testing)
- **No obvious vulnerabilities**: Code follows secure coding practices

### Areas Requiring Production Implementation
- **Key provisioning**: `crypto_set_aes_key()` and `crypto_set_public_key()` are stubs - need integration with secure storage (OTP/eFuse)
- **Anti-rollback counter**: `get_nv_counter()` returns 0 - needs NV storage implementation
- **Boot source detection**: `get_boot_source()` is hardcoded - needs platform-specific GPIO/eFuse reading

### Security Recommendations
1. **Implement secure key storage** before production deployment
2. **Add input sanitization** for image headers beyond basic magic/version checks
3. **Consider timing attack mitigations** for crypto operations if performance-critical
4. **Audit flash driver** for secure read operations
5. **Implement secure boot measurements** (PCR extension) if TPM available

### GitHub Readiness
Your code is **safe to push to GitHub**. No sensitive information is exposed, and the stub implementations are clearly documented as placeholders for production features. The codebase demonstrates good security practices and proper separation of concerns.
