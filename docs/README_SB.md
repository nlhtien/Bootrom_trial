# Secure Boot Deployment Guide

This guide provides complete instructions for deploying and using the secure boot system on ARM Cortex-R5F devices. It covers everything from development to production deployment.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Key Management](#key-management)
3. [BootROM Programming](#bootrom-programming)
4. [Secure Storage Provisioning](#secure-storage-provisioning)
5. [Image Signing Workflow](#image-signing-workflow)
6. [Testing and Validation](#testing-and-validation)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)

## Development Environment Setup

### Required Tools

#### Hardware Tools
- **JTAG Debugger**: Segger J-Link, OpenOCD, or equivalent
- **Flash Programmer**: For programming BootROM to device ROM
- **OTP Programmer**: For provisioning keys to eFuse/OTP

#### Software Tools
- **ARM GCC Toolchain**: `arm-none-eabi-gcc` (9.0+)
- **CMake**: 3.15+
- **OpenSSL**: For key generation and testing
- **QEMU**: For testing (`qemu-system-arm`)
- **GDB**: For debugging

### Environment Setup

```bash
# Install ARM toolchain (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install gcc-arm-none-eabi cmake build-essential

# Install OpenSSL
sudo apt-get install openssl libssl-dev

# Install QEMU
sudo apt-get install qemu-system-arm

# Clone repository
git clone <repository-url>
cd Bootrom_trial
git submodule update --init --recursive
```

## Key Management

### Key Types and Usage

| Key Type | Purpose | Storage Location | Size | Generation |
|----------|---------|------------------|------|------------|
| **RSA Private Key** | Signing boot images | Host PC (secure) | 2048-bit | Development/HSM |
| **RSA Public Key** | Verifying signatures | Device OTP/eFuse | 256 bytes (DER) | Derived from private |
| **AES Key** | Encrypting boot images | Device OTP/eFuse | 256-bit | Random generation |

### Key Generation (Development)

```bash
# Create secure directory for keys
mkdir -p keys && cd keys

# Generate RSA keypair
openssl genrsa -out rsa_private.pem 2048

# Extract public key in DER format (for device)
openssl rsa -in rsa_private.pem -pubout -outform DER -out rsa_public.der

# Generate AES key
openssl rand -out aes_key.bin 32

# Verify key sizes
ls -la *.pem *.der *.bin
```

### Key Generation (Production - HSM)

```bash
# Using HSM (example with PKCS#11)
pkcs11-tool --module /usr/lib/libsofthsm2.so \
  --keypairgen --key-type rsa:2048 \
  --label "bootrom-signing-key" \
  --id 01

# Extract public key
pkcs11-tool --module /usr/lib/libsofthsm2.so \
  --read-object --type pubkey --label "bootrom-signing-key" \
  --output-file rsa_public.der
```

### Key Storage Requirements

#### Development Keys
- Store in encrypted password manager
- Use separate keys for testing/production
- Rotate keys regularly
- Backup in secure location

#### Production Keys
- Generate in secure facility with multiple personnel
- Store private keys in HSM
- Distribute public keys to manufacturing
- Implement key revocation procedures

## BootROM Programming

### Step 1: Build BootROM

```bash
# Configure for production (no semihosting)
cmake -B build -S .

# Build
cmake --build build

# Verify output
ls -la build/
# bootrom.bin (37KB), bootrom.elf, bootrom.hex, bootrom.dis
```

### Step 2: Program to Device ROM

#### Using JTAG Programmer
```bash
# OpenOCD example
openocd -f interface/jlink.cfg -f target/cortex-r5.cfg \
  -c "init" \
  -c "halt" \
  -c "flash write_image erase build/bootrom.bin 0x00000000" \
  -c "reset run" \
  -c "shutdown"
```

#### Using Flash Programmer Tool
```bash
# Manufacturer-specific tool
# Example for TI devices:
ccs_flash_programmer -device AM65x -flash_type ROM \
  -input_file build/bootrom.bin -start_addr 0x00000000
```

### Step 3: Verify Programming

```bash
# Read back and compare
openocd -f interface/jlink.cfg -f target/cortex-r5.cfg \
  -c "init" \
  -c "halt" \
  -c "dump_image readback.bin 0x00000000 0x10000" \
  -c "shutdown"

# Compare
diff build/bootrom.bin readback.bin
```

## Secure Storage Provisioning

### OTP/eFuse Memory Map

```
OTP Region Layout (Example):
0x0000 - 0x00FF: RSA Public Key (256 bytes)
0x0100 - 0x011F: AES Key (32 bytes)
0x0120 - 0x0123: Anti-rollback Counter (4 bytes)
0x0124 - 0x0127: Boot Configuration (4 bytes)
```

### Provisioning Keys

#### Method 1: Manufacturing Programmer
```bash
# Program RSA public key
otp_programmer -device /dev/ttyUSB0 \
  -write -addr 0x0000 -file rsa_public.der

# Program AES key
otp_programmer -device /dev/ttyUSB0 \
  -write -addr 0x0100 -file aes_key.bin

# Set anti-rollback counter
otp_programmer -device /dev/ttyUSB0 \
  -write -addr 0x0120 -value 0x00000001
```

#### Method 2: JTAG Interface
```bash
# Using OpenOCD
openocd -f interface/jlink.cfg -f target/cortex-r5.cfg \
  -c "init" \
  -c "halt" \
  -c "mww 0xE0000000 0xDEADBEEF" \  # Unlock OTP
  -c "load_image rsa_public.der 0xE0000100" \
  -c "load_image aes_key.bin 0xE0000200" \
  -c "mww 0xE0000300 1" \  # Set counter
  -c "mww 0xE0000000 0x00000000" \  # Lock OTP
  -c "reset run" \
  -c "shutdown"
```

### Verification

```bash
# Read back keys (if OTP allows reading)
otp_programmer -device /dev/ttyUSB0 \
  -read -addr 0x0000 -size 256 -output verify_rsa.der

# Compare
diff rsa_public.der verify_rsa.der
```

## Image Signing Workflow

### Build Signing Tool

```bash
# Build with OpenSSL (recommended)
cd tools/boot_signer
cmake -DUSE_OPENSSL=ON -B build -S .
cmake --build build
```

### Sign Boot Images

```bash
# Sign FSBL (First Stage Boot Loader)
./tools/boot_signer/build/boot_signer \
  fsbl.bin signed_fsbl.img rsa_private.pem aes_key.bin

# Sign U-Boot
./tools/boot_signer/build/boot_signer \
  u-boot.bin signed_u-boot.img rsa_private.pem aes_key.bin

# Sign Linux kernel (if applicable)
./tools/boot_signer/build/boot_signer \
  zImage signed_zImage.img rsa_private.pem aes_key.bin
```

### Image Packaging

```bash
# Create boot package
mkdir boot_package
cp signed_fsbl.img boot_package/
cp signed_u-boot.img boot_package/
cp rsa_public.der boot_package/  # For verification
cp aes_key.bin boot_package/     # For debugging only

# Create manifest
cat > boot_package/manifest.txt << EOF
Boot Package Contents:
- signed_fsbl.img: First Stage Boot Loader
- signed_u-boot.img: U-Boot bootloader
- rsa_public.der: RSA public key for verification
- aes_key.bin: AES key (remove in production)

Signing Key Fingerprint:
$(openssl rsa -in rsa_private.pem -pubout -outform DER | openssl dgst -sha256)

Package Created: $(date)
EOF
```

## Testing and Validation

### Unit Testing

```bash
# Test BootROM in QEMU
qemu-system-arm -M virt -kernel build/bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000 \
  -nographic

# Expected output:
# === BootROM Starting (Stage 3 & 4) ===
# Crypto subsystem initialized
# Boot image verified and decrypted successfully
# Handoff: Simulating jump to FSBL at 0x...
```

### Integration Testing

```bash
# Test with GDB
qemu-system-arm -M virt -kernel build/bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000 \
  -s -S &

# Connect GDB
arm-none-eabi-gdb build/bootrom.elf \
  -ex "target remote localhost:1234" \
  -ex "break main" \
  -ex "continue"
```

### Security Testing

```bash
# Test with invalid signature
./tools/boot_signer/build/boot_signer \
  fsbl.bin invalid.img wrong_private.pem aes_key.bin

qemu-system-arm -M virt -kernel build/bootrom.elf \
  -device loader,file=invalid.img,addr=0x10000000

# Should output: ERROR: Secure boot verification failed
```

### Performance Testing

```bash
# Measure boot time
time qemu-system-arm -M virt -kernel build/bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000 \
  -nographic
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] BootROM built and tested
- [ ] Keys generated in secure environment
- [ ] Signing tool validated
- [ ] Boot images signed with production keys
- [ ] Manufacturing equipment programmed
- [ ] Test devices available

### Manufacturing Process

#### Phase 1: Device Programming
```bash
# 1. Program BootROM to ROM
flash_programmer -input build/bootrom.bin -addr 0x00000000

# 2. Provision keys to OTP
otp_programmer -write -addr 0x0000 -file rsa_public.der
otp_programmer -write -addr 0x0100 -file aes_key.bin

# 3. Program signed boot images to flash
flash_programmer -input signed_fsbl.img -addr 0x10000000
flash_programmer -input signed_u-boot.img -addr 0x10100000
```

#### Phase 2: Verification
```bash
# Power cycle device
# Verify secure boot sequence
# Check for secure boot success indicators
```

#### Phase 3: Packaging
```bash
# Label device as "Secure Boot Enabled"
# Include security certificates
# Document key fingerprints
```

### Post-Deployment

#### Monitoring
- Monitor for secure boot failures
- Track anti-rollback counter updates
- Log security events

#### Updates
- Plan secure firmware update mechanism
- Implement key rotation procedures
- Maintain secure key backups

## Troubleshooting

### BootROM Won't Start

**Symptom:** Device doesn't boot, no output
**Possible Causes:**
- BootROM not programmed correctly
- Invalid vector table
- Memory corruption

**Debug Steps:**
```bash
# Check ROM programming
openocd -c "dump_image rom.bin 0x00000000 0x10000"
diff build/bootrom.bin rom.bin

# Test with QEMU
qemu-system-arm -M virt -kernel build/bootrom.elf -nographic
```

### Signature Verification Fails

**Symptom:** "Secure boot verification failed"
**Possible Causes:**
- Wrong public key in OTP
- Image signed with wrong private key
- Corrupted signature

**Debug Steps:**
```bash
# Verify keys match
openssl rsa -in rsa_private.pem -pubout -outform DER | diff - rsa_public.der

# Manual signature verification
# Extract signature from image and verify with OpenSSL
```

### Decryption Fails

**Symptom:** Boot hangs after signature verification
**Possible Causes:**
- Wrong AES key in OTP
- Corrupted IV in image header
- Padding errors

**Debug Steps:**
```bash
# Test AES decryption manually
openssl enc -d -aes-256-cbc -in encrypted.bin -out decrypted.bin \
  -K $(hexdump -e '16/1 "%02x"' aes_key.bin) \
  -iv $(hexdump -e '16/1 "%02x"' iv.bin)
```

### QEMU Testing Issues

**Symptom:** Works in QEMU but fails on hardware
**Possible Causes:**
- Memory map differences
- Peripheral differences
- Timing issues

**Debug Steps:**
```bash
# Use QEMU with hardware emulation
qemu-system-arm -M xilinx-zynqmp -kernel build/bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000
```

## Security Best Practices

### Key Management
- **Never store private keys** on development machines
- **Use HSM** for production key operations
- **Implement key rotation** every 6-12 months
- **Multi-person approval** for key operations

### Secure Boot Chain
- **Verify entire chain**: BootROM → FSBL → OS Loader → Kernel
- **Use secure update mechanisms** for firmware updates
- **Implement remote attestation** for device verification
- **Monitor security events** continuously

### Compliance
- **Document all security procedures**
- **Maintain audit trails** for key operations
- **Regular security assessments**
- **Follow industry standards** (NIST, etc.)

## Support and Resources

### Documentation
- [MbedTLS Documentation](https://mbed-tls.readthedocs.io/)
- [ARM Secure Boot Guidelines](https://developer.arm.com/documentation)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

### Tools
- [OpenOCD](http://openocd.org/)
- [QEMU](https://www.qemu.org/)
- [ARM GCC](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm)

### Security References
- [NIST SP 800-193 - Platform Firmware Resiliency](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf)
- [UEFI Secure Boot](https://uefi.org/specifications)

---

**Remember:** Security is a process, not a product. Regular updates, monitoring, and audits are essential for maintaining security over time.