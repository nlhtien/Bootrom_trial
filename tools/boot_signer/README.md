# BootROM Signing Tool

This tool creates signed boot images compatible with the BootROM secure boot implementation.

## Features

- **RSA-2048 Signature**: Signs boot images with RSA private keys
- **AES-256 Encryption**: Encrypts boot image payloads
- **PKCS#7 Padding**: Proper padding for AES-CBC
- **Random IV Generation**: Cryptographically secure initialization vectors
- **Cross-Platform**: Works on Linux, macOS, Windows

## Supported Crypto Libraries

### Option 1: MbedTLS (Recommended)
- Uses same crypto library as BootROM
- No external dependencies
- Consistent security implementation
- Build with: `cmake -DUSE_MBEDTLS=ON`

### Option 2: OpenSSL
- Mature, well-tested crypto library
- Standard in development environments
- Build with: `cmake -DUSE_OPENSSL=ON` (default)

## Build Instructions

### Prerequisites

#### For MbedTLS Build
- MbedTLS library (automatically uses BootROM's copy)

#### For OpenSSL Build
- OpenSSL development libraries
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS
brew install openssl

# CentOS/RHEL
sudo yum install openssl-devel
```

### Build Steps

```bash
# Navigate to signing tool directory
cd tools/boot_signer

# Create build directory
mkdir build && cd build

# Configure build (choose one option)
# Option 1: Use MbedTLS
cmake -DUSE_MBEDTLS=ON -DMBEDTLS_ROOT=../../../bootrom/external/mbedtls ..

# Option 2: Use OpenSSL (default)
cmake -DUSE_OPENSSL=ON ..

# Build
make

# Install (optional)
make install
```

## Usage

### Basic Usage
```bash
./boot_signer <input_binary> <output_image> <private_key> <aes_key>
```

### Parameters
- `input_binary`: Binary file to sign (e.g., `fsbl.bin`)
- `output_image`: Output signed image file (e.g., `signed_fsbl.img`)
- `private_key`: RSA private key file
- `aes_key`: AES-256 key file (32 bytes)

### Example
```bash
# Sign FSBL binary
./boot_signer fsbl.bin signed_fsbl.img private_key.der aes_key.bin

# Sign U-Boot
./boot_signer u-boot.bin signed_u-boot.img private_key.der aes_key.bin
```

## Key Generation

### For MbedTLS Version
```bash
# Generate RSA private key (DER format)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -outform DER -out private_key.der

# Extract public key for BootROM
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

# Generate AES key
openssl rand -out aes_key.bin 32
```

### For OpenSSL Version
```bash
# Generate RSA private key (PEM format)
openssl genrsa -out private_key.pem 2048

# Extract public key for BootROM
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der

# Generate AES key
openssl rand -out aes_key.bin 32
```

## Image Format

The output image follows the BootROM's expected format:

```
[Header (512 bytes)]
  Magic: "MBRT" (0x5442524D)
  Version: 1
  Image Size: <encrypted_payload_size>
  Image Version: <anti_rollback_version>
  IV: <16_bytes_aes_iv>
  Signature: <256_bytes_rsa_signature>

[Encrypted Payload]
  AES-256-CBC encrypted data with PKCS#7 padding
```

## Verification

### Manual Verification
```bash
# Extract and verify signature (example script needed)
python3 verify_signature.py signed_fsbl.img public_key.der

# Decrypt and verify payload
openssl enc -d -aes-256-cbc -in payload.enc -out payload.dec -K <aes_key_hex> -iv <iv_hex>
```

### BootROM Testing
Load the signed image into QEMU and verify BootROM accepts it:

```bash
qemu-system-arm -M virt -kernel bootrom.elf \
  -device loader,file=signed_fsbl.img,addr=0x10000000
```

## Security Notes

- **Private keys**: Never store in repository or device
- **AES keys**: Can be per-device or shared across images
- **Key rotation**: Implement regular key rotation
- **Secure storage**: Use HSM for production key operations

## Troubleshooting

### Common Errors

#### "Cannot open private key file"
- Ensure key file exists and has correct format
- For MbedTLS: Use DER format
- For OpenSSL: Use PEM format

#### "AES key must be 32 bytes"
- Generate AES key with: `openssl rand -out aes_key.bin 32`

#### "Signature generation failed"
- Verify private key is valid RSA-2048
- Check key format matches crypto library

#### BootROM rejects signed image
- Verify public key is loaded in BootROM
- Check image format matches BootROM expectations
- Verify signature with public key manually

### Debug Output
The tool provides verbose output showing each step:
- File loading
- Key loading
- Encryption
- Hashing
- Signing
- File writing

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Build and Sign Boot Images
  run: |
    # Build BootROM
    cmake --build build

    # Generate keys (for testing only)
    openssl genrsa -out test_key.pem 2048
    openssl rand -out test_aes.bin 32

    # Build signing tool
    cd tools/boot_signer
    cmake -B build -S .
    cmake --build build

    # Sign images
    ./build/boot_signer fsbl.bin signed_fsbl.img ../test_key.pem ../test_aes.bin
```

## Contributing

- Test with both MbedTLS and OpenSSL backends
- Add support for ECC signatures (secp256r1)
- Implement key derivation functions
- Add certificate chain support</content>

cd /home/kora/tiennlh/project/Bootrom_trial/tools/boot_signer/build && rm -rf * && cmake .. -DUSE_OPENSSL=ON -DUSE_MBEDTLS=OFF && make

cd /home/kora/tiennlh/project/Bootrom_trial/tools/boot_signer/build && ./boot_signer --help

<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/tools/boot_signer/README.md