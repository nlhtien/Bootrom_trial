# Changelog

All notable changes to the BootROM secure boot project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation suite in `docs/` folder
  - `architecture.md`: System architecture and design
  - `api.md`: Complete API reference
  - `security.md`: Security analysis and threat model
  - `troubleshooting.md`: Common issues and solutions
- Enhanced `.gitignore` with security-focused patterns
- MbedTLS library build option in CMakeLists.txt

### Changed
- Updated main `README.md` with quick start guide and security notes
- Improved signing tool path resolution for MbedTLS backend

### Fixed
- Signing tool build issues with proper dependency handling
- Documentation inconsistencies and missing information

## [1.0.0] - 2026-01-04

### Added
- Initial secure boot implementation for ARM Cortex-R5F
- RSA-2048 signature verification with MbedTLS
- AES-256-CBC payload encryption
- Anti-rollback protection mechanism
- Cross-platform signing tool with OpenSSL/MbedTLS backends
- QEMU testing support with semihosting
- Comprehensive build system with CMake
- Platform abstraction layer for hardware independence
- UART debugging and watchdog support
- Complete documentation suite:
  - Main project README with build/test instructions
  - Signing workflow guide (README_SIGN.md)
  - Deployment guide (README_SB.md)
  - Testing procedures (README_TEST.md)
  - Architecture overviews in subfolders

### Security
- No hardcoded secrets in source code
- Proper key zeroization after use
- Input validation and buffer overflow protection
- Fail-safe boot modes for security failures
- Anti-rollback counter implementation
- Secure boot chain of trust

### Technical Details
- **Target Platform:** ARM Cortex-R5F
- **Crypto Library:** MbedTLS 3.6.2 (subset for embedded)
- **Build System:** CMake with ARM GCC cross-compilation
- **Memory Usage:** ~45KB ROM, ~28KB RAM
- **Boot Time:** <500ms target (crypto: ~200ms)
- **Image Format:** Custom header with RSA+AES protection

### Known Limitations
- Requires production key provisioning (OTP/eFuse integration)
- Hardware secure storage not yet implemented
- Limited to single-stage boot (no chain loading)
- No hardware crypto acceleration support yet

### Testing
- Unit tests for crypto functions
- QEMU-based integration testing
- Hardware testing framework outlined
- Security testing procedures documented

---

## Types of changes
- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for any bug fixes
- `Security` in case of vulnerabilities

## Versioning
This project uses [Semantic Versioning](https://semver.org/).

Given a version number MAJOR.MINOR.PATCH, increment the:

- **MAJOR** version when you make incompatible API changes
- **MINOR** version when you add functionality in a backwards compatible manner
- **PATCH** version when you make backwards compatible bug fixes

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format.

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## Acknowledgments
- MbedTLS project for the cryptographic library
- ARM ecosystem for development tools
- OpenSSL project for host-side crypto operations</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/docs/CHANGELOG.md