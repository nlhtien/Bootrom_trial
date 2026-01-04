# Contributing to BootROM

Thank you for your interest in contributing to the BootROM secure boot project! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## How to Contribute

### 1. Reporting Issues

When reporting bugs or requesting features:

**For Bug Reports:**
- Use the bug report template
- Include detailed steps to reproduce
- Provide system information (OS, toolchain versions)
- Attach relevant logs and error messages
- Specify expected vs actual behavior

**For Feature Requests:**
- Clearly describe the proposed feature
- Explain the use case and benefits
- Consider backward compatibility
- Provide implementation suggestions if possible

### 2. Contributing Code

#### Development Setup
```bash
# Clone repository
git clone https://github.com/your-org/Bootrom_trial.git
cd Bootrom_trial

# Initialize submodules
git submodule update --init --recursive

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make
```

#### Code Standards

**C Code Style:**
- Follow Linux kernel coding style
- Use 4 spaces for indentation
- Maximum line length: 80 characters
- Use descriptive variable names
- Add comments for complex logic

**Example:**
```c
/**
 * verify_image_header - Validate image header structure
 * @header: Pointer to image header
 *
 * Returns: 0 on success, negative error code on failure
 */
int verify_image_header(const image_header_t *header)
{
    if (!header) {
        uart_printf("ERROR: NULL header pointer\n");
        return -EINVAL;
    }

    if (header->magic != IMAGE_MAGIC) {
        uart_printf("ERROR: Invalid magic number: 0x%08x\n", header->magic);
        return -EINVAL;
    }

    return 0;
}
```

**Commit Messages:**
- Use imperative mood ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Provide detailed description if needed
- Reference issue numbers when applicable

**Examples:**
```
feat: Add hardware crypto acceleration support

- Implement AES/SHA acceleration for R5F
- Add platform abstraction for crypto hardware
- Update performance benchmarks

Fixes #123
```

```
fix: Correct AES IV handling in decryption

The initialization vector was not being properly
updated for multi-block AES operations, causing
decryption failures for large payloads.

Closes #456
```

#### Testing Requirements

**Unit Tests:**
- Add tests for new functions
- Maintain >90% code coverage
- Test error conditions and edge cases

**Integration Tests:**
- Test with QEMU for functionality
- Verify on hardware when possible
- Test security features thoroughly

**Security Testing:**
- Fuzz test input validation
- Verify cryptographic operations
- Test against known attack vectors

### 3. Documentation

**Code Documentation:**
- Use Doxygen-style comments for functions
- Document parameters and return values
- Explain complex algorithms
- Update API documentation

**User Documentation:**
- Keep README files current
- Update troubleshooting guides
- Document new features
- Provide usage examples

### 4. Security Considerations

**Security Reviews:**
- All crypto-related changes require security review
- Key handling code needs extra scrutiny
- Consider side-channel attack vectors
- Document security implications

**Vulnerability Reporting:**
- Report security issues privately first
- Allow time for fixes before public disclosure
- Follow responsible disclosure practices

## Development Workflow

### Branching Strategy
```
main          # Production-ready code
├── develop     # Integration branch
│   ├── feature/secure-boot-enhancement
│   ├── bugfix/crypto-timing
│   └── docs/api-updates
```

### Pull Request Process

1. **Create Feature Branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes:**
   - Write tests first (TDD approach)
   - Implement functionality
   - Update documentation
   - Ensure code style compliance

3. **Run Tests:**
   ```bash
   # Build and test
   mkdir build && cd build
   cmake .. && make
   ctest  # If tests are implemented

   # QEMU testing
   qemu-system-arm -M virt -kernel bootrom.elf -nographic
   ```

4. **Commit Changes:**
   ```bash
   git add .
   git commit -m "feat: Add your feature description"
   ```

5. **Create Pull Request:**
   - Push branch to GitHub
   - Create PR with detailed description
   - Reference related issues
   - Request reviews from maintainers

6. **Code Review:**
   - Address review comments
   - Make requested changes
   - Ensure CI passes

7. **Merge:**
   - Squash commits if requested
   - Delete feature branch
   - Update changelog

### Continuous Integration

**Automated Checks:**
- Build verification on multiple platforms
- Unit test execution
- Code style checking
- Security scanning
- Documentation validation

**Manual Reviews:**
- Security assessment for crypto changes
- Performance impact evaluation
- API compatibility checking
- Documentation review

## Areas for Contribution

### High Priority
- **Hardware Integration:** OTP/eFuse drivers
- **Security Hardening:** Side-channel protections
- **Performance Optimization:** Crypto acceleration
- **Testing:** Comprehensive test suites

### Medium Priority
- **New Features:** ECC support, certificate chains
- **Platform Support:** Additional ARM cores
- **Tools:** Enhanced signing utilities
- **Documentation:** API references, tutorials

### Low Priority
- **Code Quality:** Refactoring, cleanup
- **Build System:** Additional toolchain support
- **Examples:** Sample applications
- **Research:** New security features

## Getting Help

### Communication Channels
- **Issues:** Bug reports and feature requests
- **Discussions:** General questions and design discussions
- **Pull Requests:** Code review and implementation discussions

### Finding Tasks
- Check open issues with `good first issue` label
- Look for `help wanted` tagged issues
- Review the project roadmap in `README_NG.md`

### Mentorship
- New contributors can request mentorship
- Pair programming sessions available
- Code review provides learning opportunities

## Recognition

Contributors are recognized through:
- Author credits in commit history
- Changelog entries
- Contributor acknowledgments
- Potential co-authorship on publications

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

Thank you for contributing to BootROM! 🚀</content>
<parameter name="filePath">/home/kora/tiennlh/project/Bootrom_trial/docs/CONTRIBUTING.md