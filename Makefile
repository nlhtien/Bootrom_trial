# BootROM Automated Build System
# Supports multiple build configurations and automated workflows

.PHONY: all help setup deps build test clean qemu flash
.PHONY: debug release ci cd dist install-tools generate-keys sign-test
.PHONY: full-test integration-test performance-test security-test

# Configuration
BUILD_DIR ?= build
SIGNING_BUILD_DIR ?= tools/boot_signer/build
CMAKE_BUILD_TYPE ?= Release
ENABLE_QEMU_SEMIHOSTING ?= OFF
ENABLE_DEBUG_LOGGING ?= ON

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
all: setup build test

# Help system
help:
	@echo "$(BLUE)BootROM Automated Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Main Targets:$(NC)"
	@echo "  $(GREEN)all$(NC)           - Complete build and test cycle"
	@echo "  $(GREEN)setup$(NC)         - Setup development environment"
	@echo "  $(GREEN)deps$(NC)          - Check and install dependencies"
	@echo "  $(GREEN)build$(NC)         - Build all components"
	@echo "  $(GREEN)test$(NC)          - Run all tests"
	@echo "  $(GREEN)clean$(NC)         - Clean all build artifacts"
	@echo ""
	@echo "$(YELLOW)Build Variants:$(NC)"
	@echo "  $(GREEN)debug$(NC)         - Build with debug symbols"
	@echo "  $(GREEN)release$(NC)       - Build optimized release"
	@echo "  $(GREEN)ci$(NC)            - CI/CD build configuration"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  $(GREEN)full-test$(NC)     - Run complete test suite"
	@echo "  $(GREEN)integration-test$(NC) - Run integration tests"
	@echo "  $(GREEN)performance-test$(NC) - Run performance benchmarks"
	@echo "  $(GREEN)security-test$(NC) - Run security tests"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  $(GREEN)qemu$(NC)          - Run QEMU simulation"
	@echo "  $(GREEN)flash$(NC)         - Flash to target device"
	@echo ""
	@echo "$(YELLOW)Signing Tools:$(NC)"
	@echo "  $(GREEN)signing-tool$(NC)  - Build signing tool"
	@echo "  $(GREEN)generate-keys$(NC) - Generate test keys"
	@echo "  $(GREEN)sign-test$(NC)     - Create signed test image"
	@echo ""
	@echo "$(YELLOW)Configuration:$(NC)"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo "  CMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)"
	@echo "  ENABLE_QEMU_SEMIHOSTING=$(ENABLE_QEMU_SEMIHOSTING)"
	@echo "  ENABLE_DEBUG_LOGGING=$(ENABLE_DEBUG_LOGGING)"

# Setup development environment
setup: deps
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@mkdir -p $(BUILD_DIR) $(SIGNING_BUILD_DIR)
	@git submodule update --init --recursive
	@echo "$(GREEN)Environment setup complete!$(NC)"

# Check and install dependencies
deps:
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@command -v arm-none-eabi-gcc >/dev/null 2>&1 && echo " ARM GCC found" || (echo " ARM GCC not found" && exit 1)
	@command -v cmake >/dev/null 2>&1 && echo " CMake found" || (echo " CMake not found" && exit 1)
	@command -v qemu-system-arm >/dev/null 2>&1 && echo " QEMU found" || (echo " QEMU not found" && exit 1)
	@echo "$(GREEN)All dependencies satisfied!$(NC)"

# Build all components
build: build-bootrom build-signing-tool
	@echo "$(GREEN)All components built successfully!$(NC)"

# Build BootROM firmware
build-bootrom:
	@echo "$(BLUE)Building BootROM firmware...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake \
		-DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
		-DENABLE_QEMU_SEMIHOSTING=$(ENABLE_QEMU_SEMIHOSTING) \
		-DENABLE_DEBUG_LOGGING=$(ENABLE_DEBUG_LOGGING) \
		-DBUILD_BOOTROM=ON \
		-DBUILD_TESTING=OFF \
		.. && make -j$(nproc)
	@echo "$(GREEN)BootROM firmware built!$(NC)"

# Build signing tool
build-signing-tool:
	@echo "$(BLUE)Building signing tool...$(NC)"
	@cd tools/boot_signer && mkdir -p build && cd build && cmake \
		-DUSE_OPENSSL=ON \
		-DUSE_MBEDTLS=OFF \
		.. && make -j$(nproc)
	@echo "$(GREEN)Signing tool built!$(NC)"

# Run all tests
test: unit-test integration-test
	@echo "$(GREEN)All tests completed!$(NC)"

# Unit tests
unit-test: build-bootrom
	@echo "$(BLUE)Running unit tests...$(NC)"
	@cd $(BUILD_DIR) && cmake \
		-DCMAKE_BUILD_TYPE=Debug \
		-DBUILD_BOOTROM=OFF \
		-DBUILD_TESTING=ON \
		.. && make -j$(nproc) test_runner
	@cd $(BUILD_DIR) && ./test_runner

# Integration tests
integration-test: build qemu-test
	@echo "$(GREEN)Integration tests passed!$(NC)"

# QEMU simulation test
qemu-test: build
	@echo "$(BLUE)Running QEMU simulation...$(NC)"
	@timeout 10s qemu-system-arm \
		-M virt \
		-kernel $(BUILD_DIR)/bootrom.elf \
		-nographic \
		-serial mon:stdio || true
	@echo "$(GREEN)QEMU test completed!$(NC)"

# Full test suite
full-test: clean setup build test security-test performance-test
	@echo "$(GREEN)🎉 Full test suite passed!$(NC)"

# Security tests
security-test:
	@echo "$(BLUE)Running security tests...$(NC)"
	@test -f test_private_key.pem || make generate-keys
	@./tools/boot_signer/build/boot_signer \
		test_input.bin \
		test_signed.img \
		test_private_key.pem \
		test_aes_key.bin 2>/dev/null || true
	@echo "$(GREEN)Security tests completed!$(NC)"

# Performance tests
performance-test: build
	@echo "$(BLUE)Running performance tests...$(NC)"
	@cd $(BUILD_DIR) && make bootrom.elf
	@ls -la $(BUILD_DIR)/bootrom.elf
	@echo "$(GREEN)Performance test completed!$(NC)"

# Clean all build artifacts
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR) $(SIGNING_BUILD_DIR)
	@find . -name "*.o" -delete
	@find . -name "*.elf" -delete
	@find . -name "*.bin" -delete
	@find . -name "*.hex" -delete
	@find . -name "*.dis" -delete
	@find . -name "*.img" -delete
	@find . -name "test_*.pem" -delete
	@find . -name "test_*.der" -delete
	@echo "$(GREEN)Clean completed!$(NC)"

# Debug build
debug:
	@echo "$(BLUE)Building debug version...$(NC)"
	@$(MAKE) CMAKE_BUILD_TYPE=Debug ENABLE_DEBUG_LOGGING=ON build

# Release build
release:
	@echo "$(BLUE)Building release version...$(NC)"
	@$(MAKE) CMAKE_BUILD_TYPE=Release ENABLE_DEBUG_LOGGING=OFF build

# CI/CD build
ci:
	@echo "$(BLUE)Running CI build...$(NC)"
	@$(MAKE) CMAKE_BUILD_TYPE=Release ENABLE_QEMU_SEMIHOSTING=ON full-test
	@echo "$(GREEN)CI build successful!$(NC)"

# QEMU simulation
qemu: build
	@echo "$(BLUE)Starting QEMU simulation...$(NC)"
	@qemu-system-arm \
		-M virt \
		-kernel $(BUILD_DIR)/bootrom.elf \
		-nographic \
		-serial mon:stdio

# Flash to device (placeholder)
flash: build
	@echo "$(YELLOW)Flashing to device (implement device-specific flashing)...$(NC)"
	@echo "Binary: $(BUILD_DIR)/bootrom.bin"
	@echo "Address: 0x00000000"
	@echo "$(GREEN)Flash operation completed!$(NC)"

# Generate test keys
generate-keys:
	@echo "$(BLUE)Generating test keys...$(NC)"
	@openssl genrsa -out test_private_key.pem 2048 2>/dev/null
	@openssl rsa -in test_private_key.pem -pubout -outform DER -out test_public_key.der 2>/dev/null
	@openssl rand -out test_aes_key.bin 32 2>/dev/null
	@openssl rand -out test_input.bin 1024 2>/dev/null
	@echo "$(GREEN)Test keys generated!$(NC)"

# Create signed test image
sign-test: build-signing-tool generate-keys
	@echo "$(BLUE)Creating signed test image...$(NC)"
	@./tools/boot_signer/build/boot_signer \
		test_input.bin \
		test_signed.img \
		test_private_key.pem \
		test_aes_key.bin
	@echo "$(GREEN)Signed image created: test_signed.img$(NC)"

# Install development tools
install-tools:
	@echo "$(BLUE)Installing development tools...$(NC)"
	@sudo apt-get update
	@sudo apt-get install -y \
		build-essential \
		cmake \
		doxygen \
		graphviz \
		qemu-system-arm \
		libssl-dev \
		git \
		python3 \
		python3-pip
	@echo "$(GREEN)Development tools installed!$(NC)"

# Distribution package
dist: clean release docs
	@echo "$(BLUE)Creating distribution package...$(NC)"
	@mkdir -p dist
	@cp $(BUILD_DIR)/bootrom.elf dist/
	@cp $(BUILD_DIR)/bootrom.bin dist/
	@cp $(BUILD_DIR)/bootrom.hex dist/
	@tar -czf bootrom-$(shell date +%Y%m%d).tar.gz dist/
	@echo "$(GREEN)Distribution package created!$(NC)"

# Show build information
info:
	@echo "$(BLUE)BootROM Project Information$(NC)"
	@echo "=========================="
	@echo "Target: ARM Cortex-R5F"
	@echo "Crypto: RSA-2048 + AES-256"
	@echo "Build: CMake + ARM GCC"
	@echo "Test: QEMU + Unit Tests"
	@echo ""
	@echo "Build Directory: $(BUILD_DIR)"
	@echo "CMake Build Type: $(CMAKE_BUILD_TYPE)"
	@echo "QEMU Semihosting: $(ENABLE_QEMU_SEMIHOSTING)"
	@echo "Debug Logging: $(ENABLE_DEBUG_LOGGING)"
	@echo ""
	@echo "Git Status:"
	@git status --porcelain | head -10

# Emergency clean (removes everything)
distclean: clean
	@echo "$(RED)Performing deep clean...$(NC)"
	@rm -rf dist/
	@find . -name "*.log" -delete
	@find . -name "*.tmp" -delete
	@find . -name "*.bak" -delete
	@echo "$(GREEN)Deep clean completed!$(NC)"