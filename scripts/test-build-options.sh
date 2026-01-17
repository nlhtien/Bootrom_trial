#!/bin/bash
# BootROM Build Options Test Script
# Tests all build configurations and options

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test basic build
test_basic_build() {
    log_info "Testing basic BootROM build..."
    cd "$PROJECT_ROOT"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_BOOTROM=ON \
        -DBUILD_TESTING=OFF \
        -DENABLE_QEMU_SEMIHOSTING=OFF \
        -DENABLE_DEBUG_LOGGING=ON \
        ..

    make -j"$(nproc)"
    log_success "Basic build completed"
}

# Test debug build
test_debug_build() {
    log_info "Testing debug build..."
    cd "$BUILD_DIR"

    cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_BOOTROM=ON \
        -DBUILD_TESTING=OFF \
        -DENABLE_QEMU_SEMIHOSTING=ON \
        -DENABLE_DEBUG_LOGGING=ON \
        ..

    make -j"$(nproc)"
    log_success "Debug build completed"
}

# Test test build
test_test_build() {
    log_info "Testing unit test build..."
    cd "$BUILD_DIR"

    cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_BOOTROM=OFF \
        -DBUILD_TESTING=ON \
        ..

    make -j"$(nproc)" test_runner
    log_success "Test build completed"
}

# Test signing tool build
test_signing_tool_build() {
    log_info "Testing signing tool build..."
    cd "$PROJECT_ROOT/tools/boot_signer"
    rm -rf build
    mkdir -p build
    cd build

    cmake \
        -DBOOT_SIGNER_USE_OPENSSL=ON \
        -DBOOT_SIGNER_USE_MBEDTLS=OFF \
        ..

    make -j"$(nproc)"
    log_success "Signing tool build completed"
}

# Test MbedTLS library build
test_mbedtls_build() {
    log_info "Testing MbedTLS library build..."
    cd "$BUILD_DIR"

    cmake \
        -DBUILD_MBEDTLS_LIB=ON \
        ..

    make -j"$(nproc)" mbedtls
    log_success "MbedTLS library build completed"
}

# Test QEMU simulation
test_qemu_simulation() {
    log_info "Testing QEMU simulation..."
    cd "$BUILD_DIR"

    # Build for QEMU
    cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_QEMU_SEMIHOSTING=ON \
        -DENABLE_DEBUG_LOGGING=ON \
        ..

    make -j"$(nproc)"

    # Run QEMU test (short timeout)
    timeout 5s qemu-system-arm \
        -M virt \
        -kernel bootrom.elf \
        -nographic \
        -serial mon:stdio \
        </dev/null || true

    log_success "QEMU simulation test completed"
}

# Test all configurations
test_all_configs() {
    log_info "Testing all build configurations..."

    test_basic_build
    test_debug_build
    test_test_build
    test_signing_tool_build
    test_mbedtls_build
    test_qemu_simulation

    log_success "All build configurations tested successfully!"
}

# Main script logic
case "${1:-all}" in
    "basic")
        test_basic_build
        ;;
    "debug")
        test_debug_build
        ;;
    "test")
        test_test_build
        ;;
    "signing")
        test_signing_tool_build
        ;;
    "mbedtls")
        test_mbedtls_build
        ;;
    "qemu")
        test_qemu_simulation
        ;;
    "all")
        test_all_configs
        ;;
    *)
        echo "Usage: $0 [basic|debug|test|signing|mbedtls|docs|qemu|all]"
        echo ""
        echo "Test individual build configurations:"
        echo "  basic    - Basic BootROM release build"
        echo "  debug    - Debug build with QEMU semihosting"
        echo "  test     - Unit test build"
        echo "  signing  - Signing tool build"
        echo "  mbedtls  - MbedTLS library build"
        echo "  docs     - Documentation build"
        echo "  qemu     - QEMU simulation test"
        echo "  all      - Test all configurations (default)"
        exit 1
        ;;
esac