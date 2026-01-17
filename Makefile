# ============================================================================
# BootROM Build Orchestrator (Thin Wrapper around CMake)
# ============================================================================

.PHONY: all setup build clean rebuild qemu size disasm info

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
BUILD_DIR ?= build
CMAKE_BUILD_TYPE ?= Release
ENABLE_QEMU_SEMIHOSTING ?= OFF

# Toolchain
CMAKE ?= cmake
MAKE  ?= make

# Colors
GREEN := \033[0;32m
BLUE  := \033[0;34m
RED   := \033[0;31m
NC    := \033[0m

# ----------------------------------------------------------------------------
# Default
# ----------------------------------------------------------------------------
all: build

# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------
setup:
	@mkdir -p $(BUILD_DIR)
	@echo "$(GREEN)[OK] Setup complete$(NC)"

# ----------------------------------------------------------------------------
# Build
# ----------------------------------------------------------------------------
build: setup
	@echo "$(BLUE)[BUILD] Configuring CMake ($(CMAKE_BUILD_TYPE))...$(NC)"
	@cd $(BUILD_DIR) && $(CMAKE) \
		-DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
		-DENABLE_QEMU_SEMIHOSTING=$(ENABLE_QEMU_SEMIHOSTING) \
		-DBUILD_BOOTROM=ON \
		-DBUILD_TESTING=OFF \
		..
	@echo "$(BLUE)[BUILD] Building...$(NC)"
	@$(MAKE) -C $(BUILD_DIR) -j$(shell nproc)
	@echo "$(GREEN)[OK] Build finished$(NC)"

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------
clean:
	@echo "$(BLUE)[CLEAN] Removing build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@find . -name "*.o" -delete
	@find . -name "*.elf" -delete
	@find . -name "*.bin" -delete
	@find . -name "*.hex" -delete
	@find . -name "*.dis" -delete
	@find . -name "*.map" -delete
	@echo "$(GREEN)[OK] Clean complete$(NC)"

rebuild: clean build

# ----------------------------------------------------------------------------
# Run in QEMU
# ----------------------------------------------------------------------------
qemu: build
	@echo "$(BLUE)[QEMU] Running BootROM in QEMU...$(NC)"
	@qemu-system-arm \
		-M virt \
		-kernel $(BUILD_DIR)/bootrom.elf \
		-nographic \
		-serial mon:stdio

# ----------------------------------------------------------------------------
# Info / Analysis
# ----------------------------------------------------------------------------
size: build
	@echo "$(BLUE)[SIZE] Firmware size:$(NC)"
	@arm-none-eabi-size $(BUILD_DIR)/bootrom.elf

disasm: build
	@echo "$(BLUE)[DISASM] Generating disassembly...$(NC)"
	@arm-none-eabi-objdump -d $(BUILD_DIR)/bootrom.elf > $(BUILD_DIR)/bootrom.dis
	@echo "$(GREEN)[OK] Output: $(BUILD_DIR)/bootrom.dis$(NC)"

info:
	@echo "BootROM Build Info"
	@echo "------------------"
	@echo "Build dir:   $(BUILD_DIR)"
	@echo "Build type:  $(CMAKE_BUILD_TYPE)"
	@echo "QEMU semi:   $(ENABLE_QEMU_SEMIHOSTING)"
	@echo ""
	@arm-none-eabi-gcc --version | head -1
