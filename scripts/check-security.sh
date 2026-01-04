#!/bin/bash
# BootROM Security and Sensitive Files Check Script
# Checks for sensitive files and potential security issues

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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

# Check for sensitive files
check_sensitive_files() {
    log_info "Checking for sensitive files..."

    local sensitive_patterns=(
        "*.pem"
        "*.der"
        "*.key"
        "*.p12"
        "*.pfx"
        "*.jks"
        "private_key.*"
        "public_key.*"
        "aes_key.bin"
        "*secret*"
        "*password*"
        "*.env"
    )

    local found_sensitive=()

    for pattern in "${sensitive_patterns[@]}"; do
        while IFS= read -r -d '' file; do
            # Skip files in external directories and build directories
            if [[ "$file" =~ ^./external/ ]] || [[ "$file" =~ ^./build/ ]] || [[ "$file" =~ ^./tools/.*/build/ ]]; then
                continue
            fi
            found_sensitive+=("$file")
        done < <(find . -name "$pattern" -type f -print0 2>/dev/null)
    done

    if [ ${#found_sensitive[@]} -ne 0 ]; then
        log_error "Found sensitive files that should not be committed:"
        printf '  %s\n' "${found_sensitive[@]}"
        log_error "Please remove these files or add them to .gitignore"
        return 1
    else
        log_success "No sensitive files found"
    fi
}

# Check for hardcoded secrets
check_hardcoded_secrets() {
    log_info "Checking for hardcoded secrets..."

    local secret_patterns=(
        "password.*="
        "secret.*="
        "key.*="
        "token.*="
        "api_key.*="
        "private_key.*="
        "BEGIN.*PRIVATE"
        "BEGIN.*RSA"
        "BEGIN.*EC"
    )

    local found_secrets=()

    for pattern in "${secret_patterns[@]}"; do
        while IFS= read -r -d '' file; do
            # Skip binary files, external libraries, and build files
            if file "$file" | grep -q "binary\|executable"; then
                continue
            fi
            if [[ "$file" =~ ^./external/ ]] || [[ "$file" =~ ^./build/ ]] || [[ "$file" =~ ^./tools/.*/build/ ]]; then
                continue
            fi
            if grep -q "$pattern" "$file" 2>/dev/null; then
                found_secrets+=("$file")
            fi
        done < <(find . -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*.py" -o -name "*.sh" -o -name "Makefile" -o -name "CMakeLists.txt" -type f -print0 2>/dev/null)
    done

    if [ ${#found_secrets[@]} -ne 0 ]; then
        log_warning "Found potential hardcoded secrets in:"
        printf '  %s\n' "${found_secrets[@]}"
        log_warning "Please review these files for hardcoded secrets"
    else
        log_success "No hardcoded secrets found"
    fi
}

# Check .gitignore coverage
check_gitignore_coverage() {
    log_info "Checking .gitignore coverage..."

    local temp_files=(
        "build/"
        "CMakeCache.txt"
        "CMakeFiles/"
        "*.o"
        "*.elf"
        "*.bin"
        "*.hex"
        "*.dis"
        "*.log"
        "test_output/"
    )

    local missing_patterns=()

    for temp in "${temp_files[@]}"; do
        # Create a test file
        local test_file="${temp}test.tmp"
        mkdir -p "$(dirname "$test_file")" 2>/dev/null || true
        touch "$test_file" 2>/dev/null || true

        # Check if git ignores it
        if ! git check-ignore "$test_file" 2>/dev/null; then
            missing_patterns+=("$temp")
        fi

        # Clean up
        rm -rf "$test_file" 2>/dev/null || true
    done

    if [ ${#missing_patterns[@]} -ne 0 ]; then
        log_warning ".gitignore may be missing patterns for:"
        printf '  %s\n' "${missing_patterns[@]}"
    else
        log_success ".gitignore coverage looks good"
    fi
}

# Check for large files
check_large_files() {
    log_info "Checking for large files..."

    local large_files=()
    while IFS= read -r -d '' file; do
        local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
        if [ "$size" -gt 10485760 ]; then  # 10MB
            large_files+=("$file (${size} bytes)")
        fi
    done < <(find . -type f -not -path "./.git/*" -not -path "./build/*" -not -path "./tools/*/build/*" -print0 2>/dev/null)

    if [ ${#large_files[@]} -ne 0 ]; then
        log_warning "Found large files (>10MB):"
        printf '  %s\n' "${large_files[@]}"
        log_warning "Consider using Git LFS for large files"
    else
        log_success "No large files found"
    fi
}

# Check file permissions
check_file_permissions() {
    log_info "Checking file permissions..."

    local executable_scripts=()
    while IFS= read -r -d '' file; do
        if [ -x "$file" ] && [[ "$file" =~ \.(sh|py|pl)$ ]]; then
            executable_scripts+=("$file")
        fi
    done < <(find . -name "*.sh" -o -name "*.py" -o -name "*.pl" -type f -print0 2>/dev/null)

    if [ ${#executable_scripts[@]} -ne 0 ]; then
        log_info "Found executable scripts (this is normal):"
        printf '  %s\n' "${executable_scripts[@]}"
    fi

    log_success "File permissions check completed"
}

# Main security check
run_security_check() {
    log_info "Running comprehensive security check..."

    cd "$PROJECT_ROOT"

    check_sensitive_files
    check_hardcoded_secrets
    check_gitignore_coverage
    check_large_files
    check_file_permissions

    log_success "Security check completed!"
}

# Main script logic
case "${1:-all}" in
    "sensitive")
        check_sensitive_files
        ;;
    "secrets")
        check_hardcoded_secrets
        ;;
    "gitignore")
        check_gitignore_coverage
        ;;
    "large")
        check_large_files
        ;;
    "permissions")
        check_file_permissions
        ;;
    "all")
        run_security_check
        ;;
    *)
        echo "Usage: $0 [sensitive|secrets|gitignore|large|permissions|all]"
        echo ""
        echo "Check specific security aspects:"
        echo "  sensitive   - Check for sensitive files"
        echo "  secrets     - Check for hardcoded secrets"
        echo "  gitignore   - Check .gitignore coverage"
        echo "  large       - Check for large files"
        echo "  permissions - Check file permissions"
        echo "  all         - Run all checks (default)"
        exit 1
        ;;
esac