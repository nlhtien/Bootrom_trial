/**
 * @file test_main.c
 * @brief Main test runner for BootROM
 */

#include "test_framework.h"
#include "tests/test_crypto.h"
#include "tests/test_secure_boot.h"

int main(void)
{
    /* Initialize test framework */
    if (test_init() != 0) {
        return -1;
    }

    /* Run test suites */
    test_run_suite(&crypto_test_suite);
    test_run_suite(&secure_boot_test_suite);

    /* Generate test report */
    test_report();

    return 0;
}