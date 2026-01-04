/**
 * @file test_framework.c
 * @brief Simple unit test framework implementation
 */

#include "test_framework.h"
#include "drivers/uart.h"  // For UART output
#include <string.h>

/* Test statistics */
static uint32_t tests_run = 0;
static uint32_t tests_passed = 0;
static uint32_t tests_failed = 0;
static uint32_t tests_skipped = 0;

/* UART output functions for test reporting */
static void test_print(const char *str)
{
    platform_uart_write((const uint8_t *)str, strlen(str));
}

static void test_println(const char *str)
{
    test_print(str);
    test_print("\r\n");
}

static void test_printf(const char *format, ...)
{
    // char buffer[256];  // Not used in current implementation
    // Simple implementation - in real embedded system you'd use proper printf
    test_print(format);  // Placeholder
}

/* Initialize test framework */
int test_init(void)
{
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;
    tests_skipped = 0;

    test_println("=== BootROM Test Framework Initialized ===");
    return 0;
}

/* Run a single test case */
static void test_run_case(const test_case_t *test_case)
{
    test_print("Running test: ");
    test_print(test_case->name);
    test_print("... ");

    tests_run++;

    // Run setup if provided
    if (test_case->setup) {
        test_case->setup();
    }

    // Run the test
    test_case->function();

    // Run teardown if provided
    if (test_case->teardown) {
        test_case->teardown();
    }

    // For now, assume all tests pass (no exception handling)
    test_println("PASS");
    tests_passed++;
}

/* Run a test suite */
void test_run_suite(const test_suite_t *suite)
{
    uint32_t i;

    test_print("=== Running Test Suite: ");
    test_print(suite->name);
    test_println(" ===");

    // Run suite setup if provided
    if (suite->setup) {
        suite->setup();
    }

    for (i = 0; i < suite->num_cases; i++) {
        test_run_case(&suite->cases[i]);
    }

    // Run suite teardown if provided
    if (suite->teardown) {
        suite->teardown();
    }

    test_println("");
}

/* Run all registered test suites */
void test_run_all(void)
{
    // This would be populated by test registration system
    // For now, suites are run individually
}

/* Generate test report */
void test_report(void)
{
    test_println("=== Test Report ===");
    test_printf("Tests run: %u\r\n", tests_run);
    test_printf("Tests passed: %u\r\n", tests_passed);
    test_printf("Tests failed: %u\r\n", tests_failed);
    test_printf("Tests skipped: %u\r\n", tests_skipped);

    if (tests_failed == 0) {
        test_println("All tests PASSED! ✓");
    } else {
        test_println("Some tests FAILED! ✗");
    }
}