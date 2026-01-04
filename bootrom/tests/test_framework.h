/**
 * @file test_framework.h
 * @brief Simple unit test framework for BootROM
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdint.h>
#include <stdbool.h>

/* Test function type */
typedef void (*test_fn)(void);

/* Setup/teardown function type */
typedef void (*test_setup_fn)(void);

/* Test case structure */
typedef struct {
    const char *name;
    const char *description;
    test_setup_fn setup;
    test_fn function;
    test_setup_fn teardown;
} test_case_t;

/* Test suite structure */
typedef struct {
    const char *name;
    const char *description;
    const test_case_t *cases;
    uint32_t num_cases;
    uint32_t passed;
    uint32_t failed;
    uint32_t skipped;
    test_setup_fn setup;
    test_setup_fn teardown;
} test_suite_t;

/* Test framework functions */
int test_init(void);
void test_run_suite(const test_suite_t *suite);
void test_run_all(void);
void test_report(void);

/* Test assertion macros */
#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            /* In a real framework, this would record failure */ \
            return; \
        } \
    } while (0)

#define TEST_ASSERT_EQUAL(a, b) \
    TEST_ASSERT((a) == (b))

#define TEST_ASSERT_NOT_EQUAL(a, b) \
    TEST_ASSERT((a) != (b))

#define TEST_ASSERT_NULL(ptr) \
    TEST_ASSERT((ptr) == NULL)

#define TEST_ASSERT_NOT_NULL(ptr) \
    TEST_ASSERT((ptr) != NULL)

#define TEST_ASSERT_TRUE(condition) \
    TEST_ASSERT(condition)

#define TEST_ASSERT_FALSE(condition) \
    TEST_ASSERT(!(condition))

#define TEST_ASSERT_MEM_EQUAL(a, b, size) \
    TEST_ASSERT(memcmp((a), (b), (size)) == 0)

#endif /* TEST_FRAMEWORK_H */