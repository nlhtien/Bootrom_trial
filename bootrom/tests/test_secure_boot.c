/**
 * @file test_secure_boot.c
 * @brief Unit tests for secure boot core
 */

#include "test_framework.h"
#include "secure_boot/secure_boot_core.h"
#include <string.h>

/* Mock image header structure (copied from secure_boot_core.c) */
typedef struct {
    uint32_t magic;              /* Magic number: 0x4D425254 ("MBRT") */
    uint32_t version;            /* Header version */
    uint32_t image_size;         /* Size of encrypted image */
    uint32_t image_version;      /* Image version (for anti-rollback) */
    uint32_t signature_offset;   /* Offset to signature */
    uint32_t iv_offset;          /* Offset to IV */
    uint32_t reserved[2];        /* Reserved */
    uint8_t  iv[16];             /* AES IV (128 bits) */
    uint8_t  signature[256];     /* RSA-2048 signature */
} image_header_t;

#define IMAGE_MAGIC 0x5442524D  /* "MBRT" in little-endian */
#define IMAGE_VERSION 1

/* Mock image header for testing (commented out - not currently used) */
/*
static const image_header_t test_header = {
    .magic = IMAGE_MAGIC,
    .version = IMAGE_VERSION,
    .image_size = 1024,
    .image_version = 1,
    .signature_offset = 0,
    .iv_offset = 0,
    .reserved = {0, 0},
    .iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    .signature = {0}  // Mock signature
};
*/

/* Test cases */
static void test_secure_boot_cleanup(void)
{
    /* Test that cleanup doesn't crash */
    secure_boot_cleanup();
    /* No assertions needed - just verify it doesn't crash */
}

static void test_secure_boot_load_and_verify_invalid_param(void)
{
    uint8_t buffer[1024];
    uint32_t decrypted_size;

    /* NULL buffer should fail */
    TEST_ASSERT(secure_boot_load_and_verify(0, NULL, sizeof(buffer), &decrypted_size) != 0);

    /* NULL size output should fail */
    TEST_ASSERT(secure_boot_load_and_verify(0, buffer, sizeof(buffer), NULL) != 0);

    /* Zero buffer size should fail */
    TEST_ASSERT(secure_boot_load_and_verify(0, buffer, 0, &decrypted_size) != 0);
}

static void test_secure_boot_cleanup_and_handoff(void)
{
    /* Test that handoff doesn't crash with dummy address */
    secure_boot_cleanup_and_handoff(0x10000000);
    /* No assertions needed - just verify it doesn't crash */
}

/* Test suite */
test_case_t secure_boot_tests[] = {
    {"secure_boot_cleanup", "Test cleanup function", NULL, test_secure_boot_cleanup, NULL},
    {"secure_boot_load_and_verify_invalid_param", "Test invalid parameters for load_and_verify", NULL, test_secure_boot_load_and_verify_invalid_param, NULL},
    {"secure_boot_cleanup_and_handoff", "Test cleanup and handoff function", NULL, test_secure_boot_cleanup_and_handoff, NULL}
};

test_suite_t secure_boot_test_suite = {
    "Secure Boot Tests",
    "Unit tests for secure boot core functions",
    secure_boot_tests,
    sizeof(secure_boot_tests) / sizeof(test_case_t),
    0, 0, 0, 0, 0
};