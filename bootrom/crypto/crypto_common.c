/**
 * @file crypto_common.c
 * @brief Common Crypto Utilities Implementation
 */

#include "crypto_common.h"

/* -------------------------------------------------------------------------- */
/* SECURITY UTILITIES                               */
/* -------------------------------------------------------------------------- */

/* * Why volatile? 
 * Compilers often optimize away memset() calls at the end of functions 
 * because "the memory is never read again". 
 * 'volatile' forces the write to actually happen.
 */
void crypto_secure_zeroize(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

/*
 * Why constant time?
 * Standard memcmp() returns immediately upon finding the first difference.
 * Attackers can measure the time taken to guess the hash byte-by-byte.
 * This function ALWAYS iterates through the entire length 'n'.
 */
int crypto_secure_memcmp(const void *v1, const void *v2, size_t n)
{
    const volatile uint8_t *p1 = (const volatile uint8_t *)v1;
    const volatile uint8_t *p2 = (const volatile uint8_t *)v2;
    volatile uint8_t diff = 0;

    while (n--) {
        /* Accumulate differences using OR. 
           If strings match, diff remains 0. */
        diff |= (*p1++ ^ *p2++);
    }

    return (diff == 0) ? 0 : 1;
}

/* -------------------------------------------------------------------------- */
/* DEBUG UTILITIES                                */
/* -------------------------------------------------------------------------- */

#if defined(DEBUG) || defined(BOOTROM_DEBUG_PRINT)
#include <stdio.h> /* Only included for debug builds */

void crypto_util_hexdump(const char *label, const uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return;

    if (label) printf("%s (%zu bytes):\n", label, len);

    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
        if (((i + 1) % 16) == 0) printf("\n");
    }
    printf("\n");
}

#else

/* Production Build: Empty Stub to save ROM space */
void crypto_util_hexdump(const char *label, const uint8_t *buf, size_t len)
{
    (void)label;
    (void)buf;
    (void)len;
}

#endif