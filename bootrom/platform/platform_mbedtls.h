/**
 * @file platform_mbedtls.h
 * @brief MbedTLS Platform Functions for Bare-Metal
 * 
 * NOTE: With MBEDTLS_MEMORY_BUFFER_ALLOC_C, MbedTLS uses its own
 * buffer allocator. No platform malloc/free functions are needed.
 */

#ifndef PLATFORM_MBEDTLS_H
#define PLATFORM_MBEDTLS_H

#include <stddef.h>

/* MbedTLS uses MBEDTLS_MEMORY_BUFFER_ALLOC_C, so no platform malloc/free needed */
/* Disable MbedTLS file I/O (stubs) */
#define mbedtls_fprintf(...)  (void)0
#define mbedtls_snprintf(...) 0

#endif /* PLATFORM_MBEDTLS_H */
