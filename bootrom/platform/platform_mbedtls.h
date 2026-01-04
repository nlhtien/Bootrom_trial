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

/* Define platform snprintf for MbedTLS */
#define MBEDTLS_PLATFORM_STD_SNPRINTF   mbedtls_platform_snprintf

/* Platform function declarations for MbedTLS */
#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_platform_snprintf(char *str, size_t size, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_MBEDTLS_H */
