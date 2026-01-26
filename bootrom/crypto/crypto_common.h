/**
 * @file crypto_common.h
 * @brief Common Crypto Utilities & Definitions
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* SHARED MACROS                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief Safe pointer casting to const unsigned char*
 * @details Prevents compiler warnings (-Wpointer-sign) when passing uint8_t* * to MbedTLS APIs expecting unsigned char*.
 */
#ifndef CAST_U8
#define CAST_U8(ptr) ((const unsigned char *)(const void *)(ptr))
#endif

/* -------------------------------------------------------------------------- */
/* SECURITY UTILITIES                               */
/* -------------------------------------------------------------------------- */

/**
 * @brief Securely zeroize memory (Anti-Optimization)
 * @details Uses volatile pointer to ensure compiler does not optimize away 
 * the zeroing loop. CRITICAL for clearing Keys/Secrets from Stack/Heap.
 * * @param buf Pointer to buffer
 * @param len Length in bytes
 */
void crypto_secure_zeroize(void *buf, size_t len);

/**
 * @brief Constant-time memory comparison
 * @details Execution time depends ONLY on 'len', not on the data content.
 * CRITICAL for preventing Timing Attacks when verifying Hash/Tag/Keys.
 * * @param v1 Pointer to buffer 1
 * @param v2 Pointer to buffer 2
 * @param n  Number of bytes to compare
 * @return 0 if equal, non-zero if different
 */
int crypto_secure_memcmp(const void *v1, const void *v2, size_t n);

/**
 * @brief Basic Hex Dump (Debug Only)
 * @note  Ideally compiled out in Production Release via Macros
 */
void crypto_util_hexdump(const char *label, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_COMMON_H */