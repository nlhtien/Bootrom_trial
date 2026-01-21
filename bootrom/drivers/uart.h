/**
 * @file uart.h
 * @brief UART + Logging system for BootROM
 */

#ifndef UART_H
#define UART_H

#include <stdint.h>
#include <stddef.h>

/* =========================
 * Platform config
 * ========================= */
#define UART0_BASE 0x40000000   /* Example base address for UART0 */

/* =========================
 * Log levels
 * ========================= */
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3,
} log_level_t;

/* =========================
 * UART API
 * ========================= */
int  uart_init(uint32_t baudrate);
void uart_putchar(char c);
void uart_puts(const char *s);
char uart_getchar(void);

/* Minimal printf */
void uart_printf(const char *fmt, ...);

/* =========================
 * Logging API
 * ========================= */
void log_set_level(log_level_t lvl);
void log_printf(log_level_t lvl, const char *fmt, ...);

/* =========================
 * Logging macros
 * ========================= */
#if defined(BOOTROM_DEV_MODE)

#define LOGE(...) log_printf(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOGW(...) log_printf(LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOGI(...) log_printf(LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOGD(...) log_printf(LOG_LEVEL_DEBUG, __VA_ARGS__)

#else

#define LOGE(...)
#define LOGW(...)
#define LOGI(...)
#define LOGD(...)

#endif

#endif /* UART_H */
