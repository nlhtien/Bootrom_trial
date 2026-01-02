/**
 * @file uart.h
 * @brief UART Driver Interface (Stub)
 */

#ifndef UART_H
#define UART_H

#include <stdint.h>
#include <stddef.h>

/* UART base addresses (platform-specific) */
#define UART0_BASE 0x40000000

/**
 * @brief Initialize UART
 * @param baudrate Baud rate
 * @return 0 on success
 */
int uart_init(uint32_t baudrate);

/**
 * @brief Send a character
 * @param c Character to send
 */
void uart_putchar(char c);

/**
 * @brief Send a string
 * @param str String to send
 */
void uart_puts(const char *str);

/**
 * @brief Receive a character (blocking)
 * @return Received character
 */
char uart_getchar(void);

/**
 * @brief Send formatted string (simple implementation)
 */
void uart_printf(const char *format, ...);

#endif /* UART_H */
