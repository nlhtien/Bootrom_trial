/**
 * @file uart.c
 * @brief UART Driver Implementation (Stub)
 */

#include "uart.h"
#include "platform/platform.h"

/* UART register definitions (stub - actual values depend on SoC) */
typedef struct {
    volatile uint32_t DR;      /* Data Register */
    volatile uint32_t RSR;     /* Receive Status Register */
    volatile uint32_t RESERVED[4];
    volatile uint32_t FR;      /* Flag Register */
    volatile uint32_t RESERVED2[1];
    volatile uint32_t ILPR;    /* IrDA Low-Power Counter */
    volatile uint32_t IBRD;    /* Integer Baud Rate Divisor */
    volatile uint32_t FBRD;    /* Fractional Baud Rate Divisor */
    volatile uint32_t LCR_H;   /* Line Control Register */
    volatile uint32_t CR;      /* Control Register */
} uart_regs_t;

#define UART_REG(reg) ((uart_regs_t *)UART0_BASE)->reg

/* Flag Register bits */
#define UART_FR_TXFF  (1 << 5)  /* Transmit FIFO Full */
#define UART_FR_RXFE  (1 << 4)  /* Receive FIFO Empty */

int uart_init(uint32_t baudrate)
{
    /* Stub implementation - platform-specific UART initialization */
    /* In real implementation:
     * - Enable UART clock
     * - Configure pins
     * - Set baud rate
     * - Enable UART
     */
    
    (void)baudrate;
    return 0;
}

void uart_putchar(char c)
{
    /* Wait until transmit FIFO is not full */
    while (UART_REG(FR) & UART_FR_TXFF);
    
    /* Send character */
    UART_REG(DR) = c;
    
    /* If newline, send carriage return too */
    if (c == '\n') {
        while (UART_REG(FR) & UART_FR_TXFF);
        UART_REG(DR) = '\r';
    }
}

void uart_puts(const char *str)
{
    while (*str) {
        uart_putchar(*str++);
    }
}

char uart_getchar(void)
{
    /* Wait until receive FIFO is not empty */
    while (UART_REG(FR) & UART_FR_RXFE);
    
    /* Read character */
    return (char)(UART_REG(DR) & 0xFF);
}

/* Simple printf implementation (very basic) */
static void uart_put_uint32(uint32_t val)
{
    char buffer[12];
    int i = 0;
    
    if (val == 0) {
        uart_putchar('0');
        return;
    }
    
    while (val > 0) {
        buffer[i++] = '0' + (val % 10);
        val /= 10;
    }
    
    while (i > 0) {
        uart_putchar(buffer[--i]);
    }
}

void uart_printf(const char *format, ...)
{
    const char *p = format;
    
    /* Very simple implementation - only supports %s, %d, %x */
    while (*p) {
        if (*p == '%' && *(p + 1)) {
            p++;
            if (*p == 's') {
                /* String argument - stub */
            } else if (*p == 'd' || *p == 'u') {
                /* Integer argument - stub */
                uart_put_uint32(0);
            } else if (*p == 'x') {
                /* Hex argument - stub */
                uart_puts("0x");
                uart_put_uint32(0);
            } else {
                uart_putchar('%');
                uart_putchar(*p);
            }
        } else {
            uart_putchar(*p);
        }
        p++;
    }
}
