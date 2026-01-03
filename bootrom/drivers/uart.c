/**
 * @file uart.c
 * @brief UART Driver Implementation (with QEMU semihosting support)
 */

#include "uart.h"
#include "platform/platform.h"

/* For QEMU semihosting support */
#define SEMIHOSTING_SVC 0xAB
#define SYS_WRITEC 0x03  /* Write character to console */
#define SYS_WRITE0 0x04  /* Write string to console */

/* Semihosting function for QEMU */
static inline int semihosting_call(int operation, void *parameter)
{
    int result;
    __asm__ volatile (
        "mov r0, %1\n"
        "mov r1, %2\n"
        "svc %3\n"
        "mov %0, r0\n"
        : "=r" (result)
        : "r" (operation), "r" (parameter), "i" (SEMIHOSTING_SVC)
        : "r0", "r1", "memory"
    );
    return result;
}

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
#ifdef QEMU_SEMIHOSTING
    /* Use semihosting for QEMU output */
    semihosting_call(SYS_WRITEC, &c);
#else
    /* Hardware UART implementation */
    /* Wait until transmit FIFO is not full */
    while (UART_REG(FR) & UART_FR_TXFF);
    
    /* Send character */
    UART_REG(DR) = c;
#endif
    
    /* If newline, send carriage return too */
    if (c == '\n') {
        uart_putchar('\r');
    }
}

void uart_puts(const char *str)
{
#ifdef QEMU_SEMIHOSTING
    /* Use semihosting for QEMU output */
    semihosting_call(SYS_WRITE0, (void *)str);
#else
    while (*str) {
        uart_putchar(*str++);
    }
#endif
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
