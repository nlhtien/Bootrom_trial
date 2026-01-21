/**
 * @file uart.c
 * @brief UART + Logging for BootROM (QEMU + HW)
 */

#include "uart.h"

/* ============================================================
 * QEMU semihosting
 * ============================================================ */
#ifdef ENABLE_QEMU_SEMIHOSTING

#define SEMIHOSTING_SVC 0xAB
#define SYS_WRITEC 0x03
#define SYS_WRITE0 0x04

static inline int semihosting_call(int op, void *arg)
{
    int ret;
    __asm__ volatile (
        "mov r0, %1\n"
        "mov r1, %2\n"
        "svc %3\n"
        "mov %0, r0\n"
        : "=r"(ret)
        : "r"(op), "r"(arg), "i"(SEMIHOSTING_SVC)
        : "r0", "r1", "memory"
    );
    return ret;
}

#endif

/* ============================================================
 * UART registers
 * ============================================================ */
typedef struct {
    volatile uint32_t DR;
    volatile uint32_t RSR;
    uint32_t RESERVED0[4];
    volatile uint32_t FR;
    uint32_t RESERVED1;
    volatile uint32_t ILPR;
    volatile uint32_t IBRD;
    volatile uint32_t FBRD;
    volatile uint32_t LCR_H;
    volatile uint32_t CR;
} uart_regs_t;

#define UART ((uart_regs_t *)UART0_BASE)

#define UART_FR_TXFF (1 << 5)
#define UART_FR_RXFE (1 << 4)

/* ============================================================
 * Internal state
 * ============================================================ */
static log_level_t g_log_level = LOG_LEVEL_INFO;

/* ============================================================
 * UART low level
 * ============================================================ */
int uart_init(uint32_t baudrate)
{
    (void)baudrate;

#ifndef ENABLE_QEMU_SEMIHOSTING
    /* TODO: real SoC init:
     * - enable clock
     * - pinmux
     * - set baud
     * - enable TX/RX
     */
#endif
    return 0;
}

void uart_putchar(char c)
{
#ifdef ENABLE_QEMU_SEMIHOSTING
    semihosting_call(SYS_WRITEC, &c);
#else
    while (UART->FR & UART_FR_TXFF);
    UART->DR = (uint32_t)c;
#endif

    if (c == '\n') {
        uart_putchar('\r');
    }
}

void uart_puts(const char *s)
{
#ifdef ENABLE_QEMU_SEMIHOSTING
    semihosting_call(SYS_WRITE0, (void *)s);
#else
    while (*s) {
        uart_putchar(*s++);
    }
#endif
}

char uart_getchar(void)
{
#ifndef ENABLE_QEMU_SEMIHOSTING
    while (UART->FR & UART_FR_RXFE);
    return (char)(UART->DR & 0xFF);
#else
    return 0;
#endif
}

/* ============================================================
 * Minimal printf
 * ============================================================ */
static void uart_put_hex(uint32_t v)
{
    const char *hex = "0123456789ABCDEF";
    for (int i = 28; i >= 0; i -= 4) {
        uart_putchar(hex[(v >> i) & 0xF]);
    }
}

static void uart_put_dec(uint32_t v)
{
    char buf[12];
    int i = 0;

    if (v == 0) {
        uart_putchar('0');
        return;
    }

    while (v) {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }

    while (i--) uart_putchar(buf[i]);
}

void uart_printf(const char *fmt, ...)
{
    const char *p = fmt;

    while (*p) {
        if (*p == '%' && *(p+1)) {
            p++;
            if (*p == 's') {
                uart_puts("(str)");
            } else if (*p == 'd' || *p == 'u') {
                uart_put_dec(0);
            } else if (*p == 'x') {
                uart_puts("0x");
                uart_put_hex(0);
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

/* ============================================================
 * Logging system
 * ============================================================ */
void log_set_level(log_level_t lvl)
{
    g_log_level = lvl;
}

static const char *log_prefix[] = {
    "[E] ",
    "[W] ",
    "[I] ",
    "[D] ",
};

void log_printf(log_level_t lvl, const char *fmt, ...)
{
#if defined(BOOTROM_DEV_MODE)

    if (lvl > g_log_level)
        return;

    uart_puts(log_prefix[lvl]);
    uart_puts(fmt);
    uart_puts("\n");

#else
    (void)lvl;
    (void)fmt;
#endif
}
