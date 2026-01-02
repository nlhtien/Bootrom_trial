/**
 * @file platform.h
 * @brief Platform Abstraction Layer
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Interrupt control */
static inline void __disable_irq(void)
{
    __asm volatile ("cpsid i" : : : "memory");
}

static inline void __enable_irq(void)
{
    __asm volatile ("cpsie i" : : : "memory");
}

static inline void __NOP(void)
{
    __asm volatile ("nop");
}

/* Platform initialization */
void platform_init(void);

/* Watchdog control */
void watchdog_disable(void);

/* Reset cause */
uint32_t platform_get_reset_cause(void);

/* TCM and ECC initialization */
void tcm_init_and_zeroize(void);

/* MPU setup */
void mpu_setup(void);

/* Cache control */
void enable_caches(void);

/* Vector table remap */
void remap_vector_table(void);

/* IRQ/FIQ handlers (called from assembly) */
void platform_irq_handler(void);
void platform_fiq_handler(void);

/* Delay functions */
void platform_delay_us(uint32_t us);
void platform_delay_ms(uint32_t ms);

#endif /* PLATFORM_H */
