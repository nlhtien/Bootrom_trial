/**
 * @file sys_registers.h
 * @brief System Register Access Functions (CP15)
 */

#ifndef SYS_REGISTERS_H
#define SYS_REGISTERS_H

#include <stdint.h>

/* CP15 Register Access Functions */

/**
 * @brief Read Multiprocessor Affinity Register (MPIDR)
 * @return MPIDR value
 */
static inline uint32_t read_mpidr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c0, c0, 5" : "=r" (val));
    return val;
}

/**
 * @brief Read System Control Register (SCTLR)
 * @return SCTLR value
 */
static inline uint32_t read_sctlr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r" (val));
    return val;
}

/**
 * @brief Write System Control Register (SCTLR)
 * @param val Value to write
 */
static inline void write_sctlr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c1, c0, 0" : : "r" (val));
    __asm volatile ("dsb");
    __asm volatile ("isb");
}

/**
 * @brief Read Cache Size ID Register (CCSIDR)
 * @return CCSIDR value
 */
static inline uint32_t read_ccsidr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r" (val));
    return val;
}

/**
 * @brief Data Synchronization Barrier
 */
static inline void dsb(void)
{
    __asm volatile ("dsb sy" ::: "memory");
}

/**
 * @brief Data Memory Barrier
 */
static inline void dmb(void)
{
    __asm volatile ("dmb sy" ::: "memory");
}

/**
 * @brief Instruction Synchronization Barrier
 */
static inline void isb(void)
{
    __asm volatile ("isb" ::: "memory");
}

#endif /* SYS_REGISTERS_H */
