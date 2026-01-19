/**
 * @file sys_registers.h
 * @brief ARM Cortex-R5 CP15 System Register Access Helpers
 *
 * This header provides low-level accessors for CP15 system control registers
 * used in BootROM / FSBL early initialization:
 *
 *  - CPU identification (MPIDR)
 *  - System control (SCTLR)
 *  - Coprocessor access control (CPACR) for FPU/VFP
 *  - Auxiliary control (ACTLR) for ECC / TCM behavior
 *  - Cache information (CCSIDR)
 *  - TCM control and SoC auxiliary control
 *  - Memory barriers (DSB / DMB / ISB)
 */

#ifndef SYS_REGISTERS_H
#define SYS_REGISTERS_H

#include <stdint.h>

/* ========================================================================== */
/*  CPU Identification Registers                                              */
/* ========================================================================== */

/**
 * @brief Read MPIDR (Multiprocessor Affinity Register)
 * @return MPIDR value
 */
static inline uint32_t cp15_read_mpidr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c0, c0, 5" : "=r"(val));
    return val;
}

/* ========================================================================== */
/*  System Control Registers (SCTLR)                                          */
/* ========================================================================== */

/**
 * @brief Read SCTLR (System Control Register)
 */
static inline uint32_t cp15_read_sctlr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r"(val));
    return val;
}

/**
 * @brief Write SCTLR (System Control Register)
 * @param val New SCTLR value
 */
static inline void cp15_write_sctlr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r"(val));
    __asm volatile ("dsb");
    __asm volatile ("isb");
}

/* ========================================================================== */
/*  Coprocessor Access Control (CPACR) - FPU/VFP                              */
/* ========================================================================== */

/**
 * @brief Read CPACR (Coprocessor Access Control Register)
 */
static inline uint32_t cp15_read_cpacr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c1, c0, 2" : "=r"(val));
    return val;
}

/**
 * @brief Write CPACR (Coprocessor Access Control Register)
 */
static inline void cp15_write_cpacr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c1, c0, 2" :: "r"(val));
    __asm volatile ("isb");
}

/* ========================================================================== */
/*  Auxiliary Control Register (ACTLR)                                        */
/* ========================================================================== */

/**
 * @brief Read ACTLR (Auxiliary Control Register)
 */
static inline uint32_t cp15_read_actlr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c1, c0, 1" : "=r"(val));
    return val;
}

/**
 * @brief Write ACTLR (Auxiliary Control Register)
 */
static inline void cp15_write_actlr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c1, c0, 1" :: "r"(val));
    __asm volatile ("isb");
}

/* ========================================================================== */
/*  Cache Information Registers                                               */
/* ========================================================================== */

/**
 * @brief Read CCSIDR (Cache Size ID Register)
 */
static inline uint32_t cp15_read_ccsidr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r"(val));
    return val;
}

/* ========================================================================== */
/*  TCM Control Registers                                                     */
/* ========================================================================== */

/**
 * @brief Read TCMCR (TCM Control Register)
 */
static inline uint32_t cp15_read_tcmcr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c9, c1, 0" : "=r"(val));
    return val;
}

/**
 * @brief Write TCMCR (TCM Control Register)
 */
static inline void cp15_write_tcmcr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c9, c1, 0" :: "r"(val));
    __asm volatile ("isb");
}

/* ========================================================================== */
/*  SoC Auxiliary Control Register (Implementation Defined)                   */
/* ========================================================================== */

/**
 * @brief Read SACR / SoC Auxiliary Control Register
 */
static inline uint32_t cp15_read_sacr(void)
{
    uint32_t val;
    __asm volatile ("mrc p15, 0, %0, c15, c0, 0" : "=r"(val));
    return val;
}

/**
 * @brief Write SACR / SoC Auxiliary Control Register
 */
static inline void cp15_write_sacr(uint32_t val)
{
    __asm volatile ("mcr p15, 0, %0, c15, c0, 0" :: "r"(val));
    __asm volatile ("isb");
}

/* ========================================================================== */
/*  Memory Barrier Instructions                                               */
/* ========================================================================== */

/**
 * @brief Data Synchronization Barrier
 */
static inline void dsb(void)
{
    __asm volatile ("dsb sy" ::: "memory");
}

/**
 * @brief Data Memory Barrier
 *
 * Ensures ordering of memory accesses.
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
