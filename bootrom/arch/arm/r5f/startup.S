/**
 * @file startup.S
 * @brief ARM Cortex-R5F Startup Code - 4-Stage Boot Flow
 * 
 * STAGE 1: Power On Reset & Startup
 * STAGE 2: Minimal Initialization
 */

.syntax unified
.cpu cortex-r5
.fpu vfpv3-d16
.thumb
/* Choose Thumb-2 for save memory in ROM */

/* ============================================================================
 * Vector Table
 * ============================================================================ */
.section .vectors, "a"
.align 8    /* 2^8 = 256 bytes alignment for vector table */
.global _vector_table
_vector_table:
    ldr pc, =reset_handler      /* Reset */
    ldr pc, =undef_handler       /* Undefined Instruction */
    ldr pc, =svc_handler         /* Supervisor Call */
    ldr pc, =prefetch_handler    /* Prefetch Abort */
    ldr pc, =abort_handler       /* Data Abort */
    .word 0                      /* Reserved */
    ldr pc, =irq_handler         /* IRQ */
    ldr pc, =fiq_handler         /* FIQ */

/* Memory layout (defined in linker script) */
.extern _stack_top
.extern _irq_stack_top
.extern _fiq_stack_top
.extern _svc_stack_top
.extern _abt_stack_top
.extern _und_stack_top
.extern _data_load_addr
.extern _data_start
.extern _data_end
.extern _bss_start
.extern _bss_end

/* ============================================================================
 * STAGE 1: Power On Reset & Startup
 * ============================================================================ */
.section .text.reset, "ax"
.thumb_func
.align 4
.global reset_handler
reset_handler:
    /* ============================================
     * 1. Safety Init: Disable interrupts
     * ============================================ */
    cpsid i                       /* Disable IRQ */
    cpsid f                       /* Disable FIQ */
    
    /* ============================================
     * 2. Disable Watchdog (stub - call C function)
     * ============================================ */
    bl watchdog_disable
    
    /* ============================================
     * 3. Multi-core Check: Verify Primary Core
     *    MPIDR[1:0] = 0 for primary core
     * ============================================ */
    mrc p15, 0, r0, c0, c0, 5    /* Read MPIDR */
    ands r0, r0, #0x03           /* Extract Affinity Level 0 (Core ID) */
    bne secondary_core_loop      /* If not 0, this is a secondary core */
    
    /* Primary core continues */
    b primary_core_continue
    
secondary_core_loop:
    wfi                           /* Wait for interrupt */
    b secondary_core_loop
    
primary_core_continue:
    /* ============================================
     * 4. Reset Cause Detection (call C function)
     * ============================================ */
    bl platform_get_reset_cause
    
    /* ============================================
     * 5. System Cleanup: Disable MPU, Caches, Branch Prediction
     *    CRITICAL: Must be done before any memory access
     * ============================================ */
    
    /* Disable MPU */
    mrc p15, 0, r0, c1, c0, 0    /* Read SCTLR */
    bic r0, r0, #(1 << 0)        /* Clear M bit (MPU enable) */
    mcr p15, 0, r0, c1, c0, 0    /* Write SCTLR */
    dsb                           /* Data Synchronization Barrier */
    isb                           /* Instruction Synchronization Barrier */
    
    /* Disable I-Cache */
    mrc p15, 0, r0, c1, c0, 0    /* Read SCTLR */
    bic r0, r0, #(1 << 12)       /* Clear I bit (I-Cache enable) */
    mcr p15, 0, r0, c1, c0, 0    /* Write SCTLR */
    isb
    
    /* Disable D-Cache */
    mrc p15, 0, r0, c1, c0, 0    /* Read SCTLR */
    bic r0, r0, #(1 << 2)        /* Clear C bit (D-Cache enable) */
    mcr p15, 0, r0, c1, c0, 0    /* Write SCTLR */
    dsb
    isb
    
    /* Invalidate I-Cache */
    mov r0, #0
    mcr p15, 0, r0, c7, c5, 0    /* ICIALLU - Invalidate I-Cache */
    isb
    
    /* Invalidate D-Cache */
    bl invalidate_dcache_all
    
    /* Disable Branch Prediction */
    mrc p15, 0, r0, c1, c0, 0    /* Read SCTLR */
    bic r0, r0, #(1 << 11)       /* Clear Z bit (Branch prediction) */
    mcr p15, 0, r0, c1, c0, 0    /* Write SCTLR */
    isb
    
    /* ============================================================================
     * STAGE 2: Minimal Initialization
     * ============================================================================ */

    /* ============================================
     * 1. Enable VFP/FPU
     * ============================================ */
    mrc p15, 0, r0, c1, c0, 2    /* Read CPACR */
    orr r0, r0, #(0xF << 20)     /* Enable CP10 and CP11 */
    mcr p15, 0, r0, c1, c0, 2    /* Write CPACR */
    isb                           /* Instruction Synchronization Barrier */
    mov r0, #0x40000000          /* Enable VFP */
    vmsr fpexc, r0

    /* ============================================
     * 2. Stack Setup: Initialize SP for ALL ARM Modes
     * ============================================ */
    
    /* System/User mode stack */
    cpsid i, #0x1F               /* System mode */
    ldr r0, =_stack_top
    mov sp, r0
    
    /* IRQ mode stack */
    cpsid i, #0x12               /* IRQ mode */
    ldr r0, =_irq_stack_top
    mov sp, r0
    
    /* FIQ mode stack */
    cpsid i, #0x11               /* FIQ mode */
    ldr r0, =_fiq_stack_top
    mov sp, r0
    
    /* SVC mode stack */
    cpsid i, #0x13               /* SVC mode */
    ldr r0, =_svc_stack_top
    mov sp, r0
    
    /* Abort mode stack */
    cpsid i, #0x17               /* Abort mode */
    ldr r0, =_abt_stack_top
    mov sp, r0
    
    /* Undefined mode stack */
    cpsid i, #0x1B               /* Undefined mode */
    ldr r0, =_und_stack_top
    mov sp, r0
    
    /* Return to System mode */
    cpsid i, #0x1F               /* System mode */
    
    /* ============================================
     * 3. Clear BSS section (must be done early)
     * ============================================ */
    ldr r0, =_bss_start
    ldr r1, =_bss_end
    mov r2, #0
clear_bss_loop:
    cmp r0, r1
    bge bss_cleared
    str r2, [r0], #4
    b clear_bss_loop
bss_cleared:
    
    /* ============================================
     * 4. Copy initialized data from ROM to RAM
     * ============================================ */
    ldr r0, =_data_load_addr
    ldr r1, =_data_start
    ldr r2, =_data_end
copy_data_loop:
    cmp r1, r2
    bge data_copied
    ldr r3, [r0], #4
    str r3, [r1], #4
    b copy_data_loop
data_copied:
    
    /* ============================================
     * 5. TCM & ECC Init: Enable ATCM and BTCM, Zeroize for ECC
     * ============================================ */
    bl tcm_init_and_zeroize
    
    /* ============================================
     * 6. MPU Setup: Define memory regions
     * ============================================ */
    bl mpu_setup
    
    /* ============================================
     * 7. Enable Caches: Only AFTER MPU is enabled
     * ============================================ */
    bl enable_caches
    
    /* ============================================
     * 8. Vector Table Remap: Physical Remap TCM/OCM at 0x0
     * ============================================ */
    bl remap_vector_table
    
    /* ============================================
     * 9. Platform Initialization (C code)
     * ============================================ */
    bl platform_init
    
    /* ============================================
     * 10. Jump to main()
     * ============================================ */
    bl main
    
    /* If main returns, enter error handler */
error_loop:
    b error_loop

/* ============================================================================
 * Exception Handlers
 * ============================================================================ */
.thumb_func
undef_handler:
    b undef_handler

.thumb_func
svc_handler:
    b svc_handler

.thumb_func
prefetch_handler:
    b prefetch_handler

.thumb_func
abort_handler:
    b abort_handler

.thumb_func
irq_handler:
    push {r0-r12, lr}
    bl platform_irq_handler
    pop {r0-r12, lr}
    subs pc, lr, #4

.thumb_func
fiq_handler:
    push {r0-r7, lr}
    bl platform_fiq_handler
    pop {r0-r7, lr}
    subs pc, lr, #4

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * @brief Invalidate entire D-Cache
 * Simplified implementation using DCIALL (Data Cache Invalidate All)
 */
.thumb_func
invalidate_dcache_all:
    push {r0, lr}
    
    /* Invalidate entire D-Cache using DCIALL */
    mov r0, #0
    mcr p15, 0, r0, c7, c14, 6   /* DCIALL - Data Cache Invalidate All to PoU */
    
    dsb
    isb
    
    pop {r0, pc}

/* External C functions */
.extern watchdog_disable
.extern platform_get_reset_cause
.extern tcm_init_and_zeroize
.extern mpu_setup
.extern enable_caches
.extern remap_vector_table
.extern platform_init
.extern main
.extern platform_irq_handler
.extern platform_fiq_handler

.end
