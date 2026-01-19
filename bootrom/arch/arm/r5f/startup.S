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
.global _TCM_A_Region
.global _TCM_B_Region
.equ _TCM_A_REGION, 0x00000000         /* Base address ATCM */
.equ _TCM_B_REGION, 0x20000000         /* Base address BTCM */

.equ ATCM_SIZE, 0x00008000             /* Size of ATCM - 32 KB */
.equ BTCM_SIZE, 0x00008000             /* Size of BTCM - 32 KB */

_vector_table:
    ldr pc, =reset_handler             /* Reset */
    ldr pc, =undef_handler             /* Undefined Instruction */
    ldr pc, =svc_handler               /* Supervisor Call */
    ldr pc, =prefetch_handler          /* Prefetch Abort */
    ldr pc, =abort_handler             /* Data Abort */
    .word 0                            /* Reserved */
    ldr pc, =irq_handler               /* IRQ */
    ldr pc, =fiq_handler               /* FIQ */

/* Memory layout (defined in linker script) */
.extern _stack_top
.extern _irq_stack_top
.extern _fiq_stack_top
.extern _svc_stack_top
.extern _abt_stack_top
.extern _und_stack_top
.extern _stack_bottom
.extern _irq_stack_bottom
.extern _fiq_stack_bottom
.extern _svc_stack_bottom
.extern _abt_stack_bottom
.extern _und_stack_bottom
.extern _data_load_addr
.extern _data_start
.extern _data_end
.extern _bss_start
.extern _bss_end
.extern _heap_start
.extern _heap_end
.extern _text_start
.extern _text_end

/* ============================================================================
 * STAGE 1: Power On Reset & Startup
 * ============================================================================ */
.section .text.reset, "ax"
.thumb_func
.align 4
.global reset_handler
reset_handler:
    /* Initialize processor registers to 0 */
    mov	r0,#0
    mov	r1,#0
    mov	r2,#0
    mov	r3,#0
    mov	r4,#0
    mov	r5,#0
    mov	r6,#0
    mov	r7,#0
    mov	r8,#0
    mov	r9,#0
    mov	r10,#0
    mov	r11,#0
    mov	r12,#0

    /* ============================================
     * 1. Safety Init: Disable interrupts
     * ============================================ */
    cpsid i                            /* Disable IRQ */
    cpsid f                            /* Disable FIQ */
    
    /* ============================================
     * 2. Disable Watchdog (stub - call C function)
     * ============================================ */
    bl watchdog_disable
    
    /* ============================================
     * 3. Multi-core Check: Verify Primary Core
     *    MPIDR[1:0] = 0 for primary core
     * ============================================ */
    @ For QEMU testing: Skip multi-core check
    #ifndef BOOTROM_DEV_MODE
        mrc p15, 0, r0, c0, c0, 5      /* Read MPIDR */
        ands r0, r0, #0x03             /* Extract Affinity Level 0 (Core ID) */
        bne secondary_core_loop        /* If not 0, this is a secondary core */
    #endif

    /* Primary core continues */
    b primary_core_continue
    
secondary_core_loop:
    wfi                                /* Wait for interrupt */
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
    mrc p15, 0, r0, c1, c0, 0          /* Read SCTLR */
    bic r0, r0, #(1 << 0)              /* Clear M bit (MPU enable) */
    mcr p15, 0, r0, c1, c0, 0          /* Write SCTLR */
    dsb                                /* Data Synchronization Barrier */
    isb                                /* Instruction Synchronization Barrier */
    
    /* Disable I-Cache */
    mrc p15, 0, r0, c1, c0, 0          /* Read SCTLR */
    bic r0, r0, #(1 << 12)             /* Clear I bit (I-Cache enable) */
    mcr p15, 0, r0, c1, c0, 0          /* Write SCTLR */
    isb
    
    /* Disable D-Cache */
    mrc p15, 0, r0, c1, c0, 0          /* Read SCTLR */
    bic r0, r0, #(1 << 2)              /* Clear C bit (D-Cache enable) */
    mcr p15, 0, r0, c1, c0, 0          /* Write SCTLR */
    dsb
    isb
    
    /* Invalidate I-Cache */
    mov r0, #0
    mcr p15, 0, r0, c7, c5, 0          /* ICIALLU - Invalidate I-Cache */
    isb
    
    /* Invalidate D-Cache - Temporaty */
    /* Need to add loop - invalidate_dcache_all */
    mov r0, #0
    mcr p15, 0, r0, c15, c5, 0         /* DCIALLU - Invalidate D-Cache */
    dsb
    isb
    
    /* Disable Branch Prediction */
    mrc p15, 0, r0, c1, c0, 0          /* Read SCTLR */
    bic r0, r0, #(1 << 11)             /* Clear Z bit (Branch prediction enable bit) */
    mcr p15, 0, r0, c1, c0, 0          /* Write SCTLR */
    isb
    
    /* ============================================================================
     * STAGE 2: Minimal Initialization
     * ============================================================================ */

    /* ============================================
     * 1. Enable VFP/FPU
     * ============================================ */
    mrc p15, 0, r0, c1, c0, 2          /* Read CPACR */
    orr r0, r0, #(0xF << 20)           /* Enable CP10 and CP11 */
    mcr p15, 0, r0, c1, c0, 2          /* Write CPACR */
    isb                                /* Instruction Synchronization Barrier */
    vmrs	r3, FPEXC
    orr	r0, r3, #(1<<30)               /* Enable VFP - bit 30 */
    vmsr FPEXC, r0

    /* clear the floating point register*/
	mov	r1,#0
	vmov	d0,r1,r1
	vmov	d1,r1,r1
	vmov	d2,r1,r1
	vmov	d3,r1,r1
	vmov	d4,r1,r1
	vmov	d5,r1,r1
	vmov	d6,r1,r1
	vmov	d7,r1,r1
	vmov	d8,r1,r1
	vmov	d9,r1,r1
	vmov	d10,r1,r1
	vmov	d11,r1,r1
	vmov	d12,r1,r1
	vmov	d13,r1,r1
	vmov	d14,r1,r1
	vmov	d15,r1,r1

    /* ============================================
     * 2. Stack Setup: Initialize SP for ALL ARM Modes
     * ============================================ */
    
    /* System/User mode stack */
    cpsid i, #0x1F                     /* System mode */
    ldr r0, =_stack_top
    mov sp, r0
    
    /* IRQ mode stack */
    cpsid i, #0x12                     /* IRQ mode */
    ldr r0, =_irq_stack_top
    mov sp, r0
    
    /* FIQ mode stack */
    cpsid i, #0x11                     /* FIQ mode */
    ldr r0, =_fiq_stack_top
    mov sp, r0
    
    /* SVC mode stack */
    cpsid i, #0x13                     /* SVC mode */
    ldr r0, =_svc_stack_top
    mov sp, r0
    
    /* Abort mode stack */
    cpsid i, #0x17                     /* Abort mode */
    ldr r0, =_abt_stack_top
    mov sp, r0
    
    /* Undefined mode stack */
    cpsid i, #0x1B                     /* Undefined mode */
    ldr r0, =_und_stack_top
    mov sp, r0
    
    /* Return to System mode */
    cpsid i, #0x1F                     /* System mode */
    
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
     * 4. Copy initialized data from ROM to OCRAM
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
    /* bl tcm_init_and_zeroize */
    /* Enable ATCM */
    mrc p15, 0, r1, c9, c1, 0
    tst r1, #0x1                       /* Test bit 0 to check if TCM is enabled */
    beq InitTCMB                       /* If ATCM is not enabled, go to BTCM initialization */
    orr r0, r0, #(0x1 << 0)
    mcr p15, 0, r0, c9, c1, 1          /* Enable ATCM */

InitTCMB:
    /* Enable BTCM */
    mcr p15, 0, r1, c9, c1, 0
    tst r1, #0x1
    beq InitTCMDone
    orr r0, r0, #(0x1 << 0)
    mcr p15, 0, r0, c9, c1, 0          /* Enable BTCM */

InitTCMDone:
    mrc p15, 0, r1, c15, c0, 0         /* Read SACR */
    orr r1, r1, #(0x3)                 /* Enable ATCMRMW and BTCMRMW */
    mcr p15, 0, r1, c15, c0, 0         /* Write SACR */
    isb

    /* Zeroize ATCM */
    ldr r0, =_TCM_A_REGION             /* Load base address of ATCM */
    ldr r1, =ATCM_SIZE                 /* Load the size of ATCM from the .equ directive */
    mov r2, #0                         /* Value to zeroize with (zero) */
ZeroATCMLoop:
    str r2, [r0], #4                   /* Store 0 at [r0] and increment r0 by 4 (word size) */
    subs r1, r1, #4                    /* Decrement the size counter by 4 bytes */
    bne ZeroATCMLoop                   /* Continue until size is zero */

    /* Zeroize BTCM */
    ldr r0, =_TCM_B_REGION             /* Load base address of BTCM */
    ldr r1, =BTCM_SIZE                 /* Load the size of BTCM from the .equ directive */
ZeroBTCMLoop:
    str r2, [r0], #4                   /* Store 0 at [r0] and increment r0 by 4 (word size) */
    subs r1, r1, #4                    /* Decrement the size counter by 4 bytes */
    bne ZeroBTCMLoop                   /* Continue until size is zero */
    dsb
    isb

    /* TCM ECC checks */
    mrc p15, 0, r0, c1, c0, 1          /* Read ACTLR */
    orr r0, r0, #(0x1 << 17)           /* Enable RSDIS bit 17 to disable the return stack */
    orr r0, r0, #(0x1 << 27)           /* Enable B1TCM ECC check */
    orr r0, r0, #(0x1 << 26)	       /* Enable B0TCM ECC check */
    orr r0, r0, #(0x1 << 25)	       /* Enable ATCM ECC check */
	bic	r0, r0, #(0x1 << 5)		       /* Generate abort on parity errors, with [5:3]=b 000*/
	bic r0, r0, #(0x1 << 4)
	bic	r0, r0, #(0x1 << 3)
    mcr p15, 0, r0, c1, c0, 1          /* Write ACTLR*/
	dsb
    
    /* ============================================
     * 6. MPU Setup: Define memory regions
     * ============================================ */
    /* bl mpu_setup */
    mrc p15, 0, r0, c1, c0, 0          /* Recheck Disable MPU */
    tst r1, #0x1
    beq SetupMPU
    bic r0, r0, #(0x1 << 0)
    mcr p15, 0, r0, c1, c0, 0
SetupMPU:
    /* Region 0: ROM - Read/Execute, Normal */
    /* Base: 0x00000000, Size: 64KB (2^16), Region: 0 */
    mov r0, #0
    mcr p15, 0, r0, c6, c2, 0          /* Region 0 */
    ldr r0, =0x00000000                /* Base address of Region 0 */
    mcr p15, 0, r0, c6, c1, 0          /* Write to Region Base Register */

    mrc p15, 0, r1, c6, c1, 2
    bic r1, r1, #(0x1F << 1)
    orr r1, r1, #(0x1F << 0)           /* Region size code for 64KB */
    mcr p15, 0, r1, c6, c1, 2          /* Write to Region Size and Enable Register */

    mrc p15, 0, r2, c6, c1, 4
    bic r2, r2, #(0x1 << 12)           /* Execute */
    bic r2, r2, #(0x7 << 8)
    orr r2, r2, #(0x5 << 8)            /* Privileged Mode Read Only and User Mode No Access */
    bic r2, r2, #(0x7 << 3)
    orr r2, r2, #(0x1 << 3)            /* Normal Memory */
    bic r2, r2, #(0x7 << 0)            /* Non-Cacheable, Non-shared, Non-Bufferable  */
    mcr p15, 0, r2, c6, c1, 4          /* Write to Region Access Control Register */


    /* Region 1: OCRAM - Read/Write/Execute, Normal, Cacheable */
    /* Base: 0x08000000, Size: 64KB (2^16), Region: 1 */
    mov r0, #1
    mcr p15, 0, r0, c6, c2, 0          /* Region 1 */
    ldr r0, =0x08000000                /* Base address of Region 0 */
    mcr p15, 0, r0, c6, c1, 0          /* Write to Region Base Register */

    mrc p15, 0, r1, c6, c1, 2
    bic r1, r1, #(0x1F << 1)
    orr r1, r1, #(0x1F << 0)           /* Region size code for 64KB */
    mcr p15, 0, r1, c6, c1, 2          /* Write to Region Size and Enable Register */

    mrc p15, 0, r2, c6, c1, 4
    bic r2, r2, #(0x1 << 12)           /* Execute */
    bic r2, r2, #(0x7 << 8)
    orr r2, r2, #(0x3 << 8)            /* Full Access */
    bic r2, r2, #(0x7 << 3)
    orr r2, r2, #(0x0 << 3)            /* Normal Memory */
    bic r2, r2, #(0x7 << 0)
    orr r2, r2, #(0x2 << 0)            /* Cacheable, Non-shared, Non-Bufferable  */
    mcr p15, 0, r2, c6, c1, 4          /* Write to Region Access Control Register */

    /* Region 2: Peripherals - Read/Write, Device, Non-cacheable */
    /* Base: 0x40000000, Size: 512MB (2^29), Region: 2 */
    mov r0, #2
    mcr p15, 0, r0, c6, c2, 0          /* Region 2 */
    ldr r0, =0x40000000                /* Base address of Region 0 */
    mcr p15, 0, r0, c6, c1, 0          /* Write to Region Base Register */

    mrc p15, 0, r1, c6, c1, 2
    bic r1, r1, #(0x1F << 1)
    orr r1, r1, #(0x39 << 0)           /* Region size code for 512MB */
    mcr p15, 0, r1, c6, c1, 2          /* Write to Region Size and Enable Register */

    mrc p15, 0, r2, c6, c1, 4
    orr r2, r2, #(0x1 << 12)           /* No Execute */
    bic r2, r2, #(0x7 << 8)
    orr r2, r2, #(0x3 << 8)            /* Full Access */
    bic r2, r2, #(0x7 << 3)
    orr r2, r2, #(0x0 << 3)            /* Device */
    bic r2, r2, #(0x7 << 0)
    orr r2, r2, #(0x1 << 0)            /* Non-Cacheable, Non-shared, Bufferable  */
    mcr p15, 0, r2, c6, c1, 4          /* Write to Region Access Control Register */

    mrc p15, 0, r0, c1, c0, 0          /* Enable MPU */
    orr r0, r0, #(0x1 << 0)
    mcr p15, 0, r0, c1, c0, 0
    dsb
    isb
    
    /* ============================================
     * 7. Enable Caches: Only AFTER MPU is enabled
     * ============================================ */
    /* bl enable_caches */
    mrc p15, 0, r0, c1, c0, 0
    orr r0, r0, #(0x1 << 2)            /* Enable D-Cache */
    orr r0, r0, #(0x1 << 11)           /* Enable Branch Prediction */
    orr r0, r0, #(0x1 << 12)           /* Enable I-Cache */
    mcr p15, 0, r0, c1, c0, 0
    dsb
    isb
    
    /* ============================================
     * 8. Vector Table Remap: Physical Remap TCM/OCM at 0x00000000
     * ============================================ */
    /* bl remap_vector_table */
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #(0x1 << 13)
    mcr p15, 0, r0, c1, c0, 0
    /* Enabled Branch Prediction in step 7 */

    
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
