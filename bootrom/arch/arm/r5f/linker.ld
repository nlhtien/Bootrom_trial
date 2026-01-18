/**
 * @file linker.ld
 * @brief Linker Script for ARM Cortex-R5F BootROM
 * * Memory Layout:
 * - ROM:      Boot ROM region (read-only code and data)
 * - OCRAM:    On-Chip RAM (Large data, buffers, heap)
 * - TCM:      Tightly Coupled Memory (Critical stacks for performance)
 */

ENTRY(reset_handler)

MEMORY
{
    /* ROM: BootROM code storage (256KB) */
    ROM (rx)      : ORIGIN = 0x00000000, LENGTH = 256K
    
    /* OCRAM: Data, bss, heap, buffer, image Decrypted */
    /* Note: Address 0x08000000 is typical for QEMU/SoC RAM */
    OCRAM (rwx)   : ORIGIN = 0x08000000, LENGTH = 1M
    
    /* TCM: Stacks mode CPU (64KB) */
    TCM (rwx)     : ORIGIN = 0x00200000, LENGTH = 64K
}

/* Stack sizes configuration */
_irq_stack_size = 0x1000;   /* 4KB */
_fiq_stack_size = 0x1000;   /* 4KB */
_svc_stack_size = 0x1000;   /* 4KB */
_abt_stack_size = 0x1000;   /* 4KB */
_und_stack_size = 0x1000;   /* 4KB */
_sys_stack_size = 0x1000;   /* 4KB */
_heap_size = 0x1000;        /* 4KB */

SECTIONS
{
    /* Vector table at the beginning of ROM */
    .vectors :
    {
        KEEP(*(.vectors))
    } > ROM

    /* Code section */
    .text :
    {
        _text_start = .;
        *(.text.reset)   /* Reset handler first */
        *(.text*)        /* All other code */
        *(.rodata*)      /* Read-only data */
        . = ALIGN(4);
        _text_end = .;
    } > ROM

    /* Initialized data */
    /* MOVED TO OCRAM to save TCM space */
    .data : AT> ROM
    {
        _data_start = .;
        *(.data*)
        . = ALIGN(4);
        _data_end = .;
    } > OCRAM 
    _data_load_addr = LOADADDR(.data);


    /* Uninitialized data (BSS) */
    /* MOVED TO OCRAM: This contains the large MbedTLS buffers */
    .bss (NOLOAD):
    {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;
    } > OCRAM

    /* Stacks remain in TCM for maximum speed */
    .stacks (NOLOAD) :
    {
        . = ALIGN(8);
        
        /* IRQ stack */
        _irq_stack_bottom = .;
        . += _irq_stack_size;
        _irq_stack_top = .;
        . = ALIGN(8);
        
        /* FIQ stack */
        _fiq_stack_bottom = .;
        . += _fiq_stack_size;
        _fiq_stack_top = .;
        . = ALIGN(8);
        
        /* SVC stack */
        _svc_stack_bottom = .;
        . += _svc_stack_size;
        _svc_stack_top = .;
        . = ALIGN(8);
        
        /* Abort stack */
        _abt_stack_bottom = .;
        . += _abt_stack_size;
        _abt_stack_top = .;
        . = ALIGN(8);
        
        /* Undefined stack */
        _und_stack_bottom = .;
        . += _und_stack_size;
        _und_stack_top = .;
        . = ALIGN(8);
        
        /* System/User stack */
        _stack_bottom = .;
        . += _sys_stack_size;
        _stack_top = .;
        . = ALIGN(8);
    } > TCM

    /* Heap section (Moved to OCRAM) */
    .heap (NOLOAD) :
    {
        . = ALIGN(8);
        _heap_start = .;
        . += _heap_size;
        _heap_end = .;
        . = ALIGN(8);
    } > OCRAM

    /* Sanity Checks */
    
    /* 1. Ensure TCM (Stacks) doesn't overflow */
    _TCM_end = ORIGIN(TCM) + LENGTH(TCM);
    ASSERT(_stack_top <= _TCM_end, "Error: TCM Stack overflow detected!")

    /* 2. Ensure OCRAM (Data/BSS/Heap) doesn't overflow */
    _OCRAM_end = ORIGIN(OCRAM) + LENGTH(OCRAM);
    ASSERT(_heap_end <= _OCRAM_end, "Error: OCRAM Data overflow detected!")

    /* Discard sections */
    /DISCARD/ :
    {
        libc.a ( * )
        libm.a ( * )
        libgcc.a ( * )
    }
}