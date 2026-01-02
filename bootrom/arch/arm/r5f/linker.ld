/**
 * @file linker.ld
 * @brief Linker Script for ARM Cortex-R5F BootROM
 * 
 * Memory Layout:
 * - BOOT_ROM: Boot ROM region (read-only code and data)
 * - OCRAM: On-Chip RAM for stacks, heap, and runtime data
 * - TCM: Tight Coupled Memory for stacks, heap, and runtime data
 */

ENTRY(reset_handler)

MEMORY
{
    BOOT_ROM (rx) : ORIGIN = 0x00000000, LENGTH = 64K
    /* OCRAM (rwx) : ORIGIN = 0x08000000, LENGTH = 64K */
    /* DTCM */
    TCM (rwx) : ORIGIN = 0x00200000, LENGTH = 64K
}

/* Stack sizes */
_irq_stack_size = 0x400;
_fiq_stack_size = 0x400;
_svc_stack_size = 0x400;
_abt_stack_size = 0x400;
_und_stack_size = 0x400;
_sys_stack_size = 0x1000;
_heap_size = 0x1000;

SECTIONS
{
    /* Vector table at the beginning of ROM */
    .vectors :
    {
        KEEP(*(.vectors))
    } > BOOT_ROM

    /* Code section */
    .text :
    {
        _text_start = .;
        *(.text.reset)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _text_end = .;
    } > BOOT_ROM

    /* Exception unwinding tables */
    .ARM.extab :
    {
        *(.ARM.extab*)
    } > BOOT_ROM

    .ARM.exidx :
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } > BOOT_ROM

    /* Initialized data (stored in ROM, copied to TCM at startup) */
    _data_load_addr = LOADADDR(.data);
    .data : AT(_text_end)
    {
        _data_start = .;
        *(.data*)
        . = ALIGN(4);
        _data_end = .;
    } > TCM

    /* Uninitialized data (BSS) */
    .bss :
    {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;
    } > TCM

    /* Stacks in TCM */
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

    /* Heap section */
    .heap (NOLOAD) :
    {
        . = ALIGN(8);
        _heap_start = .;
        . += _heap_size;
        _heap_end = .;
        . = ALIGN(8);
    } > TCM

    /* Ensure TCM doesn't overflow */
    _TCM_end = ORIGIN(TCM) + LENGTH(TCM);
    ASSERT(_heap_end <= _TCM_end, "TCM overflow detected!")

    /* Discard sections */
    /DISCARD/ :
    {
        libc.a ( * )
        libm.a ( * )
        libgcc.a ( * )
    }
}
