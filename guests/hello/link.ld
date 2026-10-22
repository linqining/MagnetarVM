OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = 0x1000;
    .text : {
        *(.text.entry)
        *(.text*)
        . = ALIGN(4);
    }

    . = 0x10000000;
    .rodata : {
        *(.rodata*)
        *(.srodata*)
    }
    .data : {
        *(.data*)
        *(.sdata*)
    }
    .bss : {
        *(.bss*)
        *(.sbss*)
        *(COMMON)
    }
}
