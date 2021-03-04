    .section ".sm.text"
    .align 2
    .global __sm_isr
    .type __sm_isr,@function

__sm_isr:
    ; r15 was pushed in sm_entry.s
    pop r15
    ; For the dummy entry, we do not use the sm_tmp or sm_irq_sp labels
    ; Instead, we restore all registers as they were during the interrupt.
    ; The downside is that we do not pass on the information on what IRQ happened
    ; to the ISR, but the upside is that we hand it an unfiltered state.
    ; If the ISR handles multiple IRQs, it can perform the caller_id itself.
    mov &__sm_tmp, r1
    br #__sm_isr_func
