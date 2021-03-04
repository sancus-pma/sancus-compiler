    .section ".sm.text"
    .align 2
    .global __sm_verify
    .type __sm_verify,@function

    ; r13: address of stored ID
    ; r14: address of an SM
    ; r15: address of expected tag
__sm_verify:
    mov 0(r13), r12
    cmp #0x0000, r12
    jeq .Ltag

    ; we have a stored ID, check if it  matches with the SM
    mov r14, r15
    .word 0x1386
    cmp r12, r15
    jne .Lexit
    ret

.Ltag:
    ; we don't have an ID yet, calculate tag
    .word 0x1382
    cmp #0x0000, r15
    ; Try again if our ID is zero. This may happen if we got interrupted while calculating the ID
    jeq .Ltag 
    mov r15, 0(r13)
    ret

.Lexit:
    call #exit
