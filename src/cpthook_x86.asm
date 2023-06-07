bits 32
SECTION .text
cpthook_stub:
    sub esp, 0x10
    ;push eax
    ;push ecx
    ;push edx
    ;push ebx
    mov [esp + 0x0c], eax
    mov [esp + 0x08], ecx
    mov [esp + 0x04], edx
    mov [esp], ebx
    call here
    here:
    ; save return address
    pop eax
    ; make eax point to CPTHOOK_CTX and accoutn for the pushed eax and ebx and call 1f
    lea eax, [eax + 0x1a1b1c1d]
    ; now eax points to CPTHOOK_CTX
    ; save the full context
    add eax, 0x04 ; point to regs
    mov ebx, [esp + 0xc]
    mov [eax], ebx ; eax + 0x00 = CPTHOOK_CTX->eax
    mov ebx, [esp + 0x8]
    mov [eax + 0x04], ebx ; eax + 0x04 = CPTHOOK_CTX->ecx
    mov ebx, [esp + 0x4]
    mov [eax + 0x08], ebx ; eax + 0x08 = CPTHOOK_CTX->edx
    mov ebx, [esp]
    mov [eax + 0x0c], ebx ; eax + 0x0c = CPTHOOK_CTX->ebx
    mov ebx, esp
    add ebx, 0x10            ; ebx = esp + 0x10
    mov [eax + 0x10], ebx    ; eax + 0x10 = CPTHOOK_CTX->esp
    mov [eax + 0x14], ebp    ; eax + 0x14 = CPTHOOK_CTX->ebp
    mov [eax + 0x18], esi    ; eax + 0x18 = CPTHOOK_CTX->esi
    mov [eax + 0x1c], edi    ; eax + 0x1c = CPTHOOK_CTX->edi
    movss [eax + 0x20], xmm0 ; eax + 0x20 = CPTHOOK_CTX->xmm0
    movss [eax + 0x24], xmm1 ; eax + 0x24 = CPTHOOK_CTX->xmm1
    movss [eax + 0x28], xmm2 ; eax + 0x28 = CPTHOOK_CTX->xmm2
    movss [eax + 0x2c], xmm3 ; eax + 0x2c = CPTHOOK_CTX->xmm3
    movss [eax + 0x30], xmm4 ; eax + 0x30 = CPTHOOK_CTX->xmm4
    movss [eax + 0x34], xmm5 ; eax + 0x34 = CPTHOOK_CTX->xmm5
    movss [eax + 0x38], xmm6 ; eax + 0x38 = CPTHOOK_CTX->xmm6
    movss [eax + 0x3c], xmm7 ; eax + 0x3c = CPTHOOK_CTX->xmm7
    add esp, 0x10
    lea ebx, [eax + 0x11223344]
    lea ecx, [eax - 0x4]
    push ecx
    call [ebx]
    call here2
    here2:
    pop eax
    lea eax, [eax + 0x2a2b2c2d]
    add eax, 0x04  ; point to regs
    sub esp, 0x10  ; make room for the pushed regs
    mov ebx, [eax] ; eax + 0x00 = CPTHOOK_CTX->eax
    mov [esp + 0x0c], ebx
    mov ebx, [eax + 0x04]
    mov [esp + 0x08], ebx
    mov ebx, [eax + 0x08]
    mov [esp + 0x04], ebx
    mov ebx, [eax + 0x0c]
    mov [esp], ebx
    mov ebx, esp
    add ebx, 0x10 ; ebx = esp + 0x10
    mov esp, ebx  ; restore esp
    mov ebp, [eax + 0x14]
    mov esi, [eax + 0x18]
    mov edi, [eax + 0x1c]
    movss xmm0, [eax + 0x20]
    movss xmm1, [eax + 0x24]
    movss xmm2, [eax + 0x28]
    movss xmm3, [eax + 0x2c]
    movss xmm4, [eax + 0x30]
    movss xmm5, [eax + 0x34]
    movss xmm6, [eax + 0x38]
    movss xmm7, [eax + 0x3c]
    mov eax, [esp - 0x4]
    mov ecx , [esp - 0x8]
    mov edx , [esp - 0xc]
    mov ebx , [esp - 0x10]
    nop
    nop
    nop
    nop
    nop