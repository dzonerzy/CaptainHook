bits 64
default rel
SECTION .text
cpthook_stub:
    sub rsp, 0x20
    ;push rax
    ;push rcx
    ;push rdx
    ;push rbx
    mov [rsp+0x18], rax
    mov [rsp+0x10], rcx
    mov [rsp+0x08], rdx
    mov [rsp], rbx
    call here
    here:
    ; save return address
    pop rax ; <- RIP
    ; make rax point to CPTHOOK_CTX and accoutn for the pushed rax and rbx and call 1f
    lea rax, [rax + 0x1a1b1c1d]
    ; now rax points to CPTHOOK_CTX
    ; save the full context
    ; keep in mind that old rax now is in [rsp + 0x18]
    add rax, 0x08
    mov rbx, [rsp+0x18]
    mov [rax], rbx ; save rax
    mov rbx, [rsp + 0x010]
    mov [rax + 0x08], rbx ; save rcx
    mov rbx, [rsp + 0x08]
    mov [rax + 0x10], rbx ; save rdx
    mov rbx, [rsp]
    mov [rax + 0x18], rbx ; save rbx
    mov rbx, rsp
    add rbx, 0x20
    mov [rax + 0x20], rbx      ; save rsp
    mov [rax + 0x28], rbp      ; save rbp
    mov [rax + 0x30], rsi      ; save rsi
    mov [rax + 0x38], rdi      ; save rdi
    mov [rax + 0x40], r8       ; save r8
    mov [rax + 0x48], r9       ; save r9
    mov [rax + 0x50], r10      ; save r10
    mov [rax + 0x58], r11      ; save r11
    mov [rax + 0x60], r12      ; save r12
    mov [rax + 0x68], r13      ; save r13
    mov [rax + 0x70], r14      ; save r14
    mov [rax + 0x78], r15      ; save r15
    movss [rax + 0x80], xmm0   ; save xmm0
    movss [rax + 0x90], xmm1   ; save xmm1
    movss [rax + 0xa0], xmm2   ; save xmm2
    movss [rax + 0xb0], xmm3   ; save xmm3
    movss [rax + 0xc0], xmm4   ; save xmm4
    movss [rax + 0xd0], xmm5   ; save xmm5
    movss [rax + 0xe0], xmm6   ; save xmm6
    movss [rax + 0xf0], xmm7   ; save xmm7
    movss [rax + 0x100], xmm8  ; save xmm8
    movss [rax + 0x110], xmm9  ; save xmm9
    movss [rax + 0x120], xmm10 ; save xmm10
    movss [rax + 0x130], xmm11 ; save xmm11
    movss [rax + 0x140], xmm12 ; save xmm12
    movss [rax + 0x150], xmm13 ; save xmm13
    movss [rax + 0x160], xmm14 ; save xmm14
    movss [rax + 0x170], xmm15 ; save xmm15
    ; we saved the full context
    ; now we can freely pop rax, rbx, rcx and rdx
    add rsp, 0x20
    lea rbx, [rax + 0x11223344] ; rbx points to HookEntry / HookExit
    lea rcx, [rax - 0x8]
    sub rsp, 0x10
    call [rbx] ; call the hook entry
    add rsp, 0x10
    ; now restore registers based on cpthk_ctx
    call here2
    here2:
    pop rax
    lea rax, [rax + 0x2a2b2c2d] ; rax now points to CPTHOOK_CTX
    add rax, 0x08               ; rax now points to the saved context
    sub rsp, 0x20
    mov rbx, [rax]              ; save rax
    mov [rsp + 0x18], rbx
    mov rbx, [rax + 0x08] ; save rcx
    mov [rsp + 0x10], rbx
    mov rbx, [rax + 0x10] ; save rdx
    mov [rsp + 0x08], rbx
    mov rbx, [rax + 0x18] ; save rbx
    mov [rsp], rbx
    mov rbx, rsp
    add rbx, 0x20
    mov rsp, rbx               ; restore rsp
    mov rbp, [rax + 0x28]      ; restore rbp
    mov rsi, [rax + 0x30]      ; restore rsi
    mov rdi, [rax + 0x38]      ; restore rdi
    mov r8, [rax + 0x40]       ; restore r8
    mov r9, [rax + 0x48]       ; restore r9
    mov r10, [rax + 0x50]      ; restore r10
    mov r11, [rax + 0x58]      ; restore r11
    mov r12, [rax + 0x60]      ; restore r12
    mov r13, [rax + 0x68]      ; restore r13
    mov r14, [rax + 0x70]      ; restore r14
    mov r15, [rax + 0x78]      ; restore r15
    movss xmm0, [rax + 0x80]   ; restore xmm0
    movss xmm1, [rax + 0x90]   ; restore xmm1
    movss xmm2, [rax + 0xa0]   ; restore xmm2
    movss xmm3, [rax + 0xb0]   ; restore xmm3
    movss xmm4, [rax + 0xc0]   ; restore xmm4
    movss xmm5, [rax + 0xd0]   ; restore xmm5
    movss xmm6, [rax + 0xe0]   ; restore xmm6
    movss xmm7, [rax + 0xf0]   ; restore xmm7
    movss xmm8, [rax + 0x100]  ; restore xmm8
    movss xmm9, [rax + 0x110]  ; restore xmm9
    movss xmm10, [rax + 0x120] ; restore xmm10
    movss xmm11, [rax + 0x130] ; restore xmm11
    movss xmm12, [rax + 0x140] ; restore xmm12
    movss xmm13, [rax + 0x150] ; restore xmm13
    movss xmm14, [rax + 0x160] ; restore xmm14
    movss xmm15, [rax + 0x170] ; restore xmm15
    ; now restore rax, rbx, rcx and rdx from the stack
    mov rax, [rsp - 0x8]  ; restore rax
    mov rcx, [rsp - 0x10] ; restore rcx
    mov rdx, [rsp - 0x18] ; restore rdx
    mov rbx, [rsp - 0x20] ; restore rbx
    jmp [$+6]            ; jump to the trampoline
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop