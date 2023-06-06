#pragma once
#include <cpthook.h>
#include <tlhelp32.h>

typedef enum _THREAD_OP
{
    THREAD_OP_SUSPEND,
    THREAD_OP_RESUME
} THREAD_OP;

// JMP [RIP-OFFSET]
#define JMP_RELATIVE64(Address, Destination)  \
    *(unsigned char *)(Address) = 0xFF;       \
    *(unsigned char *)((Address) + 1) = 0x25; \
    *(DWORD *)((Address) + 2) = (DWORD)(((uintptr_t)Destination) - ((uintptr_t)Address) - 6);

#define JMP_ABSOLUTE64(Address, Destination)  \
    *(unsigned char *)(Address) = 0xFF;       \
    *(unsigned char *)((Address) + 1) = 0x25; \
    *(unsigned short *)((Address) + 2) = 0x0; \
    *(uintptr_t *)((Address) + 6) = (uintptr_t)((uintptr_t)Destination);

#define JMP_RELATIVE32(Address, Destination) \
    *(unsigned char *)(Address) = 0xE9;      \
    *(DWORD *)((Address) + 1) = (DWORD)((uintptr_t)Destination) - (DWORD)((uintptr_t)Address) - 5;

uintptr_t cpthk_find_pattern(uint8_t *pBuffer, DWORD dwBufferSize, const char *pPattern);
void cpthk_get_text_section(uintptr_t *textSection, size_t *textSize);
bool cpthk_operate_threads(THREAD_OP Operation);
bool cpthk_protect_function(PCONTROL_FLOW_GRAPH Cfg, DWORD Protection);
size_t cpthk_populate_hook_context(uintptr_t HookContext, uintptr_t Address, uintptr_t Trampoline, int mode);
void cpthk_stub(void);
void cpthk_stub_end(void);
size_t cpthk_write_jmp(uintptr_t Address, uintptr_t Destination, unsigned char *saveBuffer);
