#pragma once
#include <cpthook_int.h>
#include <cpthook_anal.h>
#include <cpthook_utils.h>
#include <cpthook_ir.h>
#include <cpthook_temu.h>
#include <fadec-enc.h>

#define HOOKSIZE 14

#pragma pack(push, 1)
typedef struct _CPTHOOK_CTX
{
    PCALLING_CONVENTION CallingConvention;
    union
    {
        unsigned char _rctx[128];

        struct
        {
            unsigned long long rax;
            unsigned long long rcx;
            unsigned long long rdx;
            unsigned long long rbx;
            unsigned long long rsp;
            unsigned long long rbp;
            unsigned long long rsi;
            unsigned long long rdi;
            unsigned long long r8;
            unsigned long long r9;
            unsigned long long r10;
            unsigned long long r11;
            unsigned long long r12;
            unsigned long long r13;
            unsigned long long r14;
            unsigned long long r15;
        } x64regs;

        struct
        {
            unsigned long eax;
            unsigned long ecx;
            unsigned long edx;
            unsigned long ebx;
            unsigned long esp;
            unsigned long ebp;
            unsigned long esi;
            unsigned long edi;
        } x32regs;
    };

    uintptr_t EntryHook;
    uintptr_t ExitHook;
} CPTHOOK_CTX, *PCPTHOOK_CTX;
#pragma pack(pop)

typedef void(__fastcall *HOOKFNC)(CPTHOOK_CTX Context);

typedef struct _HOOK_ENTRY
{
    bool Enabled;
    uintptr_t OriginalEntryBytes[HOOKSIZE + 15];
    size_t OriginalEntrySize;
    uintptr_t OriginalExitBytes[HOOKSIZE + 15];
    size_t OriginalExitSize;
    uintptr_t HookTrampoline;
    PCPTHOOK_CTX HookContext;
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct _HOOK_LIST
{
    unsigned long Size;
    unsigned long Count;
    PHOOK_ENTRY Entries;
} HOOK_LIST, *PHOOK_LIST;

extern PHOOK_LIST HookList;
extern bool HookListInitialized;

bool cpthk_init(void);
void cpthk_deinit(void);
bool cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook);
bool cpthk_unhook(uintptr_t FunctionAddress);
