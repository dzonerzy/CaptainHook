#pragma once
#include <cpthook_int.h>
#include <cpthook_anal.h>
#include <cpthook_ir.h>
#include <cpthook_temu.h>

#define HOOKSIZE 6

typedef struct uint128_t
{
    unsigned long long lo;
    unsigned long long hi;
} uint128_t;

#pragma pack(push, 1)
typedef struct _CPTHOOK_CTX
{
    PCALLING_CONVENTION CallingConvention;
    union
    {
        struct
        {
            unsigned char grp[128];
            unsigned char xmm[256];
        } regs;

        struct
        {
            unsigned long long regs[16];
            uint128_t xmm[16];
        } x64;

        struct
        {
            unsigned long regs[8];
            uint128_t xmm[8];
        } x32;
    };

    uintptr_t EntryHook;
    uintptr_t ExitHook;
    uintptr_t HookTrampolineEntry;
    uintptr_t HookTrampolineExit;
} CPTHOOK_CTX, *PCPTHOOK_CTX;
#pragma pack(pop)

typedef void(__stdcall *HOOKFNC)(PCPTHOOK_CTX Context);

typedef struct _HOOK_ENTRY
{
    uintptr_t FunctionAddress;
    bool Enabled;
    uint8_t OriginalEntryBytes[HOOKSIZE + 15];
    size_t OriginalEntrySize;
    uint8_t OriginalExitBytes[HOOKSIZE + 15];
    size_t OriginalExitSize;
    PCPTHOOK_CTX HookContext;
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct _HOOK_LIST
{
    unsigned long Size;
    unsigned long Count;
    PHOOK_ENTRY Entries;
} HOOK_LIST, *PHOOK_LIST;

typedef struct _JMP_TABLE
{
    uintptr_t *TableEntry;
    size_t TableCount;
    size_t TableCapacity;
} JMP_TABLE, *PJMP_TABLE;

extern JMP_TABLE JmpTable;
extern PHOOK_LIST HookList;
extern bool HookListInitialized;

bool cpthk_init(void);
void cpthk_uninit(void);
bool cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook);
bool cpthk_unhook(uintptr_t FunctionAddress);

#include <cpthook_utils.h>
