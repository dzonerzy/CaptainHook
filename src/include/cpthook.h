#pragma once
#include <cpthook_int.h>
#include <cpthook_anal.h>
#include <cpthook_ir.h>
#include <cpthook_temu.h>

// Versioning
#define MAJOR_VERSION "0"
#define MINOR_VERSION "1"
#define PATCH_VERSION "0"
#define CODENAME "BETA"

#define VERSION_STR(M, m, p, c) M "." m "." p " [" c "]"

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
    size_t FunctionSize;
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

typedef enum CPTHK_STATUS
{
    CPTHK_OK = 0,
    CPTHK_ERROR = 1,
    CPTHK_ALREADY_INITIALIZED = 2,
    CPTHK_NOT_INITIALIZED = 3,
    CPTHK_UNABLE_TO_CONTROL_THREADS = 4,
    CPTHK_UNABLE_TO_PROTECT_MEMORY = 5,
    CPTHK_HOOK_NOT_FOUND = 6,
    CPTHK_UNABLE_TO_BUILD_CFG = 7,
    CPTHK_OUT_OF_MEMORY = 8,
    CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION = 9,
    CPTHK_INTERNAL_ERROR = 10,
    CPTHK_UNABLE_TO_QUERY_MEMORY = 11,
} CPTHK_STATUS;

CPTHK_STATUS cpthk_init(void);
CPTHK_STATUS cpthk_uninit(void);
CPTHK_STATUS cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook);
CPTHK_STATUS cpthk_unhook(uintptr_t FunctionAddress);
char *cpthk_str_error(CPTHK_STATUS Status);
char *cpthk_version(void);

#include <cpthook_utils.h>
