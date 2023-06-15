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

#define HOOKSIZE 5

#pragma pack(push, 1)
typedef struct _CPTHOOK_CTX
{
    PCONTEXT CpuContext;
    PCALLING_CONVENTION CallingConvention;
    void(__stdcall *EntryHook)(struct _CPTHOOK_CTX *Context);
    void(__stdcall *ExitHook)(struct _CPTHOOK_CTX *Context);
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
    PCONTROL_FLOW_GRAPH Cfg;
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
CPTHK_STATUS cpthk_enable(uintptr_t FunctionAddress);
CPTHK_STATUS cpthk_disable(uintptr_t FunctionAddress);

uintptr_t *cpthk_get_param(PCPTHOOK_CTX ctx, int index);
void cpthk_set_param_int(PCPTHOOK_CTX ctx, int index, uintptr_t value);
void cpthk_set_param_float(PCPTHOOK_CTX ctx, int index, double value);
uintptr_t *cpthk_get_return_param(PCPTHOOK_CTX ctx);
void cpthk_set_return_param_int(PCPTHOOK_CTX ctx, uintptr_t value);
void cpthk_set_return_param_float(PCPTHOOK_CTX ctx, double value);

char *cpthk_str_error(CPTHK_STATUS Status);
char *cpthk_version(void);

#include <cpthook_utils.h>
