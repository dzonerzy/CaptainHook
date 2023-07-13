#pragma once
#include <cpthook_int.h>
#include <cpthook_anal.h>
#include <cpthook_ir.h>
#include <cpthook_temu.h>
#include <cpthook_js.h>

// Versioning
#define MAJOR_VERSION "0"
#define MINOR_VERSION "2"
#define PATCH_VERSION "1"
#define CODENAME "Rustic"
#define VERSION_STR(M, m, p, c) M "." m "." p " [" c "]"

// Hooking
#define HOOKSIZE 5

// Utilities
#define CPTHK_HOOK_NAME(fnc) cpthk_##fnc
#define CPTHK_HOOKFNC(fnc) void __stdcall cpthk_##fnc(PCPTHOOK_CTX ctx)
#if defined(_WIN64)
#define CPTHK_REG_AX(ctx) ((ctx)->CpuContext->Rax)
#define CPTHK_REG_BX(ctx) ((ctx)->CpuContext->Rbx)
#define CPTHK_REG_CX(ctx) ((ctx)->CpuContext->Rcx)
#define CPTHK_REG_DX(ctx) ((ctx)->CpuContext->Rdx)
#define CPTHK_REG_DI(ctx) ((ctx)->CpuContext->Rdi)
#define CPTHK_REG_SI(ctx) ((ctx)->CpuContext->Rsi)
#define CPTHK_REG_IP(ctx) ((ctx)->CpuContext->Rip)
#define CPTHK_REG_SP(ctx) ((ctx)->CpuContext->Rsp)
#define CPTHK_REG_BP(ctx) ((ctx)->CpuContext->Rbp)
#define CPTHK_REG_FLAGS(ctx) ((ctx)->CpuContext->EFlags)
#define CPTHK_REG_R8(ctx) ((ctx)->CpuContext->R8)
#define CPTHK_REG_R9(ctx) ((ctx)->CpuContext->R9)
#define CPTHK_REG_R10(ctx) ((ctx)->CpuContext->R10)
#define CPTHK_REG_R11(ctx) ((ctx)->CpuContext->R11)
#define CPTHK_REG_R12(ctx) ((ctx)->CpuContext->R12)
#define CPTHK_REG_R13(ctx) ((ctx)->CpuContext->R13)
#define CPTHK_REG_R14(ctx) ((ctx)->CpuContext->R14)
#define CPTHK_REG_R15(ctx) ((ctx)->CpuContext->R15)
#else
#define CPTHK_REG_AX(ctx) ((ctx)->CpuContext->Eax)
#define CPTHK_REG_BX(ctx) ((ctx)->CpuContext->Ebx)
#define CPTHK_REG_CX(ctx) ((ctx)->CpuContext->Ecx)
#define CPTHK_REG_DX(ctx) ((ctx)->CpuContext->Edx)
#define CPTHK_REG_DI(ctx) ((ctx)->CpuContext->Edi)
#define CPTHK_REG_SI(ctx) ((ctx)->CpuContext->Esi)
#define CPTHK_REG_IP(ctx) ((ctx)->CpuContext->Eip)
#define CPTHK_REG_SP(ctx) ((ctx)->CpuContext->Esp)
#define CPTHK_REG_BP(ctx) ((ctx)->CpuContext->Ebp)
#define CPTHK_REG_FLAGS(ctx) ((ctx)->CpuContext->EFlags)
#endif

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
    PHOOK_ENTRY *Entries;
} HOOK_LIST, *PHOOK_LIST;

typedef struct _TRAMP_ENTRY
{
    uintptr_t FunctionAddress;
    uintptr_t TrampolineAddress;
    PCONTROL_FLOW_GRAPH Cfg;
} TRAMP_ENTRY, *PTRAMP_ENTRY;

typedef struct _TRAMP_LIST
{
    unsigned long Size;
    unsigned long Count;
    PTRAMP_ENTRY *Entries;
} TRAMP_LIST, *PTRAMP_LIST;

typedef struct _JMP_TABLE
{
    uintptr_t *TableEntry;
    size_t TableCount;
    size_t TableCapacity;
} JMP_TABLE, *PJMP_TABLE;

extern PHOOK_LIST HookList;
extern PTRAMP_LIST TrampList;
extern bool CpthkInitialized;

typedef enum CPTHK_STATUS
{
    CPTHK_OK = 0,
    CPTHK_ERROR = 1,
    CPTHK_ALREADY_INITIALIZED = 2,
    CPTHK_NOT_INITIALIZED = 3,
    CPTHK_UNABLE_TO_CONTROL_THREADS = 4,
    CPTHK_UNABLE_TO_PROTECT_MEMORY = 5,
    CPTHK_HOOK_ALREADY_EXISTS = 6,
    CPTHK_HOOK_NOT_FOUND = 7,
    CPTHK_UNABLE_TO_BUILD_CFG = 8,
    CPTHK_OUT_OF_MEMORY = 9,
    CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION = 10,
    CPTHK_INTERNAL_ERROR = 11,
    CPTHK_UNABLE_TO_QUERY_MEMORY = 12,
} CPTHK_STATUS;

CPTHK_STATUS cpthk_init(void);
CPTHK_STATUS cpthk_uninit(void);
CPTHK_STATUS cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook);
CPTHK_STATUS cpthk_tiny_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook);
CPTHK_STATUS cpthk_unhook(uintptr_t FunctionAddress);
CPTHK_STATUS cpthk_tiny_unhook(uintptr_t FunctionAddress);
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
