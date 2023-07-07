#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum
{
    FD_REG_R0 = 0,
    FD_REG_R1,
    FD_REG_R2,
    FD_REG_R3,
    FD_REG_R4,
    FD_REG_R5,
    FD_REG_R6,
    FD_REG_R7,
    FD_REG_R8,
    FD_REG_R9,
    FD_REG_R10,
    FD_REG_R11,
    FD_REG_R12,
    FD_REG_R13,
    FD_REG_R14,
    FD_REG_R15,
    // Alternative names for byte registers
    FD_REG_AL = 0,
    FD_REG_CL,
    FD_REG_DL,
    FD_REG_BL,
    FD_REG_AH,
    FD_REG_CH,
    FD_REG_DH,
    FD_REG_BH,
    // Alternative names for general purpose registers
    FD_REG_AX = 0,
    FD_REG_CX,
    FD_REG_DX,
    FD_REG_BX,
    FD_REG_SP,
    FD_REG_BP,
    FD_REG_SI,
    FD_REG_DI,
    // FD_REG_IP can only be accessed in long mode (64-bit)
    FD_REG_IP = 0x10,
    // Segment register values
    FD_REG_ES = 0,
    FD_REG_CS,
    FD_REG_SS,
    FD_REG_DS,
    FD_REG_FS,
    FD_REG_GS,
    // No register specified
    FD_REG_NONE = 0x3f
} FdReg;

/** Internal use only. **/
typedef struct
{
    uint8_t type;
    uint8_t size;
    uint8_t reg;
    uint8_t misc;
} FdOp;

/** Never(!) access struct fields directly. Use the macros defined below. **/
typedef struct
{
    uint16_t type;
    uint8_t flags;
    uint8_t segment;
    uint8_t addrsz;
    uint8_t operandsz;
    uint8_t size;
    uint8_t evex;

    FdOp operands[4];

    int64_t disp;
    int64_t imm;

    uint64_t address;
} FdInstr;

typedef enum _ARG_TYPE
{
    ARG_TYPE_INT,
    ARG_TYPE_FLOAT,
    ARG_TYPE_STRUCT,
    ARG_TYPE_UNKNOWN
} ARG_TYPE;

typedef struct _ARG_POSITION
{
    // could be a register or a stack offset
    FdReg Reg;
    // if the argument is a struct, this field will be used
    // to store the offset of the struct
    long long Offset;
} ARG_POSITION, *PARG_POSITION;

typedef struct _ARGUMENT
{
    FdInstr Instruction;
    ARG_TYPE Type;
    size_t Size;
    ARG_POSITION Position;
    // is that argument already used?
    bool Used;
    bool Gpr;
    bool Fpu;
    bool Vec;
    bool Stack;
} ARGUMENT, *PARGUMENT;

typedef struct _CALLING_CONVENTION
{
    uintptr_t EntryHookAddress;
    uintptr_t ExitHookAddress;
    ARGUMENT Arguments[16];
    size_t ArgumentsCount;
    FdReg ReturnRegister;
} CALLING_CONVENTION, *PCALLING_CONVENTION;

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

typedef struct _CONTROL_FLOW_GRAPH
{
    uintptr_t Address;
    SIZE_T Size;
    DWORD Flags;
    struct _FLOW_GRAPH_NODE *Head;
    struct _FLOW_GRAPH_NODE *Tail;
    struct _CFG_HASHMAP *Map;
} CONTROL_FLOW_GRAPH, *PCONTROL_FLOW_GRAPH;

typedef struct _FLOW_GRAPH_NODE
{
    bool Visited;
    uintptr_t Address;
    SIZE_T Size;
    DWORD Flags;
    struct _FLOW_GRAPH_NODE *Prev;
    struct _FLOW_GRAPH_NODE *Next;
    struct _FLOW_GRAPH_NODE *Branch;
    struct _FLOW_GRAPH_NODE *BranchAlt;
    PCONTROL_FLOW_GRAPH Graph;
} FLOW_GRAPH_NODE, *PFLOW_GRAPH_NODE;

#define CPTHK_HOOK_NAME(fnc) cpthk_##fnc##_hook
#define CPTHK_HOOKFNC(fnc) void __stdcall cpthk_##fnc##_hook(PCPTHOOK_CTX ctx)

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

#if defined(__cplusplus)
extern "C"
{
#endif
    // Hooking
    CPTHK_STATUS cpthk_init(void);
    CPTHK_STATUS cpthk_uninit(void);
    CPTHK_STATUS cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook);
    CPTHK_STATUS cpthk_tiny_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook);
    CPTHK_STATUS cpthk_unhook(uintptr_t FunctionAddress);
    CPTHK_STATUS cpthk_tiny_unhook(uintptr_t FunctionAddress);
    CPTHK_STATUS cpthk_enable(uintptr_t FunctionAddress);
    CPTHK_STATUS cpthk_disable(uintptr_t FunctionAddress);

    // Parameters
    uintptr_t *cpthk_get_param(PCPTHOOK_CTX ctx, int index);
    void cpthk_set_param_int(PCPTHOOK_CTX ctx, int index, uintptr_t value);
    void cpthk_set_param_float(PCPTHOOK_CTX ctx, int index, double value);
    uintptr_t *cpthk_get_return_param(PCPTHOOK_CTX ctx);
    void cpthk_set_return_param_int(PCPTHOOK_CTX ctx, uintptr_t value);
    void cpthk_set_return_param_float(PCPTHOOK_CTX ctx, double value);

    // Control flow graph
    PCONTROL_FLOW_GRAPH cpthk_build_cfg(uintptr_t Address);

    // Calling convention
    PCALLING_CONVENTION cpthk_find_calling_convention(PCONTROL_FLOW_GRAPH Cfg);

    // Errors
    char *cpthk_str_error(CPTHK_STATUS Status);
#if defined(__cplusplus)
}
#endif