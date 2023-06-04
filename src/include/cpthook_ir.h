#pragma once
#include <cpthook_int.h>
#include <fadec.h>

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

typedef enum _TRACE_OP_TYPE
{
    TRACE_REG = 1,
    TRACE_OFFSET = 2,
    TRACE_IMMEDIATE = 4,
    TRACE_UNKNOWN = 8,
} TRACE_OP_TYPE;

typedef enum _TRACE_TYPE
{
    TRACE_TYPE_LOAD,
    TRACE_TYPE_STORE,
    TRACE_TYPE_MATH,
} TRACE_TYPE;

typedef union _INST_TRACE_VALUE
{
    struct
    {
        FdReg RegValue;
        bool gpr;
        bool fpu;
        bool vec;
    } RegValue;

    struct
    {
        FdReg Reg;
        bool gpr;
        bool fpu;
        bool vec;
        long long Offset;
    } OffsetValue;

    unsigned long long ImmediateValue;

} INST_TRACE_VALUE, *PINST_TRACE_VALUE;

typedef enum _INST_ACTION
{
    INST_ACTION_NONE,
    /* Those actions are used to handle stack operations */
    /* like push, pop, call, ret, etc. */
    /* ACTION_POP and ACTION_PUSH are used to handle */
    /* stack operations */
    /* ACTION_POP =  write to the register the value of the stack and decrement stack pointer */
    /* ACTION_PUSH = write to the stack the value of operand  and increment stack pointer */
    /* ACTION_CALL = write to the stack the next instruction address , increment stack pointer  and jump to the function */
    /* ACTION_RET = decrement stack pointer and jump to the address stored in the stack */
    INST_ACTION_POP,
    INST_ACTION_PUSH,
    INST_ACTION_CALL,
    INST_ACTION_RET,
    /* ACTION_POP: */
    /* [SP] = tmp */
    /* SP = SP + (8 or 4) */
    /* ACTION_PUSH: */
    /* tmp = [SP] */
    /* [SP] = 0 */
    /* SP = SP - (8 or 4) */
    /* ACTION_CALL: */
    /* [SP] = next instruction address */
    /* SP = SP + (8 or 4) */
    /* jump to function */
    /* ACTION_RET: */
    /* tmp = [SP] */
    /* SP = SP - (8 or 4) */
    /* jump to tmp */
} INST_ACTION;

typedef struct _INST_TRACE
{
    uintptr_t Address;
    FdInstr Instr;
    TRACE_TYPE Type;
    TRACE_OP_TYPE Lt;
    TRACE_OP_TYPE Rt;
    INST_TRACE_VALUE LValue;
    INST_TRACE_VALUE RValue;
    INST_ACTION Action;
} INST_TRACE, *PINST_TRACE;

typedef struct _INST_TRACE_LIST
{
    PINST_TRACE Entries;
    size_t Size;
} INST_TRACE_LIST, *PINST_TRACE_LIST;

typedef enum _TRACE_POINT
{
    TRACE_POINT_NONE,
    TRACE_POINT_CALLER,
    TRACE_POINT_CALLEE,
    TRACE_POINT_RETURN,
} TRACE_POINT;

PCALLING_CONVENTION cpthk_find_calling_convention(PCONTROL_FLOW_GRAPH Cfg);
