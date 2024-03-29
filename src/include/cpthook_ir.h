/*
 * cpthook (CaptainHook) - A prototype-less hooking library for Windows
 *
 * This library allows for hooking functions without the need to know their signatures,
 * providing a flexible solution for intercepting and manipulating function calls at runtime.
 *
 * Author: Daniele 'dzonerzy' Linguaglossa
 *
 * Created on: 06/04/2023
 *
 * License: MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
    ARGUMENT ReturnArg;
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
    TRACE_POINT_RETURN_PREV_BLOCK,
} TRACE_POINT;

typedef struct _IR_STACK_ENTRY
{
    PFLOW_GRAPH_NODE Node;
} IR_STACK_ENTRY, *PIR_STACK_ENTRY;

typedef struct _IR_STACK
{
    PIR_STACK_ENTRY Entries;
    unsigned long long Current;
    SIZE_T Size;
} IRSTACK, *PIRSTACK;

PCALLING_CONVENTION cpthk_find_calling_convention(PCONTROL_FLOW_GRAPH Cfg);
char *cpthk_format_trace(PINST_TRACE trace);
