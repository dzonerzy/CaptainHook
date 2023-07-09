#pragma once
#include <cpthook.h>

typedef enum _TEMU_FLAG
{
    FLAG_NONE = 0,
    FLAG_READ = 1,
    FLAG_WRITE = 2,
    FLAG_READ_WRITE = FLAG_READ | FLAG_WRITE,
} TEMU_FLAG;

typedef struct _TEMU_REGISTER
{
    TEMU_FLAG Flags;
    unsigned short OpCount;
    uintptr_t Value;
    unsigned long Timestamp;
} TEMU_REGISTER, *PTEMU_REGISTER;

typedef struct _TEMU_MEM
{
    uintptr_t Memory[0x1000];
    TEMU_FLAG Flags[0x1000];
    unsigned short OpCount[0x1000];
    unsigned long Timestamp[0x1000];
} TEMU_MEM, *PTEMU_MEM;

typedef struct _TEMU_CPU_CONTEXT
{
    TEMU_REGISTER GeneralRegisters[17]; // 16 + 1 for RIP
    TEMU_REGISTER FPURegisters[16];
    TEMU_REGISTER XMMRegisters[16];
    TEMU_MEM Stack;
    TEMU_MEM Mem;
} TEMU_CPU_CONTEXT, *PTEMU_CPU_CONTEXT;

typedef enum _TEMU_PRIORITIZE_FLAGS
{
    TEMU_PRIORITIZE_WRITE_FLAG = 1,
    TEMU_PRIORITIZE_READ_FLAG = 2,
} TEMU_PRIORITIZE_FLAGS;

typedef enum _TEMU_ANAL_FLAGS
{
    TEMU_NO_ANAL = 0,
    TEMU_ANAL_PARAM = 1,
    TEMU_ANAL_RETURN = 2,
} TEMU_ANAL_FLAGS;

typedef enum _TRACE_POSITION
{
    TRACE_POSITION_REG_GPR = 1,
    TRACE_POSITION_REG_FPU = 2,
    TRACE_POSITION_REG_VEC = 3,
    TRACE_POSITION_STACK = 4,
} TRACE_POSITION;

typedef struct _TRACE_LOG
{
    unsigned int Index;
    TRACE_POSITION Position;
    INST_TRACE Trace;
    unsigned long Timestamp;
} TRACE_LOG, *PTRACE_LOG;

typedef struct _TEMU_TRACE_LOGGER
{
    uintptr_t StartAddress;
    size_t TraceCount;
    TRACE_LOG TraceLog[0x1000];
} TEMU_TRACE_LOGGER, *PTEMU_TRACE_LOGGER;

extern unsigned long BaseTimestamp;

PCALLING_CONVENTION
cpthk_emu_traces(PINST_TRACE_LIST list, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags, TEMU_ANAL_FLAGS AnalFlags);
void cpthk_emu_reset_regs(PTEMU_CPU_CONTEXT Cpu);
void cpthk_print_regs(PTEMU_CPU_CONTEXT Cpu);
