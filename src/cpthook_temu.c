#include <cpthook.h>

unsigned long BaseTimestamp = 0;

static char *cpthk_gpr[] = {
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
};

static char *cpthk_xmm[] = {
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
};

static char *cpthk_fpu[] = {
    "st0",
    "st1",
    "st2",
    "st3",
    "st4",
    "st5",
    "st6",
    "st7",
};

void cpthk_print_regs(PTEMU_CPU_CONTEXT Cpu)
{
    printf("------------ REGS ---------\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%s: %08x (%c%c) (%d) ", cpthk_gpr[i], Cpu->GeneralRegisters[i].Value, Cpu->GeneralRegisters[i].Flags & FLAG_READ ? 'r' : '-', Cpu->GeneralRegisters[i].Flags & FLAG_WRITE ? 'w' : '-', Cpu->GeneralRegisters[i].OpCount);
        printf("%s: %08x (%c%c) (%d) ", cpthk_xmm[i], Cpu->XMMRegisters[i].Value, Cpu->XMMRegisters[i].Flags & FLAG_READ ? 'r' : '-', Cpu->XMMRegisters[i].Flags & FLAG_WRITE ? 'w' : '-', Cpu->XMMRegisters[i].OpCount);
        printf("\n");
    }
    printf("---------- FPU REGS ----------\n");
    for (int i = 0; i < 8; i++)
    {
        printf("%s: %08x (%c%c) (%d)\n", cpthk_fpu[i], Cpu->FPURegisters[i].Value, Cpu->FPURegisters[i].Flags & FLAG_READ ? 'r' : '-', Cpu->FPURegisters[i].Flags & FLAG_WRITE ? 'w' : '-', Cpu->FPURegisters[i].OpCount);
    }
    printf("------------ STACK -----------\n");
    for (uintptr_t i = Cpu->GeneralRegisters[FD_REG_BP].Value - (sizeof(uintptr_t) * 6); i < Cpu->GeneralRegisters[FD_REG_BP].Value + (sizeof(uintptr_t) * 6); i += sizeof(uintptr_t))
    {

        if (i == Cpu->GeneralRegisters[FD_REG_BP].Value)
            printf("%08x: %08x (%c%c) (%d) <- SP\n", i, Cpu->Stack.Memory[i], Cpu->Stack.Flags[i] & FLAG_READ ? 'r' : '-', Cpu->Stack.Flags[i] & FLAG_WRITE ? 'w' : '-', Cpu->Stack.OpCount[i]);
        else
            printf("%08x: %08x (%c%c) (%d)\n", i, Cpu->Stack.Memory[i], Cpu->Stack.Flags[i] & FLAG_READ ? 'r' : '-', Cpu->Stack.Flags[i] & FLAG_WRITE ? 'w' : '-', Cpu->Stack.OpCount[i]);
    }
}

void cpthk_emu_reset_regs(PTEMU_CPU_CONTEXT Cpu)
{
    // initialize the registers
    for (int i = 0; i < 16; i++)
    {
        if (i == FD_REG_SP || i == FD_REG_BP)
            Cpu->GeneralRegisters[i].Value = 2048;
        else
            Cpu->GeneralRegisters[i].Value = 2048;
        Cpu->GeneralRegisters[i].Flags = FLAG_NONE;
        Cpu->GeneralRegisters[i].OpCount = 0;
        Cpu->GeneralRegisters[i].Timestamp = 0;

        Cpu->XMMRegisters[i].Value = 2048;
        Cpu->XMMRegisters[i].Flags = FLAG_NONE;
        Cpu->XMMRegisters[i].OpCount = 0;
        Cpu->XMMRegisters[i].Timestamp = 0;

        Cpu->FPURegisters[i].Value = 2048;
        Cpu->FPURegisters[i].Flags = FLAG_NONE;
        Cpu->FPURegisters[i].OpCount = 0;
        Cpu->FPURegisters[i].Timestamp = 0;
    }

    // initialize the stack
    for (uintptr_t i = 0; i < 4096; i += 1)
    {
        Cpu->Stack.Memory[i] = 2048;
        Cpu->Stack.Flags[i] = FLAG_NONE;
        Cpu->Mem.Memory[i] = 2048;
        Cpu->Mem.Flags[i] = FLAG_NONE;
        Cpu->Stack.OpCount[i] = 0;
        Cpu->Stack.Timestamp[i] = 0;
        Cpu->Mem.OpCount[i] = 0;
        Cpu->Mem.Timestamp[i] = 0;
    }
}

void cpthk_mov_reg_reg(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{

    uintptr_t *dst = NULL;

    if (trace->LValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->FPURegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Value;
    }

    if (trace->RValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value;
    }
    else if (trace->RValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Value;
    }
    else if (trace->RValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->FPURegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->FPURegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->FPURegisters[trace->RValue.RegValue.RegValue].Value;
    }
}

void cpthk_mov_reg_imm(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;

    if (trace->LValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->FPURegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Value;
    }

    *dst = trace->RValue.ImmediateValue;
}

void cpthk_mov_reg_offset(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;

    if (trace->LValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        Cpu->FPURegisters[trace->LValue.RegValue.RegValue].OpCount++;
        dst = &Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Value;
    }

    if (trace->RValue.OffsetValue.gpr)
    {
        if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
        {
            if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            *dst = Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                *dst = Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
            }
        }
    }
}

void cpthk_mov_offset_reg(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;

    // Left side
    if (trace->LValue.OffsetValue.gpr)
    {
        if (trace->LValue.OffsetValue.Reg == FD_REG_SP || trace->LValue.OffsetValue.Reg == FD_REG_BP)
        {
            dst = &Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset];
            if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
            {
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] |= FLAG_WRITE;
                Cpu->Stack.Timestamp[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] = BaseTimestamp++ + 0x1000;
            }
            if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] & FLAG_WRITE)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] &= ~FLAG_WRITE;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset]++;
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset < 0x1000)
            {
                dst = &Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset];
                if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
                {
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] |= FLAG_WRITE;
                    Cpu->Mem.Timestamp[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] = BaseTimestamp++ + 0x1000;
                }
                if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] & FLAG_WRITE)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] &= ~FLAG_WRITE;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset]++;
            }
        }
    }

    // Right side

    if (trace->RValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value;
    }
    else if (trace->RValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Value;
    }
    else if (trace->RValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->FPURegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        Cpu->FPURegisters[trace->RValue.RegValue.RegValue].OpCount++;
        *dst = Cpu->FPURegisters[trace->RValue.RegValue.RegValue].Value;
    }
}

void cpthk_mov_offset_imm(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;

    if (trace->LValue.OffsetValue.gpr)
    {
        if (trace->LValue.OffsetValue.Reg == FD_REG_SP || trace->LValue.OffsetValue.Reg == FD_REG_BP)
        {
            dst = &Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset];
            if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
            {
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] |= FLAG_WRITE;
                Cpu->Stack.Timestamp[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] = BaseTimestamp++ + 0x1000;
            }
            if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] & FLAG_WRITE)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] &= ~FLAG_WRITE;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset]++;
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset < 0x1000)
            {
                dst = &Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset];
                if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
                {
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] |= FLAG_WRITE;
                    Cpu->Mem.Timestamp[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] = BaseTimestamp++ + 0x1000;
                }
                if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] & FLAG_WRITE)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset] &= ~FLAG_WRITE;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->LValue.OffsetValue.Reg].Value + trace->LValue.OffsetValue.Offset]++;
            }
        }
    }

    *dst = trace->RValue.ImmediateValue;
}

void cpthk_lea_reg_offset(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;
    // Left side is always a register

    if (trace->LValue.RegValue.gpr)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
    }
    else if (trace->LValue.RegValue.vec)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
    }
    else if (trace->LValue.RegValue.fpu)
    {
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Value;
        Cpu->FPURegisters[trace->LValue.RegValue.RegValue].OpCount++;
    }

    // Right side is an offset but don't read memory pointed by it just calculate the address

    if (trace->RValue.OffsetValue.gpr)
    {
        *dst = Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset;
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Flags |= FLAG_READ;
        Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].OpCount++;
    }
}

void cpthk_add_reg_reg(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value += Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value += Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Value;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
    }
}

void cpthk_add_reg_imm(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value += trace->RValue.ImmediateValue;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value += trace->RValue.ImmediateValue;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
}

void cpthk_add_reg_offset(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
    }

    if (trace->RValue.OffsetValue.gpr)
    {
        if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
        {
            if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            *dst += Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                *dst += Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
            }
        }
    }
    else if (trace->RValue.OffsetValue.vec)
    {
        if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
        {
            if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            *dst += Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                *dst += Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
            }
        }
    }
}

void cpthk_sub_reg_reg(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value -= Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value -= Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Value;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG)
            Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Flags |= FLAG_READ;
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
}

void cpthk_sub_reg_imm(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value -= trace->RValue.ImmediateValue;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value -= trace->RValue.ImmediateValue;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
    }
}

void cpthk_sub_reg_offset(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    uintptr_t *dst = NULL;
    // only GRP
    if (trace->LValue.RegValue.gpr)
    {
        Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value;
    }
    else if (trace->LValue.RegValue.vec)
    {
        Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].OpCount++;
        if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        {
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags |= FLAG_WRITE;
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Timestamp = BaseTimestamp++;
        }
        if (Flags & TEMU_PRIORITIZE_READ_FLAG && Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags & FLAG_WRITE)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Flags &= ~FLAG_WRITE;
        dst = &Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value;
    }

    if (trace->RValue.OffsetValue.gpr)
    {
        if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
        {
            if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            *dst -= Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                *dst -= Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
            }
        }
    }
    else if (trace->RValue.OffsetValue.vec)
    {
        if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
        {
            if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
            Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            *dst -= Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
        }
        else
        {
            if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                *dst -= Cpu->Mem.Memory[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset];
            }
        }
    }
}

void cpthk_emu_pop(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    switch (trace->Lt)
    {
    case TRACE_REG:
        if (trace->LValue.RegValue.gpr)
            Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value = Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value];
        else if (trace->LValue.RegValue.vec)
            Cpu->XMMRegisters[trace->LValue.RegValue.RegValue].Value = Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value];
        else if (trace->LValue.RegValue.fpu)
            Cpu->FPURegisters[trace->LValue.RegValue.RegValue].Value = Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value];
        break;
    default:
        break;
    }

    if (Flags & TEMU_PRIORITIZE_READ_FLAG)
        Cpu->Stack.Flags[trace->RValue.RegValue.RegValue] |= FLAG_READ;
    Cpu->Stack.OpCount[trace->RValue.RegValue.RegValue]++;
    Cpu->GeneralRegisters[FD_REG_SP].Value += sizeof(uintptr_t);
}

void cpthk_emu_push(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    Cpu->GeneralRegisters[FD_REG_SP].Value -= sizeof(uintptr_t);

    switch (trace->Rt)
    {
    case TRACE_REG:
        if (trace->LValue.RegValue.gpr)
            Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value] = Cpu->GeneralRegisters[trace->RValue.RegValue.RegValue].Value;
        else if (trace->LValue.RegValue.vec)
            Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value] = Cpu->XMMRegisters[trace->RValue.RegValue.RegValue].Value;
        else if (trace->LValue.RegValue.fpu)
            Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value] = Cpu->FPURegisters[trace->RValue.RegValue.RegValue].Value;
        break;
    case TRACE_IMMEDIATE:
        Cpu->Stack.Memory[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value] = trace->RValue.ImmediateValue;
        break;
    case TRACE_OFFSET:
        if (trace->RValue.OffsetValue.gpr)
        {
            if (trace->RValue.OffsetValue.Reg == FD_REG_SP || trace->RValue.OffsetValue.Reg == FD_REG_BP)
            {
                if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                    Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
            }
            else
            {
                if (Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset < 0x1000)
                {
                    if (Flags & TEMU_PRIORITIZE_READ_FLAG)
                        Cpu->Mem.Flags[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset] |= FLAG_READ;
                    Cpu->Mem.OpCount[Cpu->GeneralRegisters[trace->RValue.OffsetValue.Reg].Value + trace->RValue.OffsetValue.Offset]++;
                }
            }
        }
        break;
    default:
        break;
    }

    if (Flags & TEMU_PRIORITIZE_WRITE_FLAG)
        Cpu->Stack.Flags[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value] |= FLAG_WRITE;
    Cpu->Stack.OpCount[Cpu->GeneralRegisters[trace->LValue.RegValue.RegValue].Value]++;
}

void cpthk_emu_call(PINST_TRACE trace, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags)
{
    Cpu->GeneralRegisters[FD_REG_SP].Value -= sizeof(uintptr_t);
    Cpu->Stack.Memory[Cpu->GeneralRegisters[FD_REG_SP].Value] = 0xf000c0de;
}

void cpthk_log_param_trace(PTEMU_CPU_CONTEXT Cpu, PTEMU_TRACE_LOGGER Logger, PINST_TRACE Trace, TEMU_FLAG EmuFlags)
{
    // loop all registers and stack and search for register or stack that has been both read and written
    bool bSkip = false;
    // start with general purpose registers
    for (size_t i = 0; i < 16; i++)
    {
        if (i == FD_REG_BP || i == FD_REG_SP)
            continue;

        for (size_t j = 0; j < Logger->TraceCount; j++)
        {
            if (i == Logger->TraceLog[j].Index && Logger->TraceLog[j].Position == TRACE_POSITION_REG_GPR)
            {
                bSkip = true;
                break;
            }
        }

        if (bSkip)
        {
            bSkip = false;
            continue;
        }
        else
        {
            // check if the register has been both read and written
            if (Cpu->GeneralRegisters[i].Flags == EmuFlags)
            {
                Logger->TraceLog[Logger->TraceCount].Index = i;
                Logger->TraceLog[Logger->TraceCount].Position = TRACE_POSITION_REG_GPR;
                Logger->TraceLog[Logger->TraceCount].Timestamp = Cpu->GeneralRegisters[i].Timestamp;
                memcpy(&Logger->TraceLog[Logger->TraceCount].Trace, Trace, sizeof(INST_TRACE));
                Logger->TraceCount++;
            }
        }
    }

    // now do the same for xmm registers
    for (size_t i = 0; i < 16; i++)
    {
        for (size_t j = 0; j < Logger->TraceCount; j++)
        {
            if (i == Logger->TraceLog[j].Index && Logger->TraceLog[j].Position == TRACE_POSITION_REG_VEC)
            {
                bSkip = true;
                break;
            }

            if (bSkip)
            {
                break;
            }
        }

        if (bSkip)
        {
            bSkip = false;
            continue;
        }
        else
        {
            // check if the register has been both read and written
            if (Cpu->XMMRegisters[i].Flags == EmuFlags)
            {
                Logger->TraceLog[Logger->TraceCount].Index = i;
                Logger->TraceLog[Logger->TraceCount].Position = TRACE_POSITION_REG_VEC;
                Logger->TraceLog[Logger->TraceCount].Timestamp = Cpu->XMMRegisters[i].Timestamp;
                memcpy(&Logger->TraceLog[Logger->TraceCount].Trace, Trace, sizeof(INST_TRACE));
                Logger->TraceCount++;
            }
        }
    }

    // now do the same for fpu registers
    for (size_t i = 0; i < 8; i++)
    {
        for (size_t j = 0; j < Logger->TraceCount; j++)
        {
            if (i == Logger->TraceLog[j].Index && Logger->TraceLog[j].Position == TRACE_POSITION_REG_FPU)
            {
                bSkip = true;
                break;
            }

            if (bSkip)
            {
                break;
            }
        }

        if (bSkip)
        {
            bSkip = false;
            continue;
        }
        else
        {
            // check if the register has been both read and written
            if (Cpu->FPURegisters[i].Flags == EmuFlags)
            {
                Logger->TraceLog[Logger->TraceCount].Index = i;
                Logger->TraceLog[Logger->TraceCount].Position = TRACE_POSITION_REG_FPU;
                Logger->TraceLog[Logger->TraceCount].Timestamp = Cpu->FPURegisters[i].Timestamp;
                memcpy(&Logger->TraceLog[Logger->TraceCount].Trace, Trace, sizeof(INST_TRACE));
                Logger->TraceCount++;
            }
        }
    }

    // now do the same for stack
    for (size_t i = 0; i < 0x1000; i++)
    {
        for (size_t j = 0; j < Logger->TraceCount; j++)
        {
            if (i == Logger->TraceLog[j].Index && Logger->TraceLog[j].Position == TRACE_POSITION_STACK)
            {
                bSkip = true;
                break;
            }

            if (bSkip)
            {
                break;
            }
        }

        if (bSkip)
        {
            bSkip = false;
            continue;
        }
        else
        {
            // check if the register has been both read and written
            if (Cpu->Stack.Flags[i] == EmuFlags)
            {
                Logger->TraceLog[Logger->TraceCount].Index = i;
                Logger->TraceLog[Logger->TraceCount].Position = TRACE_POSITION_STACK;
                Logger->TraceLog[Logger->TraceCount].Timestamp = Cpu->Stack.Timestamp[i];
                memcpy(&Logger->TraceLog[Logger->TraceCount].Trace, Trace, sizeof(INST_TRACE));
                Logger->TraceCount++;
            }
        }
    }
}

PCALLING_CONVENTION cpthk_emu_traces(PINST_TRACE_LIST list, PTEMU_CPU_CONTEXT Cpu, TEMU_PRIORITIZE_FLAGS Flags, TEMU_ANAL_FLAGS AnalFlags)
{
    BaseTimestamp = 0;
    PCALLING_CONVENTION cc = malloc(sizeof(CALLING_CONVENTION));
    memset(cc, 0, sizeof(CALLING_CONVENTION));

    cc->ReturnRegister = FD_REG_NONE;

    TEMU_TRACE_LOGGER logger;
    memset(&logger, 0, sizeof(TEMU_TRACE_LOGGER));

    // start the emulation
    for (size_t i = 0; i < list->Size; i++)
    {
        PINST_TRACE trace = &list->Entries[i];
        switch (trace->Action)
        {
        case INST_ACTION_POP:
            cpthk_emu_pop(trace, Cpu, Flags);
            break;
        case INST_ACTION_PUSH:
            cpthk_emu_push(trace, Cpu, Flags);
            break;
        case INST_ACTION_CALL:
            cpthk_emu_call(trace, Cpu, Flags);
            break;
        case INST_ACTION_NONE:
            switch (trace->Type)
            {
            case TRACE_TYPE_STORE:
                switch (trace->Lt)
                {
                case TRACE_REG:
                    switch (trace->Rt)
                    {
                    case TRACE_REG:
                        cpthk_mov_reg_reg(trace, Cpu, Flags);
                        break;
                    case TRACE_IMMEDIATE:
                        cpthk_mov_reg_imm(trace, Cpu, Flags);
                        break;
                    case TRACE_OFFSET:
                        cpthk_mov_reg_offset(trace, Cpu, Flags);
                        break;
                    default:
                        break;
                    }
                    break;
                case TRACE_OFFSET:
                    // Set WRITE flag on the memory location
                    switch (trace->Rt)
                    {
                    case TRACE_REG:
                        cpthk_mov_offset_reg(trace, Cpu, Flags);
                        break;
                    case TRACE_IMMEDIATE:
                        cpthk_mov_offset_imm(trace, Cpu, Flags);
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
                break;
            case TRACE_TYPE_LOAD:
                switch (FD_TYPE(&trace->Instr))
                {
                case FDI_LEA:
                    /* All the LEAs*/
                    // only lea_reg_off can be used to read from memory
                    switch (trace->Lt)
                    {
                    case TRACE_REG:
                        switch (trace->Rt)
                        {
                        case TRACE_OFFSET:
                            cpthk_lea_reg_offset(trace, Cpu, Flags);
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
                break;
            case TRACE_TYPE_MATH:
                switch (FD_TYPE(&trace->Instr))
                {
                case FDI_SSE_ADDSS:
                case FDI_ADD:
                    switch (trace->Lt)
                    {
                    case TRACE_REG:
                        switch (trace->Rt)
                        {
                        case TRACE_REG:
                            cpthk_add_reg_reg(trace, Cpu, Flags);
                            break;
                        case TRACE_IMMEDIATE:
                            cpthk_add_reg_imm(trace, Cpu, Flags);
                            break;
                        case TRACE_OFFSET:
                            cpthk_add_reg_offset(trace, Cpu, Flags);
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                case FDI_SSE_SUBSS:
                case FDI_SUB:
                    switch (trace->Lt)
                    {
                    case TRACE_REG:
                        switch (trace->Rt)
                        {
                        case TRACE_REG:
                            cpthk_sub_reg_reg(trace, Cpu, Flags);
                            break;
                        case TRACE_IMMEDIATE:
                            cpthk_sub_reg_imm(trace, Cpu, Flags);
                            break;
                        case TRACE_OFFSET:
                            cpthk_sub_reg_offset(trace, Cpu, Flags);
                            break;
                        default:
                            break;
                        }
                        break;
                    default:
                        break;
                    }
                    break;
                default:
                    break;
                }
                break;
            }
            break;
        default:
            break;
        }

        if (AnalFlags == TEMU_ANAL_PARAM)
        {
            cpthk_log_param_trace(Cpu, &logger, trace, FLAG_READ | FLAG_WRITE);
        }
        else if (AnalFlags == TEMU_ANAL_RETURN)
        {
            cpthk_log_param_trace(Cpu, &logger, trace, FLAG_WRITE);
        }
    }

    switch (AnalFlags)
    {
    case TEMU_NO_ANAL:
        free(cc);
        return NULL;
    case TEMU_ANAL_PARAM:

        if (logger.TraceCount > 0)
        {
            cc->EntryHookAddress = logger.TraceLog[0].Trace.Address;
        }

        // reorder the arguments based on FdReg value
        for (size_t i = 0; i < logger.TraceCount; i++)
        {
            for (size_t j = 0; j < logger.TraceCount; j++)
            {

                // from smaller to bigger
                if (logger.TraceLog[i].Trace.Rt == TRACE_REG && logger.TraceLog[j].Trace.Rt == TRACE_REG)
                {
                    if (logger.TraceLog[i].Trace.RValue.RegValue.RegValue < logger.TraceLog[j].Trace.RValue.RegValue.RegValue)
                    {
                        // swap
                        TRACE_LOG tmp = logger.TraceLog[i];
                        logger.TraceLog[i] = logger.TraceLog[j];
                        logger.TraceLog[j] = tmp;
                    }
                }
                else if (logger.TraceLog[i].Trace.Rt == TRACE_OFFSET && logger.TraceLog[j].Trace.Rt == TRACE_OFFSET)
                {
                    if (logger.TraceLog[i].Trace.RValue.OffsetValue.Offset < logger.TraceLog[j].Trace.RValue.OffsetValue.Offset)
                    {
                        // swap
                        TRACE_LOG tmp = logger.TraceLog[i];
                        logger.TraceLog[i] = logger.TraceLog[j];
                        logger.TraceLog[j] = tmp;
                    }
                }
            }
        }

        for (size_t i = 0; i < logger.TraceCount; i++)
        {
            cc->ArgumentsCount++;
            cc->Arguments[i].Used = true;
            cc->Arguments[i].Size = FD_SIZE(&logger.TraceLog[i].Trace.Instr);
            memcpy(&cc->Arguments[i].Instruction, &logger.TraceLog[i].Trace.Instr, sizeof(FdInstr));

            switch (logger.TraceLog[i].Trace.Rt)
            {
            case TRACE_REG:
                cc->Arguments[i].Position.Reg = logger.TraceLog[i].Trace.RValue.RegValue.RegValue;
                break;
            case TRACE_OFFSET:
                cc->Arguments[i].Position.Reg = logger.TraceLog[i].Trace.RValue.RegValue.RegValue;
                cc->Arguments[i].Position.Offset = logger.TraceLog[i].Trace.RValue.OffsetValue.Offset;
                break;
            default:
                break;
            }

            switch (logger.TraceLog[i].Position)
            {
            case TRACE_POSITION_REG_GPR:
                cc->Arguments[i].Gpr = true;
                cc->Arguments[i].Type = ARG_TYPE_INT;
                break;
            case TRACE_POSITION_REG_FPU:
                cc->Arguments[i].Fpu = true;
                cc->Arguments[i].Type = ARG_TYPE_FLOAT;
                break;
            case TRACE_POSITION_REG_VEC:
                cc->Arguments[i].Vec = true;
                cc->Arguments[i].Type = ARG_TYPE_FLOAT;
                break;
            case TRACE_POSITION_STACK:
                cc->Arguments[i].Stack = true;
                cc->Arguments[i].Type = FD_MODE == 32 ? ARG_TYPE_INT : ARG_TYPE_STRUCT;
                break;
            default:
                break;
            }
        }
        break;
    case TEMU_ANAL_RETURN:
        if (logger.TraceCount > 0)
        {
            // loop from tracecount - 1 to 0 (0 included)
            for (size_t i = logger.TraceCount - 1; i >= 0; i--)
            {
                if (logger.TraceLog[i].Trace.Lt == TRACE_REG && (logger.TraceLog[i].Trace.LValue.RegValue.RegValue != FD_REG_SP && logger.TraceLog[i].Trace.LValue.RegValue.RegValue != FD_REG_BP))
                {
                    cc->ReturnRegister = logger.TraceLog[i].Trace.LValue.RegValue.RegValue;
                    cc->ExitHookAddress = logger.TraceLog[i].Trace.Address + FD_SIZE(&logger.TraceLog[i].Trace.Instr);
                    break;
                }
            }
        }
        else
        {
            cc->ReturnRegister = FD_REG_NONE;
            cc->ExitHookAddress = 0;
        }
        break;
    default:
        break;
    }

    return cc;
}
