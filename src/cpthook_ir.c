#include <cpthook.h>

size_t cpthk_backward_decode(uintptr_t Start, FdInstr *instr, uintptr_t EndAddress)
{
    uintptr_t start = Start;

    for (;;)
    {
        int ret = fd_decode((uint8_t *)start, 15, FD_MODE, start, instr);
        if (ret > 0)
        {
            start += ret;

            if (start == EndAddress)
            {
                return ret;
            }
        }
        else
        {
            // handle decoding error
            start += 1;
        }
    }
}

uintptr_t cpthk_get_n_prev_instrs(uintptr_t Address, unsigned int n, uintptr_t EndAddress, uintptr_t MinEndAddress, size_t *Size, bool StopAtCall)
{
    size_t instrSize = 0;

    for (unsigned int i = 0; i < n; i++)
    {

        FdInstr instr;
        size_t size = cpthk_backward_decode(Address, &instr, EndAddress);

        if (size == 0)
        {
            return 0;
        }

        instrSize += size;
        EndAddress -= size;

        // check if the instruction at EndAddress is a call
        if (StopAtCall)
            if (FD_TYPE(&instr) == FDI_CALL)
            {
                EndAddress += size;
                instrSize -= size;
                break;
            }

        if (EndAddress < MinEndAddress)
        {
            EndAddress += size;
            instrSize -= size;
            break;
        }
    }

    if (Size)
        *Size = instrSize;

    return EndAddress;
}

char *cpthk_format_trace(PINST_TRACE trace)
{
    char *buffer = malloc(256);
    memset(buffer, 0, 256);

    if (!buffer)
        return NULL;

    if (trace->Action == INST_ACTION_CALL)
    {
        strcat(buffer, "@CALL ");
        return buffer;
    }

    if (trace->Action == INST_ACTION_RET)
    {
        strcat(buffer, "@RET ");
        return buffer;
    }

    if (trace->Type == TRACE_TYPE_LOAD)
        strcat(buffer, "LD ");

    if (trace->Type == TRACE_TYPE_STORE)
        strcat(buffer, "ST ");

    if (trace->Type == TRACE_TYPE_MATH)
        strcat(buffer, "OP ");

    switch (trace->Lt)
    {
    case TRACE_REG:
        snprintf(buffer + 3, 128, "REG[%u]", trace->LValue.RegValue.RegValue);
        break;
    case TRACE_OFFSET:
        snprintf(buffer + 3, 128, "OFF[REG[%d] + %lld]", trace->LValue.OffsetValue.Reg, trace->LValue.OffsetValue.Offset);
        break;
    case TRACE_IMMEDIATE:
        snprintf(buffer + 3, 128, "IMM[%llu]", trace->LValue.ImmediateValue);
        break;
    case TRACE_UNKNOWN:
        strcat(buffer, "UNK");
        break;
    }

    strcat(buffer, " <-> ");
    size_t offset = strlen(buffer);

    switch (trace->Rt)
    {
    case TRACE_REG:
        if (trace->Type == TRACE_TYPE_MATH)
        {
            snprintf(buffer + offset, 128, "$0 %c REG[%u]", FD_TYPE(&trace->Instr) == FDI_ADD ? '+' : '-', trace->RValue.RegValue.RegValue);
        }
        else
        {
            snprintf(buffer + offset, 128, "REG[%u]", trace->RValue.RegValue.RegValue);
        }
        break;
    case TRACE_OFFSET:
        snprintf(buffer + offset, 128, "OFF[REG[%d] + %lld]", trace->RValue.OffsetValue.Reg, trace->RValue.OffsetValue.Offset);
        break;
    case TRACE_IMMEDIATE:
        if (trace->Type == TRACE_TYPE_MATH)
        {
            snprintf(buffer + offset, 128, "$0 %c IMM[%lld]", FD_TYPE(&trace->Instr) == FDI_ADD ? '+' : '-', trace->RValue.ImmediateValue);
        }
        else
        {
            snprintf(buffer + offset, 128, "IMM[%llu]", trace->RValue.ImmediateValue);
        }
        break;
    case TRACE_UNKNOWN:
        strcat(buffer, "UNK");
        break;
    }

    if (trace->Action == INST_ACTION_NONE)
    {
        strcat(buffer, " @NONE");
        return buffer;
    }

    if (trace->Action == INST_ACTION_PUSH)
    {
        strcat(buffer, " @PUSH");
        return buffer;
    }

    if (trace->Action == INST_ACTION_POP)
    {
        strcat(buffer, " @POP");
        return buffer;
    }

    return buffer;
}

void cpthk_print_traces(PINST_TRACE_LIST list)
{
    for (size_t i = 0; i < list->Size; i++)
    {
        char *buffer = cpthk_format_trace(&list->Entries[i]);

        if (buffer)
        {
            printf("%s\n", buffer);
            free(buffer);
        }
    }
}

PINST_TRACE_LIST cpthk_free_trace_list(PINST_TRACE_LIST list)
{
    if (list)
    {
        if (list->Entries)
            free(list->Entries);

        free(list);
    }

    return NULL;
}

PINST_TRACE_LIST cpthk_get_instr_trace(uint8_t *Buffer, size_t Size, TRACE_POINT point)
{

    PINST_TRACE_LIST trace = malloc(sizeof(INST_TRACE_LIST));

    if (!trace)
        return NULL;

    trace->Size = 0;

    uintptr_t Address = (uintptr_t)Buffer;

    do
    {
        FdInstr instr;
        memset(&instr, 0, sizeof(FdInstr));
        INST_TRACE traceEntry;
        memset(&traceEntry, 0, sizeof(INST_TRACE));

        traceEntry.Address = Address;

        int ret = fd_decode((uint8_t *)Address, 15, FD_MODE, 0, &instr);

        if (ret > 0)
        {
            FdInstrType iType = FD_TYPE(&instr);
            FdRegType regType;

            bool valid = false;

            switch (iType)
            {
            case FDI_PUSH:
                traceEntry.Type = TRACE_TYPE_STORE;
                traceEntry.Instr = instr;
                traceEntry.Action = INST_ACTION_PUSH;
                if (FD_OP_TYPE(&instr, 0) == FD_OT_REG)
                {
                    traceEntry.Lt = TRACE_OFFSET;
                    traceEntry.LValue.OffsetValue.Reg = FD_REG_SP;
                    traceEntry.LValue.OffsetValue.Offset = 0;
                    traceEntry.LValue.OffsetValue.gpr = true;
                    traceEntry.Rt = TRACE_REG;
                    traceEntry.RValue.RegValue.RegValue = FD_OP_REG(&instr, 0);
                    regType = FD_OP_REG_TYPE(&instr, 0);
                    if (regType == FD_RT_VEC)
                        traceEntry.LValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.LValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.LValue.RegValue.fpu = true;
                    valid = true;
                }
                else if (FD_OP_TYPE(&instr, 0) == FD_OT_IMM)
                {
                    traceEntry.Lt = TRACE_OFFSET;
                    traceEntry.LValue.OffsetValue.Reg = FD_REG_SP;
                    traceEntry.LValue.OffsetValue.Offset = 0;
                    traceEntry.LValue.OffsetValue.gpr = true;
                    traceEntry.Rt = TRACE_IMMEDIATE;
                    traceEntry.RValue.ImmediateValue = FD_OP_IMM(&instr, 0);
                    valid = true;
                }
                else
                {
                    valid = false;
                }
                break;
            case FDI_POP:
                traceEntry.Type = TRACE_TYPE_LOAD;
                traceEntry.Instr = instr;
                traceEntry.Action = INST_ACTION_POP;

                if (FD_OP_TYPE(&instr, 0) == FD_OT_REG)
                {
                    traceEntry.Lt = TRACE_REG;
                    traceEntry.LValue.RegValue.RegValue = FD_OP_REG(&instr, 0);
                    regType = FD_OP_REG_TYPE(&instr, 0);
                    if (regType == FD_RT_VEC)
                        traceEntry.LValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.LValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.LValue.RegValue.fpu = true;
                    traceEntry.Rt = TRACE_OFFSET;
                    traceEntry.RValue.OffsetValue.Reg = FD_REG_SP;
                    traceEntry.RValue.OffsetValue.Offset = 0;
                    traceEntry.RValue.OffsetValue.gpr = true;
                    valid = true;
                }
                else
                {
                    valid = false;
                }
                break;
            case FDI_SUB:
            case FDI_ADD:
                traceEntry.Type = TRACE_TYPE_MATH;
                traceEntry.Instr = instr;

                if (FD_OP_TYPE(&instr, 0) == FD_OT_REG)
                    traceEntry.Lt = TRACE_REG;
                else
                    traceEntry.Lt = TRACE_UNKNOWN;

                if (FD_OP_TYPE(&instr, 1) == FD_OT_REG)
                    traceEntry.Rt = TRACE_REG;
                else if (FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
                    traceEntry.Rt = TRACE_IMMEDIATE;
                else
                    traceEntry.Rt = TRACE_UNKNOWN;

                switch (traceEntry.Lt)
                {
                case TRACE_REG:
                    traceEntry.LValue.RegValue.RegValue = FD_OP_REG(&instr, 0);
                    regType = FD_OP_REG_TYPE(&instr, 0);
                    if (regType == FD_RT_VEC)
                        traceEntry.LValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.LValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.LValue.RegValue.fpu = true;
                    break;
                default:
                    break;
                }

                switch (traceEntry.Rt)
                {
                case TRACE_REG:
                    traceEntry.RValue.RegValue.RegValue = FD_OP_REG(&instr, 1);
                    regType = FD_OP_REG_TYPE(&instr, 1);
                    if (regType == FD_RT_VEC)
                        traceEntry.RValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.RValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.RValue.RegValue.fpu = true;
                    break;
                case TRACE_IMMEDIATE:
                    traceEntry.RValue.ImmediateValue = FD_OP_IMM(&instr, 1);
                    break;
                default:
                    break;
                }
                valid = true;
                break;
            case FDI_MOV:
            case FDI_MOVS:
            case FDI_MOVZX:
            case FDI_MOVABS:
            case FDI_MOVSX:
            case FDI_SSE_MOVAPD:
            case FDI_SSE_MOVAPS:
            case FDI_SSE_MOVD:
            case FDI_SSE_MOVDDUP:
            case FDI_SSE_MOVDQA:
            case FDI_SSE_MOVDQU:
            case FDI_SSE_MOVHLPS:
            case FDI_SSE_MOVHPD:
            case FDI_SSE_MOVHPS:
            case FDI_SSE_MOVLHPS:
            case FDI_SSE_MOVLPD:
            case FDI_SSE_MOVLPS:
            case FDI_SSE_MOVMSKPD:
            case FDI_SSE_MOVMSKPS:
            case FDI_SSE_MOVNTDQ:
            case FDI_SSE_MOVNTDQA:
            case FDI_SSE_MOVNTPD:
            case FDI_SSE_MOVNTPS:
            case FDI_SSE_MOVNTSD:
            case FDI_SSE_MOVNTSS:
            case FDI_SSE_MOVQ:
            case FDI_SSE_MOVSD:
            case FDI_SSE_MOVSHDUP:
            case FDI_SSE_MOVSLDUP:
            case FDI_SSE_MOVSS:
            case FDI_SSE_MOVUPD:
            case FDI_SSE_MOVUPS:
            case FDI_EVX_MOVAPD:
            case FDI_EVX_MOVAPS:
            case FDI_EVX_MOVDDUP:
            case FDI_EVX_MOVDQA32:
            case FDI_EVX_MOVDQA64:
            case FDI_EVX_MOVDQU16:
            case FDI_EVX_MOVDQU32:
            case FDI_EVX_MOVDQU64:
            case FDI_EVX_MOVDQU8:
            case FDI_EVX_MOVHLPS:
            case FDI_EVX_MOVHPD:
            case FDI_EVX_MOVHPS:
            case FDI_EVX_MOVLHPS:
            case FDI_EVX_MOVLPD:
            case FDI_EVX_MOVLPS:
            case FDI_EVX_MOVNTDQ:
            case FDI_EVX_MOVNTDQA:
            case FDI_EVX_MOVNTPD:
            case FDI_EVX_MOVNTPS:
            case FDI_EVX_MOVQ:
            case FDI_EVX_MOVSD:
            case FDI_EVX_MOVSH:
            case FDI_EVX_MOVSHDUP:
            case FDI_EVX_MOVSLDUP:
            case FDI_EVX_MOVSS:
            case FDI_EVX_MOVUPD:
            case FDI_EVX_MOVUPS:
                traceEntry.Type = TRACE_TYPE_STORE;
                traceEntry.Instr = instr;

                if (FD_OP_TYPE(&instr, 0) == FD_OT_REG)
                    traceEntry.Lt = TRACE_REG;
                else if (FD_OP_TYPE(&instr, 0) == FD_OT_MEM)
                    traceEntry.Lt = TRACE_OFFSET;
                else
                    traceEntry.Lt = TRACE_UNKNOWN;

                if (FD_OP_TYPE(&instr, 1) == FD_OT_REG)
                    traceEntry.Rt = TRACE_REG;
                else if (FD_OP_TYPE(&instr, 1) == FD_OT_IMM)
                    traceEntry.Rt = TRACE_IMMEDIATE;
                else if (FD_OP_TYPE(&instr, 1) == FD_OT_MEM)
                    traceEntry.Rt = TRACE_OFFSET;
                else
                    traceEntry.Rt = TRACE_UNKNOWN;

                switch (traceEntry.Lt)
                {
                case TRACE_REG:
                    traceEntry.LValue.RegValue.RegValue = FD_OP_REG(&instr, 0);
                    regType = FD_OP_REG_TYPE(&instr, 0);
                    if (regType == FD_RT_VEC)
                        traceEntry.LValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.LValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.LValue.RegValue.fpu = true;
                    break;
                case TRACE_OFFSET:
                    traceEntry.LValue.OffsetValue.Reg = FD_OP_BASE(&instr, 0);
                    if (traceEntry.LValue.OffsetValue.Reg == FD_REG_NONE)
                    {
                        traceEntry.LValue.OffsetValue.Reg = FD_SEGMENT(&instr);
                        if (traceEntry.LValue.OffsetValue.Reg == FD_REG_NONE)
                        {
                            traceEntry.LValue.OffsetValue.Reg = FD_REG_IP;
                        }
                        else
                        {
                            if (traceEntry.LValue.OffsetValue.Reg == FD_REG_CS)
                                traceEntry.LValue.OffsetValue.Reg = FD_REG_IP;
                            else if (traceEntry.LValue.OffsetValue.Reg == FD_REG_DS)
                                traceEntry.LValue.OffsetValue.Reg = FD_REG_SI;
                            else if (traceEntry.LValue.OffsetValue.Reg == FD_REG_ES)
                                traceEntry.LValue.OffsetValue.Reg = FD_REG_DI;
                            else if (traceEntry.LValue.OffsetValue.Reg == FD_REG_SS)
                                traceEntry.LValue.OffsetValue.Reg = FD_REG_SP;
                        }
                    }
                    traceEntry.LValue.OffsetValue.gpr = true;
                    if (traceEntry.LValue.OffsetValue.Reg == FD_REG_IP)
                        traceEntry.LValue.OffsetValue.Offset = 0;
                    else
                        traceEntry.LValue.OffsetValue.Offset = FD_OP_DISP(&instr, 0);
                    break;
                default:
                    break;
                }

                switch (traceEntry.Rt)
                {
                case TRACE_REG:
                    traceEntry.RValue.RegValue.RegValue = FD_OP_REG(&instr, 1);
                    regType = FD_OP_REG_TYPE(&instr, 1);
                    if (regType == FD_RT_VEC)
                        traceEntry.RValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.RValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.RValue.RegValue.fpu = true;
                    break;
                case TRACE_IMMEDIATE:
                    traceEntry.RValue.ImmediateValue = FD_OP_IMM(&instr, 1);
                    break;
                case TRACE_OFFSET:
                    traceEntry.RValue.OffsetValue.Reg = FD_OP_BASE(&instr, 1);
                    if (traceEntry.RValue.OffsetValue.Reg == FD_REG_NONE)
                    {
                        traceEntry.RValue.OffsetValue.Reg = FD_SEGMENT(&instr);
                        if (traceEntry.RValue.OffsetValue.Reg == FD_REG_NONE)
                        {
                            traceEntry.RValue.OffsetValue.Reg = FD_REG_IP;
                        }
                        else
                        {
                            if (traceEntry.RValue.OffsetValue.Reg == FD_REG_CS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_IP;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_DS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_SI;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_ES)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_DI;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_SS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_SP;
                        }
                    }
                    traceEntry.RValue.OffsetValue.gpr = true;
                    if (traceEntry.RValue.OffsetValue.Reg == FD_REG_IP)
                        traceEntry.RValue.OffsetValue.Offset = 0;
                    else
                        traceEntry.RValue.OffsetValue.Offset = FD_OP_DISP(&instr, 1);
                    break;
                default:
                    break;
                }

                valid = true;
                break;
            case FDI_LEA:
                traceEntry.Type = TRACE_TYPE_LOAD;
                traceEntry.Instr = instr;

                if (FD_OP_TYPE(&instr, 0) == FD_OT_REG)
                    traceEntry.Lt = TRACE_REG;
                else
                    traceEntry.Lt = TRACE_UNKNOWN;

                if (FD_OP_TYPE(&instr, 1) == FD_OT_MEM)
                    traceEntry.Rt = TRACE_OFFSET;
                else
                    traceEntry.Rt = TRACE_UNKNOWN;

                switch (traceEntry.Lt)
                {
                case TRACE_REG:
                    traceEntry.LValue.RegValue.RegValue = FD_OP_REG(&instr, 0);
                    regType = FD_OP_REG_TYPE(&instr, 0);
                    if (regType == FD_RT_VEC)
                        traceEntry.LValue.RegValue.vec = true;
                    else if (regType == FD_RT_GPL || regType == FD_RT_GPH)
                        traceEntry.LValue.RegValue.gpr = true;
                    else if (regType == FD_RT_FPU)
                        traceEntry.LValue.RegValue.fpu = true;
                    break;
                default:
                    break;
                }

                switch (traceEntry.Rt)
                {
                case TRACE_OFFSET:
                    traceEntry.RValue.OffsetValue.Reg = FD_OP_BASE(&instr, 1);
                    if (traceEntry.RValue.OffsetValue.Reg == FD_REG_NONE)
                    {
                        traceEntry.RValue.OffsetValue.Reg = FD_SEGMENT(&instr);
                        if (traceEntry.RValue.OffsetValue.Reg == FD_REG_NONE)
                        {
                            traceEntry.RValue.OffsetValue.Reg = FD_REG_IP;
                        }
                        else
                        {
                            if (traceEntry.RValue.OffsetValue.Reg == FD_REG_CS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_IP;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_DS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_SI;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_ES)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_DI;
                            else if (traceEntry.RValue.OffsetValue.Reg == FD_REG_SS)
                                traceEntry.RValue.OffsetValue.Reg = FD_REG_SP;
                        }
                    }
                    traceEntry.RValue.OffsetValue.gpr = true;
                    if (traceEntry.RValue.OffsetValue.Reg == FD_REG_IP)
                        traceEntry.RValue.OffsetValue.Offset = 0;
                    else
                        traceEntry.RValue.OffsetValue.Offset = FD_OP_DISP(&instr, 1);
                    break;
                default:
                    break;
                }

                valid = true;
                break;
            default:
                valid = false;
                break;
            }

            if (valid)
            {
                if (trace->Size == 0)
                {
                    trace->Entries = malloc(sizeof(INST_TRACE));
                }
                else
                {
                    trace->Entries = realloc(trace->Entries, sizeof(INST_TRACE) * (trace->Size + 1));
                }

                // trace->Entries[trace->Size] = traceEntry;
                memcpy(&trace->Entries[trace->Size], &traceEntry, sizeof(INST_TRACE));
                trace->Size++;
            }

            Address += ret;
        }
    } while (Address < (uintptr_t)Buffer + Size);

    if (point == TRACE_POINT_CALLER)
    {
        // add fake trace with INST_ACTION_CALL
        trace->Entries = realloc(trace->Entries, sizeof(INST_TRACE) * (trace->Size + 1));
        INST_TRACE traceEntry;
        traceEntry.Type = TRACE_TYPE_STORE;
        traceEntry.Action = INST_ACTION_CALL;
        // trace->Entries[trace->Size] = traceEntry;
        memcpy(&trace->Entries[trace->Size], &traceEntry, sizeof(INST_TRACE));
        trace->Size++;
    }

    return trace;
}

PINST_TRACE_LIST cpthk_get_trace(PCONTROL_FLOW_GRAPH Cfg, TRACE_POINT point, PINST_TRACE_LIST prev)
{
    PINST_TRACE_LIST list = NULL;
    PXREFS xrefs = NULL;
    size_t bufferSize = 0;
    uintptr_t StartAddress = 0;
    uintptr_t textAddr = 0;

    switch (point)
    {
    case TRACE_POINT_CALLER:

        xrefs = cpthk_find_xref(Cfg->Address);

        if (!xrefs)
            return NULL;

        int idx = -1;

        for (size_t i = 0; i < xrefs->Size; i++)
        {
            if (xrefs->Entries[i].Type == FDI_CALL)
            {
                idx = i;
                break;
            }
        }

        if (idx == -1)
        {
            return NULL;
        }

        cpthk_get_text_section(&textAddr, NULL);

        if (textAddr == 0)
        {
            return NULL;
        }

        StartAddress = cpthk_get_n_prev_instrs(textAddr, 40, xrefs->Entries[idx].Address, 0, &bufferSize, true);
        free(xrefs);
        list = cpthk_get_instr_trace((uint8_t *)StartAddress, bufferSize, point);

        return list;
    case TRACE_POINT_CALLEE:

        list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->Address, Cfg->Head->Size, point);
        // TODO: find a way to understand if getting trace of head block is enough
        // or if we do need to loop through all blocks until the end
        if (list->Size == 0 || (prev && list->Size < (prev->Size / 2)))
        {
            free(list);
            list = NULL;
            if (Cfg->Head->Branch && Cfg->Head->BranchAlt)
            {
                if (Cfg->Head->Branch->Size > Cfg->Head->BranchAlt->Size)
                {
                    list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->Branch->Address, Cfg->Head->Branch->Size, point);
                }
                else
                {
                    list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->BranchAlt->Address, Cfg->Head->BranchAlt->Size, point);
                }
            }
            else if (Cfg->Head->Branch)
            {
                list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->Branch->Address, Cfg->Head->Branch->Size, point);
            }
            else if (Cfg->Head->BranchAlt)
            {
                list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->BranchAlt->Address, Cfg->Head->BranchAlt->Size, point);
            }
            else
            {
                list = cpthk_get_instr_trace((uint8_t *)Cfg->Head->Next->Address, Cfg->Head->Next->Size, point);
            }

            return list;
        }

        return list;
        break;
    case TRACE_POINT_RETURN:
        cpthk_get_text_section(&textAddr, NULL);

        if (textAddr == 0)
        {
            return NULL;
        }

        StartAddress = cpthk_get_n_prev_instrs(textAddr, 10, Cfg->Tail->Address + Cfg->Tail->Size, Cfg->Tail->Address, &bufferSize, false);

        list = cpthk_get_instr_trace((uint8_t *)StartAddress, bufferSize, point);

        if (list->Size == 0)
        {
            free(list);
            return NULL;
        }

        return list;
    default:
        return NULL;
    }
}

PCALLING_CONVENTION cpthk_find_calling_convention(PCONTROL_FLOW_GRAPH cfg)
{
    TEMU_CPU_CONTEXT cpu;
    cpthk_emu_reset_regs(&cpu);

    PINST_TRACE_LIST list = cpthk_get_trace(cfg, TRACE_POINT_CALLER, NULL);
    if (!list)
    {
        return NULL;
    }

    cpthk_emu_traces(list, &cpu, TEMU_PRIORITIZE_WRITE_FLAG, TEMU_NO_ANAL);

    PINST_TRACE_LIST list2 = cpthk_get_trace(cfg, TRACE_POINT_CALLEE, list);
    if (!list2)
    {
        return NULL;
    }

    PCALLING_CONVENTION paramCallingConvention = cpthk_emu_traces(list2, &cpu, TEMU_PRIORITIZE_READ_FLAG, TEMU_ANAL_PARAM);

    PINST_TRACE_LIST list3 = cpthk_get_trace(cfg, TRACE_POINT_RETURN, NULL);
    if (!list3)
    {
        return NULL;
    }

    cpthk_emu_reset_regs(&cpu);
    PCALLING_CONVENTION returnCallingConvention = cpthk_emu_traces(list3, &cpu, TEMU_PRIORITIZE_WRITE_FLAG, TEMU_ANAL_RETURN);

    paramCallingConvention->ExitHookAddress = returnCallingConvention->ExitHookAddress;
    paramCallingConvention->ReturnRegister = returnCallingConvention->ReturnRegister;

    // free everything
    cpthk_free_trace_list(list);
    cpthk_free_trace_list(list2);
    cpthk_free_trace_list(list3);
    // cpthk_free_hashmap(cfg->Map);
    // free(cfg);
    free(returnCallingConvention);

    printf("Calling convention:\n");
    printf("  Return register: %d\n", paramCallingConvention->ReturnRegister);
    printf("  Argument count: %d\n", paramCallingConvention->ArgumentsCount);
    printf("  Arguments:\n");
    for (size_t i = 0; i < paramCallingConvention->ArgumentsCount; ++i)
    {
        char buf[100];
        fd_format(&paramCallingConvention->Arguments[i].Instruction, buf, sizeof(buf));
        printf("        %d: %s\n", i, buf);
    }
    printf("  EntryHookAddress: %p\n", paramCallingConvention->EntryHookAddress);
    printf("  ExitHookAddress: %p\n", paramCallingConvention->ExitHookAddress);

    return paramCallingConvention;
}
