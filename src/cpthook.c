#include <cpthook.h>

PHOOK_LIST HookList = NULL;
bool HookListInitialized = false;

#if defined(_WIN64)
ULONGLONG WINAPI cpthk_veh(EXCEPTION_POINTERS *Info)
{
    if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        uintptr_t EAddr = (uintptr_t)Info->ExceptionRecord->ExceptionAddress;
        unsigned short index = *(unsigned short *)(EAddr + 2);
        unsigned char isEntry = *(unsigned char *)(EAddr + 4);
        PHOOK_ENTRY entry = &HookList->Entries[index];

        entry->HookContext->CpuContext = Info->ContextRecord;

        if (isEntry)
        {
            if (entry->Enabled)
            {
                entry->HookContext->EntryHook(entry->HookContext);
            }
            Info->ContextRecord->Rip = entry->HookContext->HookTrampolineEntry;
        }
        else
        {
            if (entry->Enabled)
            {
                entry->HookContext->ExitHook(entry->HookContext);
            }
            Info->ContextRecord->Rip = entry->HookContext->HookTrampolineExit;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#else
DWORD WINAPI cpthk_veh(EXCEPTION_POINTERS *Info)
{
    if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        uintptr_t EAddr = (uintptr_t)Info->ExceptionRecord->ExceptionAddress;
        unsigned short index = *(unsigned short *)(EAddr + 2);
        unsigned char isEntry = *(unsigned char *)(EAddr + 4);
        PHOOK_ENTRY entry = &HookList->Entries[index];

        entry->HookContext->CpuContext = Info->ContextRecord;

        if (isEntry)
        {
            if (entry->Enabled)
            {
                entry->HookContext->EntryHook(entry->HookContext);
            }
            Info->ContextRecord->Eip = entry->HookContext->HookTrampolineEntry;
        }
        else
        {
            if (entry->Enabled)
            {
                entry->HookContext->ExitHook(entry->HookContext);
            }
            Info->ContextRecord->Eip = entry->HookContext->HookTrampolineExit;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

CPTHK_STATUS cpthk_init(void)
{
    if (HookList)
        return CPTHK_ALREADY_INITIALIZED;

    HookList = (PHOOK_LIST)malloc(sizeof(HOOK_LIST));
    if (!HookList)
        return CPTHK_OUT_OF_MEMORY;

    memset(HookList, 0, sizeof(HOOK_LIST));

    HookList->Size = 128;
    HookList->Count = 0;
    HookList->Entries = (PHOOK_ENTRY)malloc(HookList->Size * sizeof(HOOK_ENTRY));

    memset(HookList->Entries, 0, HookList->Size * sizeof(HOOK_ENTRY));

    if (!AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)cpthk_veh))
    {
        return CPTHK_ERROR;
    }

    HookListInitialized = true;
    return CPTHK_OK;
}

CPTHK_STATUS cpthk_uninit(void)
{
    if (!HookList)
        return CPTHK_NOT_INITIALIZED;

    for (unsigned long i = 0; i < HookList->Count; i++)
    {
        PHOOK_ENTRY entry = &HookList->Entries[i];
        if (entry->HookContext)
        {
            free((void *)entry->HookContext->HookTrampolineEntry);
            free((void *)entry->HookContext->HookTrampolineExit);
            free((void *)entry->HookContext);
            entry->HookContext = NULL;
        }
    }

    free((void *)HookList);
    HookList = NULL;
    HookListInitialized = false;

    return CPTHK_OK;
}

uintptr_t cpthk_get_arg(CPTHOOK_CTX Context, uint32_t ArgIndex)
{
    return 0;
}

void cpthk_set_arg(CPTHOOK_CTX Context, uint32_t ArgIndex, uintptr_t Value)
{
}

void cpthk_set_return(CPTHOOK_CTX Context, uintptr_t Value)
{
}

bool cpthk_write_trampoline(uintptr_t TrampolineAddr, uintptr_t OriginalHook, uint8_t *originalBytes, size_t originalBytesSize)
{

    // copy the original bytes to the trampoline take care of possible jumps which now are not valid anymore
    size_t trampolineSize = 0;
    size_t writeOffset = 0;
    FdInstr instr;
    uint8_t *decodeAddress = originalBytes;

    do
    {
        int ret = fd_decode(decodeAddress, 15, FD_MODE, OriginalHook + trampolineSize, &instr);
        if (ret > 0)
        {
            if (IS_CONDJMP(instr) || IS_JMP(instr))
            {
                if (FD_MODE == 64)
                {
                    // TODO: this won't work if jmp location is inside the trampoline itself
                    uintptr_t jmpAddress = FD_OP_IMM(&instr, 0);
                    // jmp address is relative to OriginalHook + trampolineSize , but we are writing to TrampolineAddr
                    // so we need to recalculate the address to be relative to TrampolineAddr
                    jmpAddress = jmpAddress - (OriginalHook + trampolineSize) + TrampolineAddr;
                    *(unsigned char *)(TrampolineAddr + writeOffset) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(unsigned char *)(TrampolineAddr + writeOffset + 1) = 0x0e;
                    // JMP + 12
                    *(unsigned short *)(TrampolineAddr + writeOffset + 2) = 0x0b0e;
                    // JMP [RIP]
                    JMP_ABSOLUTE64(TrampolineAddr + writeOffset + 4, jmpAddress);
                    writeOffset += 18;
                }
                else
                {
                    // TODO: this won't work if jmp location is inside the trampoline itself
                    uintptr_t jmpAddress = FD_OP_IMM(&instr, 0);
                    *(unsigned char *)(TrampolineAddr + writeOffset) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(unsigned char *)(TrampolineAddr + writeOffset + 1) = 0x0e;
                    // JMP + 9
                    *(unsigned short *)(TrampolineAddr + writeOffset + 2) = 0xeb05;
                    // JMP jmpAddress
                    JMP_RELATIVE32(TrampolineAddr + writeOffset + 4, jmpAddress);
                    writeOffset += 9;
                }
            }
            else if (IS_CALL(instr))
            {
                if (FD_MODE == 64)
                {
                    uintptr_t callAddress = FD_OP_IMM(&instr, 0);
                    // call address is relative to OriginalHook + trampolineSize , but we are writing to TrampolineAddr
                    // so we need to recalculate the address to be relative to TrampolineAddr
                    callAddress = callAddress - (OriginalHook + trampolineSize) + TrampolineAddr + writeOffset;
                    *(unsigned char *)(TrampolineAddr + writeOffset) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(DWORD *)(TrampolineAddr + writeOffset + 1) = (DWORD)(callAddress - (TrampolineAddr + writeOffset + 5));
                    writeOffset += 5;
                }
                else
                {
                    uintptr_t callAddress = FD_OP_IMM(&instr, 0);
                    // on 32 bit the call address is absolute so we don't need to recalculate it
                    *(unsigned char *)(TrampolineAddr + writeOffset) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(DWORD *)(TrampolineAddr + writeOffset + 1) = (DWORD)(callAddress - (TrampolineAddr + writeOffset + 5));
                    writeOffset += 5;
                }
            }
            else
            {
                memcpy((void *)(TrampolineAddr + writeOffset), decodeAddress, ret);
                writeOffset += ret;
            }

            trampolineSize += ret;
        }
        else
        {
            return false;
        }

        decodeAddress += ret;
    } while (trampolineSize < originalBytesSize);

    if (FD_MODE == 64)
    {
        JMP_ABSOLUTE64(TrampolineAddr + writeOffset, OriginalHook + originalBytesSize);
    }
    else
    {
        JMP_RELATIVE32(TrampolineAddr + writeOffset, OriginalHook + originalBytesSize);
    }

    return true;
}

void cpthk_restore(uintptr_t Address, uint8_t *Buffer, size_t OldBufSize)
{
    memcpy((void *)Address, Buffer, OldBufSize);
}

bool cpthk_hook_add_internal(PCONTROL_FLOW_GRAPH Cfg, PCALLING_CONVENTION CallingConvention, HOOKFNC HookEntry, HOOKFNC HookExit)
{
    if (HookList->Size > HookList->Count)
    {
        HookList->Size += 10;
        HookList->Entries = (PHOOK_ENTRY)realloc(HookList->Entries, HookList->Size * sizeof(HOOK_ENTRY));
        if (!HookList->Entries)
        {
            HookList->Size -= 10;
            return false;
        }
    }

    PHOOK_ENTRY Entry = &HookList->Entries[HookList->Count++];

    PCPTHOOK_CTX HookContext = malloc(sizeof(CPTHOOK_CTX));
    memset(HookContext, 0, sizeof(CPTHOOK_CTX));

    Entry->Cfg = Cfg;
    Entry->FunctionAddress = Cfg->Address;
    Entry->FunctionSize = Cfg->Size;
    Entry->Enabled = true;
    Entry->HookContext = (PCPTHOOK_CTX)HookContext;
    Entry->HookContext->CallingConvention = CallingConvention;
    Entry->HookContext->EntryHook = HookEntry;
    Entry->HookContext->ExitHook = HookExit;

    if (HookEntry && CallingConvention->EntryHookAddress)
    {
        // write the jmp to the entry hook
        unsigned char originalEntryBytes[HOOKSIZE + 15];
        size_t entryReplacedBytesSize = cpthk_write_ud2(CallingConvention->EntryHookAddress, (unsigned char *)&originalEntryBytes, true);

        if (entryReplacedBytesSize == 0)
        {
            return false;
        }

        // Save original Entry bytes
        Entry->OriginalEntrySize = entryReplacedBytesSize;
        memcpy(Entry->OriginalEntryBytes, originalEntryBytes, entryReplacedBytesSize);

        // Allocate space for the trampoline
        Entry->HookContext->HookTrampolineEntry = (uintptr_t)malloc(entryReplacedBytesSize + (15 * 6));

        if (!Entry->HookContext->HookTrampolineEntry)
        {
            cpthk_restore(CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            return false;
        }
        else
        {
            memset((void *)Entry->HookContext->HookTrampolineEntry, 0, entryReplacedBytesSize + (15 * 6));
        }

        // Write the trampoline
        if (!cpthk_write_trampoline(Entry->HookContext->HookTrampolineEntry, CallingConvention->EntryHookAddress, originalEntryBytes, entryReplacedBytesSize))
        {
            cpthk_restore(CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            free((void *)Entry->HookContext->HookTrampolineEntry);
            return false;
        }
    }

    if (HookExit && CallingConvention->ExitHookAddress)
    {
        // do the same for the exit hook
        unsigned char originalExitBytes[HOOKSIZE + 15];
        size_t exitReplacedBytesSize = cpthk_write_ud2(CallingConvention->ExitHookAddress, (unsigned char *)&originalExitBytes, false);

        if (exitReplacedBytesSize == 0)
        {
            return false;
        }

        // Save original Exit bytes
        Entry->OriginalExitSize = exitReplacedBytesSize;
        memcpy(Entry->OriginalExitBytes, originalExitBytes, exitReplacedBytesSize);

        // Allocate space for the trampoline
        Entry->HookContext->HookTrampolineExit = (uintptr_t)malloc(exitReplacedBytesSize + (15 * 6));
        if (!Entry->HookContext->HookTrampolineExit)
        {
            cpthk_restore(CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);
            free((void *)Entry->HookContext->HookTrampolineEntry);
            return false;
        }
        else
        {
            memset((void *)Entry->HookContext->HookTrampolineExit, 0, exitReplacedBytesSize + (15 * 6));
        }

        // Write the trampoline
        if (!cpthk_write_trampoline(Entry->HookContext->HookTrampolineExit, CallingConvention->ExitHookAddress, originalExitBytes, exitReplacedBytesSize))
        {
            cpthk_restore(CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);
            free((void *)Entry->HookContext->HookTrampolineExit);
            return false;
        }
    }

    if (HookEntry && CallingConvention->EntryHookAddress)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect((void *)Entry->HookContext->HookTrampolineEntry, Entry->OriginalEntrySize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }
    }

    if (HookExit && CallingConvention->ExitHookAddress)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect((void *)Entry->HookContext->HookTrampolineExit, Entry->OriginalExitSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }
    }

    return true;
}

CPTHK_STATUS cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook)
{
    if (!HookListInitialized)
        return CPTHK_NOT_INITIALIZED;

    if (!cpthk_operate_threads(THREAD_OP_SUSPEND))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    PCONTROL_FLOW_GRAPH ControlFlowGraph = cpthk_build_cfg(FunctionAddress);
    if (!ControlFlowGraph)
    {
        return CPTHK_UNABLE_TO_BUILD_CFG;
    }

    // try to find the calling convention
    PCALLING_CONVENTION CallingConvention = cpthk_find_calling_convention(ControlFlowGraph);
    if (!CallingConvention)
    {
        return CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION;
    }

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READWRITE))
    {
        return CPTHK_UNABLE_TO_PROTECT_MEMORY;
    }

    // Add the actual hook here
    if (!cpthk_hook_add_internal(ControlFlowGraph, CallingConvention, EntryHook, ExitHook))
    {
        return CPTHK_INTERNAL_ERROR;
    }
    // End of hook

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READ))
    {
        return CPTHK_UNABLE_TO_PROTECT_MEMORY;
    }

    if (!cpthk_operate_threads(THREAD_OP_RESUME))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    return CPTHK_OK;
}

CPTHK_STATUS cpthk_unhook(uintptr_t FunctionAddress)
{
    if (!HookListInitialized)
        return CPTHK_NOT_INITIALIZED;

    if (!cpthk_operate_threads(THREAD_OP_SUSPEND))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    bool found = false;

    // loop through the hook list and find the hook
    for (size_t i = 0; i < HookList->Count; i++)
    {
        if (HookList->Entries[i].FunctionAddress == FunctionAddress)
        {
            found = true;
            // found the hook
            PHOOK_ENTRY Entry = &HookList->Entries[i];

            // make function writable
            if (!cpthk_protect_function(Entry->Cfg, PAGE_EXECUTE_READWRITE))
            {
                return CPTHK_UNABLE_TO_PROTECT_MEMORY;
            }

            // restore the original bytes
            cpthk_restore(Entry->HookContext->CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            cpthk_restore(Entry->HookContext->CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);

            // restore the protection
            if (!cpthk_protect_function(Entry->Cfg, PAGE_EXECUTE_READ))
            {
                return CPTHK_UNABLE_TO_PROTECT_MEMORY;
            }

            // free the trampolines
            free((void *)Entry->HookContext->HookTrampolineEntry);
            free((void *)Entry->HookContext->HookTrampolineExit);

            // free the hook context
            free((void *)Entry->HookContext);

            // free the cfg
            cpthk_free_cfg(Entry->Cfg);

            // free the hook entry
            free((void *)Entry);

            // shift the entries
            for (size_t j = i; j < HookList->Count - 1; j++)
            {
                HookList->Entries[j] = HookList->Entries[j + 1];
            }

            // decrease the count
            HookList->Count--;

            break;
        }
    }

    if (!cpthk_operate_threads(THREAD_OP_RESUME))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    if (!found)
        return CPTHK_HOOK_NOT_FOUND;

    return CPTHK_OK;
}

char *cpthk_str_error(CPTHK_STATUS Status)
{
    switch (Status)
    {
    case CPTHK_OK:
        return "Operation completed successfully";
    case CPTHK_ERROR:
        return "Unknown error";
    case CPTHK_ALREADY_INITIALIZED:
        return "The library is already initialized";
    case CPTHK_NOT_INITIALIZED:
        return "The library is not initialized";
    case CPTHK_UNABLE_TO_CONTROL_THREADS:
        return "Unable to control threads";
    case CPTHK_UNABLE_TO_PROTECT_MEMORY:
        return "Unable to protect memory";
    case CPTHK_HOOK_NOT_FOUND:
        return "Hook not found";
    case CPTHK_UNABLE_TO_BUILD_CFG:
        return "Unable to build CFG";
    case CPTHK_OUT_OF_MEMORY:
        return "Out of memory";
    case CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION:
        return "Unable to find calling convention";
    case CPTHK_INTERNAL_ERROR:
        return "Internal error";
    case CPTHK_UNABLE_TO_QUERY_MEMORY:
        return "Unable to query memory";
    default:
        return "Unknown error";
    }
}

char *cpthk_version(void)
{
    return "CaptainHook v" VERSION_STR(MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION, CODENAME);
}
