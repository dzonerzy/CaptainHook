#include <cpthook.h>

PHOOK_LIST HookList = NULL;
bool HookListInitialized = false;
JMP_TABLE JmpTable = {0};

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

    HookListInitialized = true;

    if (FD_MODE == 64)
    {

        MEMORY_BASIC_INFORMATION mbi;

        if (VirtualQuery(GetModuleHandleA(NULL), &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        {
            return false;
        }

        // get page size
        uintptr_t pageSize = 0x1000;
        uintptr_t moduleBase = (uintptr_t)mbi.AllocationBase;
        uintptr_t moduleEnd = moduleBase + mbi.RegionSize;
        uintptr_t tableEntry = moduleEnd - 0x5000;
        // align tableEntry to next PAGE_SIZE
        tableEntry = (tableEntry + pageSize - 1) & ~(pageSize - 1);

        if (VirtualQuery((void *)tableEntry, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        {
            return CPTHK_UNABLE_TO_QUERY_MEMORY;
        }

        // check if the table is free
        if (mbi.State != MEM_FREE)
        {
            return false;
        }

        // allocate the table
        uintptr_t TableAddr = (uintptr_t)VirtualAlloc((void *)tableEntry, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!TableAddr)
        {
            return CPTHK_OUT_OF_MEMORY;
        }

        // initialize the table
        memset((void *)TableAddr, 0, 0x2000);

        // set the table entry
        JmpTable.TableEntry = (uintptr_t *)TableAddr;
        JmpTable.TableCapacity = 0x2000 / sizeof(uintptr_t);
        JmpTable.TableCount = 0;
    }

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

    if (FD_MODE == 64)
    {
        if (JmpTable.TableEntry)
        {
            VirtualFree((void *)JmpTable.TableEntry, 0, MEM_RELEASE);
            JmpTable.TableEntry = NULL;
        }
    }

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

void cpthk_restore_jmps(uintptr_t Address, uint8_t *Buffer, size_t OldBufSize)
{
    memcpy((void *)Address, Buffer, OldBufSize);
}

bool cpthk_hook_add_internal(PCONTROL_FLOW_GRAPH Cfg, uintptr_t HookContext, PCALLING_CONVENTION CallingConvention, HOOKFNC HookEntry, HOOKFNC HookExit)
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

    Entry->FunctionAddress = Cfg->Address;
    Entry->FunctionSize = Cfg->Size;
    Entry->Enabled = true;
    Entry->HookContext = (PCPTHOOK_CTX)HookContext;

    // create the context
    CPTHOOK_CTX Context;
    memset(&Context, 0, sizeof(CPTHOOK_CTX));

    Context.CallingConvention = CallingConvention;
    Context.EntryHook = (uintptr_t)HookEntry;
    Context.ExitHook = (uintptr_t)HookExit;

    // copy the hook context
    memcpy((void *)HookContext, &Context, sizeof(CPTHOOK_CTX));

    size_t stubSize = 0;

    if (HookEntry && CallingConvention->EntryHookAddress)
    {
        // write the jmp to the entry hook
        unsigned char originalEntryBytes[HOOKSIZE + 15];
        size_t entryReplacedBytesSize = cpthk_write_jmp(CallingConvention->EntryHookAddress, HookContext + sizeof(CPTHOOK_CTX), (unsigned char *)&originalEntryBytes);

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
            cpthk_restore_jmps(CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            return false;
        }
        else
        {
            memset((void *)Entry->HookContext->HookTrampolineEntry, 0, entryReplacedBytesSize + (15 * 6));
        }

        // Write the trampoline
        if (!cpthk_write_trampoline(Entry->HookContext->HookTrampolineEntry, CallingConvention->EntryHookAddress, originalEntryBytes, entryReplacedBytesSize))
        {
            cpthk_restore_jmps(CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            free((void *)Entry->HookContext->HookTrampolineEntry);
            return false;
        }

        // write partial shellcode + jmp to the entry trampoline
        stubSize = cpthk_populate_hook_context(HookContext, HookContext + sizeof(CPTHOOK_CTX), Entry->HookContext->HookTrampolineEntry, FD_MODE);
        if (stubSize == 0)
        {
            cpthk_restore_jmps(CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            return false;
        }
    }

    if (HookExit && CallingConvention->ExitHookAddress)
    {

        // do the same for the exit hook
        unsigned char originalExitBytes[HOOKSIZE + 15];
        size_t exitReplacedBytesSize = cpthk_write_jmp(CallingConvention->ExitHookAddress, HookContext + sizeof(CPTHOOK_CTX) + stubSize, (unsigned char *)&originalExitBytes);

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
            cpthk_restore_jmps(CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);
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
            cpthk_restore_jmps(CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);
            free((void *)Entry->HookContext->HookTrampolineExit);
            return false;
        }

        // write partial shellcode + jmp to the exit trampoline
        stubSize = cpthk_populate_hook_context(HookContext, HookContext + sizeof(CPTHOOK_CTX) + stubSize, Entry->HookContext->HookTrampolineExit, FD_MODE);
        if (stubSize == 0)
        {
            cpthk_restore_jmps(CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);
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

    // Allocate memory for the hook context + stubs
    uintptr_t Hook = (uintptr_t)malloc(sizeof(CPTHOOK_CTX) + stub_size * 2);

    if (!Hook)
        return CPTHK_OUT_OF_MEMORY;

    memset((void *)Hook, 0, sizeof(CPTHOOK_CTX) + stub_size * 2);

    DWORD oldProtect = 0;
    if (!VirtualProtect((void *)Hook, sizeof(CPTHOOK_CTX) + stub_size * 2, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        free((void *)Hook);
        return CPTHK_UNABLE_TO_PROTECT_MEMORY;
    }

    // try to find the calling convention
    PCALLING_CONVENTION CallingConvention = cpthk_find_calling_convention(ControlFlowGraph);
    if (!CallingConvention)
    {
        free((void *)Hook);
        return CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION;
    }

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READWRITE))
    {
        free((void *)Hook);
        printf("Unable to protect function 1\n");
        return CPTHK_UNABLE_TO_PROTECT_MEMORY;
    }

    // Add the actual hook here
    if (!cpthk_hook_add_internal(ControlFlowGraph, Hook, CallingConvention, EntryHook, ExitHook))
    {
        free((void *)Hook);
        return CPTHK_INTERNAL_ERROR;
    }
    // End of hook

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READ))
    {
        free((void *)Hook);
        printf("Unable to protect function 2\n");
        return CPTHK_UNABLE_TO_PROTECT_MEMORY;
    }

    if (!cpthk_operate_threads(THREAD_OP_RESUME))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    // free the CFG
    cpthk_free_cfg(ControlFlowGraph);

    return CPTHK_OK;
}

CPTHK_STATUS cpthk_unhook(uintptr_t FunctionAddress)
{
    if (!HookListInitialized)
        return CPTHK_NOT_INITIALIZED;

    if (!cpthk_operate_threads(THREAD_OP_SUSPEND))
        return CPTHK_UNABLE_TO_CONTROL_THREADS;

    DWORD oldProtect = 0;
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
            if (!VirtualProtect((void *)Entry->FunctionAddress, Entry->FunctionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                return CPTHK_UNABLE_TO_PROTECT_MEMORY;
            }

            // restore the original bytes
            cpthk_restore_jmps(Entry->HookContext->CallingConvention->EntryHookAddress, Entry->OriginalEntryBytes, Entry->OriginalEntrySize);
            cpthk_restore_jmps(Entry->HookContext->CallingConvention->ExitHookAddress, Entry->OriginalExitBytes, Entry->OriginalExitSize);

            // restore the protection
            if (!VirtualProtect((void *)Entry->FunctionAddress, Entry->FunctionSize, PAGE_EXECUTE_READ, &oldProtect))
            {
                return CPTHK_UNABLE_TO_PROTECT_MEMORY;
            }

            // free the trampolines
            free((void *)Entry->HookContext->HookTrampolineEntry);
            free((void *)Entry->HookContext->HookTrampolineExit);

            // free the hook context
            free((void *)Entry->HookContext);

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
