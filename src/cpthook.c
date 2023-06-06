#include <cpthook.h>

PHOOK_LIST HookList = NULL;
bool HookListInitialized = false;
JMP_TABLE JmpTable = {0};

bool cpthk_init(void)
{
    if (HookList)
        return true;

    HookList = (PHOOK_LIST)malloc(sizeof(HOOK_LIST));
    if (!HookList)
        return false;

    HookList->Size = 128;
    HookList->Count = 0;
    HookList->Entries = (PHOOK_ENTRY)malloc(HookList->Size * sizeof(HOOK_ENTRY));
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
            return false;
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
            return false;
        }

        // initialize the table
        memset((void *)TableAddr, 0, 0x2000);

        // set the table entry
        JmpTable.TableEntry = (uintptr_t *)TableAddr;
        JmpTable.TableCapacity = 0x2000 / sizeof(uintptr_t);
        JmpTable.TableCount = 0;
    }
    else
    {
        // on 32 bit we don't need a jmp table since we can use the jmp relative to the hook entry
    }

    return true;
}

void cpthk_deinit(void)
{
    if (!HookList)
        return;

    if (HookList->Entries)
        free(HookList->Entries);

    free(HookList);
    HookList = NULL;
    HookListInitialized = false;
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
    size_t writeSize = 0;
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
                    *(unsigned char *)(TrampolineAddr + writeSize) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(unsigned char *)(TrampolineAddr + writeSize + 1) = 0x0e;
                    // JMP + 12
                    *(unsigned short *)(TrampolineAddr + writeSize + 2) = 0x0b0e;
                    // JMP [RIP]
                    JMP_ABSOLUTE64(TrampolineAddr + writeSize + 4, jmpAddress);
                    writeSize += 18;
                }
                else
                {
                    // TODO: this won't work if jmp location is inside the trampoline itself
                    uintptr_t jmpAddress = FD_OP_IMM(&instr, 0);
                    *(unsigned char *)(TrampolineAddr + writeSize) = *(unsigned char *)decodeAddress; // copy the first byte
                    *(unsigned char *)(TrampolineAddr + writeSize + 1) = 0x0e;
                    // JMP + 9
                    *(unsigned short *)(TrampolineAddr + writeSize + 2) = 0xeb05;
                    // JMP jmpAddress
                    JMP_RELATIVE32(TrampolineAddr + writeSize + 4, jmpAddress);
                }
            }
            else
            {
                memcpy((void *)(TrampolineAddr + writeSize), decodeAddress, ret);
                trampolineSize += ret;
                writeSize += ret;
            }
        }
        else
        {
            return false;
        }

        decodeAddress += ret;
    } while (trampolineSize < originalBytesSize);

    if (FD_MODE == 64)
    {
        JMP_ABSOLUTE64(TrampolineAddr + writeSize, OriginalHook + originalBytesSize);
    }
    else
    {
        JMP_RELATIVE32(TrampolineAddr + writeSize, OriginalHook + originalBytesSize);
    }

    return true;
}

void cpthk_restore_jmps(uintptr_t Address, uint8_t *Buffer, size_t OldBufSize)
{
    memcpy((void *)Address, Buffer, OldBufSize);
}

bool cpthk_hook_add_internal(uintptr_t FunctionAddress, uintptr_t HookContext, PCALLING_CONVENTION CallingConvention, HOOKFNC HookEntry, HOOKFNC HookExit)
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

    Entry->FunctionAddress = FunctionAddress;
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

    if (HookEntry)
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

    if (HookExit)
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

    if (HookEntry)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect((void *)Entry->HookContext->HookTrampolineEntry, Entry->OriginalEntrySize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }
    }

    if (HookExit)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect((void *)Entry->HookContext->HookTrampolineExit, Entry->OriginalExitSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            return false;
        }
    }

    printf("Function Entry Hooking Address %p\n", CallingConvention->EntryHookAddress);
    printf("Function Exit Hooking Address %p\n", CallingConvention->ExitHookAddress);
    printf("EntryTrampoline %p\n", Entry->HookContext->HookTrampolineEntry);
    printf("ExitTrampoline %p\n", Entry->HookContext->HookTrampolineExit);
    printf("HookContext start + stub : %p\n", HookContext);

    return true;
}

bool cpthk_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook)
{
    if (!HookListInitialized)
        return false;

    if (!cpthk_operate_threads(THREAD_OP_SUSPEND))
        return false;

    PCONTROL_FLOW_GRAPH ControlFlowGraph = cpthk_build_cfg(FunctionAddress);
    if (!ControlFlowGraph)
    {
        return false;
    }

    // Allocate memory for the hook context + stubs
    uintptr_t Hook = (uintptr_t)malloc(sizeof(CPTHOOK_CTX) + 0x1000);
    if (!Hook)
        return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect((void *)Hook, sizeof(CPTHOOK_CTX) + 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        free((void *)Hook);
        return false;
    }

    // try to find the calling convention
    PCALLING_CONVENTION CallingConvention = cpthk_find_calling_convention(ControlFlowGraph);
    if (!CallingConvention)
    {
        free((void *)Hook);
        return false;
    }

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READWRITE))
    {
        free((void *)Hook);
        return false;
    }

    // Add the actual hook here
    if (!cpthk_hook_add_internal(FunctionAddress, Hook, CallingConvention, EntryHook, ExitHook))
    {
        free((void *)Hook);
        return false;
    }
    // End of hook

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READ))
    {
        free((void *)Hook);
        return false;
    }

    if (!cpthk_operate_threads(THREAD_OP_RESUME))
        return false;

    return true;
}

bool cpthk_unhook(uintptr_t FunctionAddress)
{
    if (!HookListInitialized)
        return false;

    if (!cpthk_operate_threads(THREAD_OP_SUSPEND))
        return false;

    if (!cpthk_operate_threads(THREAD_OP_RESUME))
        return false;
    return true;
}
