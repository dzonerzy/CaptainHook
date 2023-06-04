#include <cpthook.h>

PHOOK_LIST HookList = NULL;
bool HookListInitialized = false;

bool cpthk_init(void)
{
    if (HookList)
        return true;

    HookList = (PHOOK_LIST)malloc(sizeof(HOOK_LIST));
    if (!HookList)
        return false;

    HookList->Size = 0;
    HookList->Count = 0;
    HookList->Entries = NULL;
    HookListInitialized = true;

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

bool cpthk_hook_add_internal(uintptr_t HookContext, PCALLING_CONVENTION CallingConvention)
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

    PHOOK_ENTRY HookEntry = &HookList->Entries[HookList->Count++];

    HookEntry->Enabled = true;
    HookEntry->HookContext = (PCPTHOOK_CTX)HookContext;

    // create the context
    CPTHOOK_CTX Context;
    Context.CallingConvention = CallingConvention;

    printf("Hooking function at %p\n", CallingConvention->EntryHookAddress);
    printf("HookContext at %p\n", HookContext);
    printf("Stub at 0x%llx\n", HookContext + sizeof(CPTHOOK_CTX));

    // copy the hook context
    memcpy((void *)HookContext, &Context, sizeof(CPTHOOK_CTX));

    if (!cpthk_populate_hook_context(HookContext, FD_MODE))
    {
        return false;
    }

    unsigned char originalEntryBytes[HOOKSIZE + 15];
    size_t entryReplacedBytes = cpthk_write_jmp(CallingConvention->EntryHookAddress, HookContext + sizeof(CPTHOOK_CTX), (unsigned char *)&originalEntryBytes);

    if (entryReplacedBytes == 0)
    {
        free(HookEntry);
        return false;
    }

    HookEntry->OriginalEntrySize = entryReplacedBytes;
    memcpy(HookEntry->OriginalEntryBytes, originalEntryBytes, entryReplacedBytes);

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

    // Allocate memory for the hookentry
    uintptr_t Hook = (uintptr_t)VirtualAlloc(NULL, sizeof(CPTHOOK_CTX) + 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!Hook)
        return false;

    // try to find the calling convention
    PCALLING_CONVENTION CallingConvention = cpthk_find_calling_convention(ControlFlowGraph);
    if (!CallingConvention)
    {
        VirtualFree((LPVOID)Hook, 0, MEM_RELEASE);
        return false;
    }

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READWRITE))
    {
        VirtualFree((LPVOID)Hook, 0, MEM_RELEASE);
        return false;
    }

    if (!cpthk_hook_add_internal(Hook, CallingConvention))
    {
        VirtualFree((LPVOID)Hook, 0, MEM_RELEASE);
        return false;
    }

    // Add the actual hook here

    if (!cpthk_protect_function(ControlFlowGraph, PAGE_EXECUTE_READ))
    {
        VirtualFree((LPVOID)Hook, 0, MEM_RELEASE);
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
