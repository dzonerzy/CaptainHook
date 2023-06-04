#include <cpthook.h>

bool cpthook_hook(uintptr_t FunctionAddress, HOOKFNC EntryHook, HOOKFNC ExitHook)
{
    return false;
}

bool cpthook_unhook(uintptr_t FunctionAddress)
{
    return false;
}
