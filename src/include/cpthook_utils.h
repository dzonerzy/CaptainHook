#pragma once
#include <cpthook.h>
#include <tlhelp32.h>

typedef enum _THREAD_OP
{
    THREAD_OP_SUSPEND,
    THREAD_OP_RESUME
} THREAD_OP;

void cpthk_get_text_section(uintptr_t *textSection, size_t *textSize);
bool cpthk_operate_threads(THREAD_OP Operation);
bool cpthk_protect_function(PCONTROL_FLOW_GRAPH Cfg, DWORD Protection);
bool cpthk_populate_hook_context(uintptr_t Address, int mode);
void cpthk_stub64(void);
void cpthk_stub64_end(void);
size_t cpthk_write_jmp(uintptr_t Address, uintptr_t Destination, unsigned char *saveBuffer);
