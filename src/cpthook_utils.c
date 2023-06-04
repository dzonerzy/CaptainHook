#include <cpthook.h>
#include <fadec-enc.h>

void cpthk_get_text_section(uintptr_t *textSection, size_t *textSize)
{
    HMODULE hMod = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dosHeader->e_lfanew);

    bool is64 = false;
    // check if 32 or 64 bit
    if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        is64 = false;
    }
    else if (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        is64 = true;
    }

    if (is64)
    {
        PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)hMod + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)ntHeader64 + sizeof(IMAGE_NT_HEADERS64));
        for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++)
        {
            if (strcmp((char *)sectionHeader[i].Name, ".text") == 0)
            {
                if (textSection)
                    *textSection = (uintptr_t)hMod + sectionHeader[i].VirtualAddress;
                if (textSize)
                    *textSize = sectionHeader[i].Misc.VirtualSize;
                break;
            }
        }
    }
    else
    {
        PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)hMod + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)ntHeader32 + sizeof(IMAGE_NT_HEADERS32));
        for (int i = 0; i < ntHeader32->FileHeader.NumberOfSections; i++)
        {
            if (strcmp((char *)sectionHeader[i].Name, ".text") == 0)
            {
                if (textSection)
                    *textSection = (uintptr_t)hMod + sectionHeader[i].VirtualAddress;
                if (textSize)
                    *textSize = sectionHeader[i].Misc.VirtualSize;
                break;
            }
        }
    }
}

bool cpthk_operate_threads(THREAD_OP Operation)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnap, &te))
    {
        CloseHandle(hSnap);
        return false;
    }

    do
    {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
        {
            if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != GetCurrentThreadId())
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    if (Operation == THREAD_OP_RESUME)
                        ResumeThread(hThread);
                    else if (Operation == THREAD_OP_SUSPEND)
                        SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        }
        te.dwSize = sizeof(THREADENTRY32);
    } while (Thread32Next(hSnap, &te));

    CloseHandle(hSnap);
    return true;
}

void cpthk_stub64(void)
{
    /*
    typedef struct _CALLING_CONVENTION
    {
        uintptr_t EntryHookAddress;
        uintptr_t ExitHookAddress;
        ARGUMENT Arguments[16];
        size_t ArgumentsCount;
        FdReg ReturnRegister;
    } CALLING_CONVENTION, *PCALLING_CONVENTION;

    #pragma pack(push, 1)
    typedef struct _CPTHOOK_CTX
    {
        PCALLING_CONVENTION CallingConvention;
        union
        {
            unsigned char _rctx[128];

            struct
            {
                unsigned long long rax;
                unsigned long long rcx;
                unsigned long long rdx;
                unsigned long long rbx;
                unsigned long long rsp;
                unsigned long long rbp;
                unsigned long long rsi;
                unsigned long long rdi;
                unsigned long long r8;
                unsigned long long r9;
                unsigned long long r10;
                unsigned long long r11;
                unsigned long long r12;
                unsigned long long r13;
                unsigned long long r14;
                unsigned long long r15;
            } x64regs;

            struct
            {
                unsigned long eax;
                unsigned long ecx;
                unsigned long edx;
                unsigned long ebx;
                unsigned long esp;
                unsigned long ebp;
                unsigned long esi;
                unsigned long edi;
            } x32regs;
        };
    } CPTHOOK_CTX, *PCPTHOOK_CTX;
    #pragma pack(pop)
    */
    __asm(

        ".intel_syntax noprefix\n"
        // save rax and rbx since we will use them
        "push rax\n"
        "push rbx\n"
        "call 1f\n"
        "1:\n"
        // save return address
        "pop rax\n"
        // make rax point to CPTHOOK_CTX and accoutn for the pushed rax and rbx and call 1f
        "lea rax, [rax + 0x88 + 0x10]\n"

        "");
}
void cpthk_stub64_end(void) {}

bool cpthk_populate_hook_context(uintptr_t Address, int mode)
{
    if (!Address)
        return false;

    switch (mode)
    {
    case 32:
        break;
    case 64:
        // copy the stub
        memcpy((void *)(Address + sizeof(CPTHOOK_CTX)), (void *)cpthk_stub64, (uintptr_t)cpthk_stub64_end - (uintptr_t)cpthk_stub64);
        break;
    default:
        return false;
    }

    return true;
}

bool cpthk_protect_function(PCONTROL_FLOW_GRAPH Cfg, DWORD Protection)
{
    if (!Cfg)
        return false;

    DWORD oldProtect;
    if (!VirtualProtect((void *)Cfg->Address, Cfg->Size, Protection, &oldProtect))
        return false;

    return true;
}

size_t cpthk_write_jmp(uintptr_t Address, uintptr_t Destination, unsigned char *saveBuffer)
{
    // decode instruction at Address and write a jmp to Destination
    // take care of overlapping instructions and such
    // in this case the overlapping instructions will be overwritten with nops
    // so we can just write the jmp

    int size = 0;
    uintptr_t startAddress = Address;
    do
    {
        FdInstr instr;
        int ret = fd_decode((uint8_t *)startAddress, 15, FD_MODE, Address, &instr);
        if (ret > 0)
        {
            memcpy(saveBuffer + size, (void *)startAddress, ret);
            size += ret;
            startAddress += ret;
        }
        else
        {
            return -1;
        }
    } while (size < 5);

    // write jmp at Address
    unsigned char jmp[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    *(uintptr_t *)(jmp + 1) = Destination - Address - 5;
    memcpy((void *)Address, jmp, 5);
    // add nop padding
    memset((void *)(Address + 5), 0x90, size - 5);

    return size;
}
