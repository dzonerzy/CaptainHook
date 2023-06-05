#include <cpthook.h>
#include <fadec-enc.h>

uintptr_t cpthk_find_pattern(uint8_t *pBuffer, DWORD dwBufferSize, const char *pPattern)
{
    for (uintptr_t i = 0; i < dwBufferSize; i++)
    {
        BOOL bFound = TRUE;
        pPattern = _strupr((char *)pPattern);
        uintptr_t dwPatternSize = strlen(pPattern);
        uintptr_t tmpi = i;

        for (uintptr_t j = 0; j < dwPatternSize; j++)
        {

            if (pPattern[j] == ' ')
            {
                continue;
            }

            if (pPattern[j] == '?')
            {
                continue;
            }

            unsigned char bVal = 0;
            bVal = (pPattern[j] >= '0' && pPattern[j] <= '9') ? pPattern[j] - '0' : pPattern[j] - 'A' + 10;
            bVal <<= 4;
            bVal |= (pPattern[j + 1] >= '0' && pPattern[j + 1] <= '9') ? pPattern[j + 1] - '0' : pPattern[j + 1] - 'A' + 10;
            ;

            if (bVal != pBuffer[tmpi])
            {
                bFound = FALSE;
                break;
            }

            tmpi++;
            j++;
        }

        if (bFound)
        {
            return i + (uintptr_t)pBuffer;
        }
    }

    return 0;
}

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

void __declspec(naked) cpthk_stub32(void)
{
}

void __declspec(naked) cpthk_stub32_end(void)
{
}

void __declspec(naked) cpthk_stub64(void)
{
    __asm(
        ".intel_syntax noprefix\n"
        // save rax and rbx since we will use them
        "push rax\n"
        "push rcx\n"
        "push rbx\n"
        "push rdx\n"
        "call 1f\n"
        "1:\n"
        // save return address
        "pop rax\n"
        // make rax point to CPTHOOK_CTX and accoutn for the pushed rax and rbx and call 1f
        "lea rax, [rax + 0x1a1b1c1d]\n"
        // now rax points to CPTHOOK_CTX
        // save the full context
        // keep in mind that old rax now is in [rsp + 0x18]
        "add rax, 0x08\n"
        "mov rbx, [rsp+0x18]\n"
        "mov [rax], rbx\n" // save rax
        "mov rbx, [rsp + 0x010]\n"
        "mov [rax + 0x08], rbx\n" // save rcx
        "mov rbx, [rsp + 0x08]\n"
        "mov [rax + 0x10], rbx\n" // save rdx
        "mov rbx, [rsp]\n"
        "mov [rax + 0x18], rbx\n" // save rbx
        "mov rbx, rsp\n"
        "add rbx, 0x20\n"
        "mov [rax + 0x20], rbx\n"      // save rsp
        "mov [rax + 0x28], rbp\n"      // save rbp
        "mov [rax + 0x30], rsi\n"      // save rsi
        "mov [rax + 0x38], rdi\n"      // save rdi
        "mov [rax + 0x40], r8\n"       // save r8
        "mov [rax + 0x48], r9\n"       // save r9
        "mov [rax + 0x50], r10\n"      // save r10
        "mov [rax + 0x58], r11\n"      // save r11
        "mov [rax + 0x60], r12\n"      // save r12
        "mov [rax + 0x68], r13\n"      // save r13
        "mov [rax + 0x70], r14\n"      // save r14
        "mov [rax + 0x78], r15\n"      // save r15
        "movss [rax + 0x80], xmm0\n"   // save xmm0
        "movss [rax + 0x90], xmm1\n"   // save xmm1
        "movss [rax + 0xa0], xmm2\n"   // save xmm2
        "movss [rax + 0xb0], xmm3\n"   // save xmm3
        "movss [rax + 0xc0], xmm4\n"   // save xmm4
        "movss [rax + 0xd0], xmm5\n"   // save xmm5
        "movss [rax + 0xe0], xmm6\n"   // save xmm6
        "movss [rax + 0xf0], xmm7\n"   // save xmm7
        "movss [rax + 0x100], xmm8\n"  // save xmm8
        "movss [rax + 0x110], xmm9\n"  // save xmm9
        "movss [rax + 0x120], xmm10\n" // save xmm10
        "movss [rax + 0x130], xmm11\n" // save xmm11
        "movss [rax + 0x140], xmm12\n" // save xmm12
        "movss [rax + 0x150], xmm13\n" // save xmm13
        "movss [rax + 0x160], xmm14\n" // save xmm14
        "movss [rax + 0x170], xmm15\n" // save xmm15
        // we saved the full context
        // now we can freely pop rax, rbx, rcx and rdx
        "pop rdx\n"                     // restore rdx
        "pop rdx\n"                     // restore rbx
        "pop rdx\n"                     // restore rcx
        "pop rdx\n"                     // restore rax
        "lea rbx, [rax + 0x11223344]\n" // rbx points to HookEntry / HookExit
        "lea rcx, [rax - 0x8]\n"
        "call [rbx]\n" // call the hook entry
        // now restore registers based on cpthk_ctx
        "call 2f\n"
        "2:\n"
        "pop rax\n"
        "lea rax, [rax + 0x2a2b2c2d]\n" // rax now points to CPTHOOK_CTX
        "add rax, 0x08\n"               // rax now points to the saved context
        "mov rbx, [rax]\n"              // save rax
        "push rbx\n"
        "mov rbx, [rax + 0x08]\n" // save rcx
        "push rbx\n"
        "mov rbx, [rax + 0x10]\n" // save rdx
        "push rbx\n"
        "mov rbx, [rax + 0x18]\n" // save rbx
        "push rbx\n"
        "mov rbx, rsp\n"
        "add rbx, 0x20\n"
        "mov rsp, rbx\n"               // restore rsp
        "mov rbp, [rax + 0x28]\n"      // restore rbp
        "mov rsi, [rax + 0x30]\n"      // restore rsi
        "mov rdi, [rax + 0x38]\n"      // restore rdi
        "mov r8, [rax + 0x40]\n"       // restore r8
        "mov r9, [rax + 0x48]\n"       // restore r9
        "mov r10, [rax + 0x50]\n"      // restore r10
        "mov r11, [rax + 0x58]\n"      // restore r11
        "mov r12, [rax + 0x60]\n"      // restore r12
        "mov r13, [rax + 0x68]\n"      // restore r13
        "mov r14, [rax + 0x70]\n"      // restore r14
        "mov r15, [rax + 0x78]\n"      // restore r15
        "movss xmm0, [rax + 0x80]\n"   // restore xmm0
        "movss xmm1, [rax + 0x90]\n"   // restore xmm1
        "movss xmm2, [rax + 0xa0]\n"   // restore xmm2
        "movss xmm3, [rax + 0xb0]\n"   // restore xmm3
        "movss xmm4, [rax + 0xc0]\n"   // restore xmm4
        "movss xmm5, [rax + 0xd0]\n"   // restore xmm5
        "movss xmm6, [rax + 0xe0]\n"   // restore xmm6
        "movss xmm7, [rax + 0xf0]\n"   // restore xmm7
        "movss xmm8, [rax + 0x100]\n"  // restore xmm8
        "movss xmm9, [rax + 0x110]\n"  // restore xmm9
        "movss xmm10, [rax + 0x120]\n" // restore xmm10
        "movss xmm11, [rax + 0x130]\n" // restore xmm11
        "movss xmm12, [rax + 0x140]\n" // restore xmm12
        "movss xmm13, [rax + 0x150]\n" // restore xmm13
        "movss xmm14, [rax + 0x160]\n" // restore xmm14
        "movss xmm15, [rax + 0x170]\n" // restore xmm15
        // now restore rax, rbx, rcx and rdx from the stack
        "mov rax, [rsp - 0x8]\n"  // restore rax
        "mov rcx, [rsp - 0x10]\n" // restore rcx
        "mov rdx, [rsp - 0x18]\n" // restore rdx
        "mov rbx, [rsp - 0x20]\n" // restore rbx
        "jmp [rip]\n"             // jump to the trampoline
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "");
}

void __declspec(naked) cpthk_stub64_end(void) {}

size_t cpthk_populate_hook_context(uintptr_t HookContext, uintptr_t Address, uintptr_t Trampoline, int mode)
{
    if (!Address)
        return 0;

    if (mode == 32)
    {
        size_t stubSize = (uintptr_t)cpthk_stub32_end - (uintptr_t)cpthk_stub32;
        // copy the stub
        memcpy((void *)Address, (void *)cpthk_stub32, stubSize);
        uintptr_t *trampolineAddr = (uintptr_t *)cpthk_find_pattern((uint8_t *)Address, stubSize, "90 90 90 90");
        if (trampolineAddr)
            *trampolineAddr = Trampoline;
        else
            return 0;

        // TODO: remove this when 32 bit hooking is implemented
        return 0;
    }
    else if (mode == 64)
    {
        size_t stubSize = (uintptr_t)cpthk_stub64_end - (uintptr_t)cpthk_stub64;
        memcpy((void *)Address, (void *)cpthk_stub64, stubSize);

        uintptr_t *trampolineAddr = (uintptr_t *)cpthk_find_pattern((uint8_t *)Address, stubSize, "90 90 90 90 90 90 90 90");
        if (trampolineAddr)
            *trampolineAddr = Trampoline;
        else
            return 0;

        signed int *firstOffset = (signed int *)cpthk_find_pattern((uint8_t *)Address, stubSize, "1D 1C 1B 1A");
        signed int *secondOffset = (signed int *)cpthk_find_pattern((uint8_t *)Address, stubSize, "2D 2C 2B 2A");

        if (!firstOffset)
            return 0;

        if (!secondOffset)
            return 0;

        *firstOffset = (signed int)(((uintptr_t)firstOffset - HookContext - 4) * -1);
        *secondOffset = (signed int)(((uintptr_t)secondOffset - HookContext - 4) * -1);

        PCPTHOOK_CTX ctx = (PCPTHOOK_CTX)HookContext;

        DWORD offset = Trampoline == ctx->HookTrampolineEntry ? 0x180 : 0x188;

        DWORD *hookOffset = (DWORD *)cpthk_find_pattern((uint8_t *)Address, stubSize, "44 33 22 11");

        if (hookOffset)
            *hookOffset = offset;
        else
            return 0;

        return stubSize;
    }

    return 0;
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
    int limitSize = FD_MODE == 32 ? 5 : 6;
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
    } while (size < limitSize);

    switch (FD_MODE)
    {
    case 32:
        JmpTable.TableEntry[JmpTable.TableCount] = Destination;
        JMP_RELATIVE32(Address, &JmpTable.TableEntry[JmpTable.TableCount]);
        memset((void *)(Address + 5), 0x90, size - limitSize);
        JmpTable.TableCount++;
        break;
    case 64:
        JmpTable.TableEntry[JmpTable.TableCount] = Destination;
        JMP_RELATIVE64(Address, &JmpTable.TableEntry[JmpTable.TableCount]);
        memset((void *)(Address + limitSize), 0x90, size - limitSize);
        JmpTable.TableCount++;
        break;
    default:
        return -1;
    }

    return size;
}
