/*
 * cpthook (CaptainHook) - A prototype-less hooking library for Windows
 *
 * This library allows for hooking functions without the need to know their signatures,
 * providing a flexible solution for intercepting and manipulating function calls at runtime.
 *
 * Author: Daniele 'dzonerzy' Linguaglossa
 *
 * Created on: 06/04/2023
 *
 * License: MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <cpthook.h>

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

bool cpthk_protect_function(PCONTROL_FLOW_GRAPH Cfg, DWORD Protection)
{
    if (!Cfg)
        return false;

    DWORD oldProtect;

    if (!(Cfg->Head->Flags & CFG_HAVE_MEM_JMP))
    {
        if (!VirtualProtect((void *)Cfg->Address, Cfg->Size, Protection, &oldProtect))
            return false;
    }
    else
    {
        if (!VirtualProtect((void *)Cfg->Head->Branch->Address, Cfg->Size, Protection, &oldProtect))
            return false;
    }

    return true;
}

bool cpthk_tiny_protect_function(uintptr_t Address, DWORD Protection)
{
    DWORD oldProtect;

    if (!VirtualProtect((void *)Address, 0x100, Protection, &oldProtect))
        return false;

    return true;
}

size_t cpthk_write_ud2(uintptr_t Address, unsigned char *saveBuffer, bool entry)
{
    // decode instruction at Address and write a jmp to Destination
    // take care of overlapping instructions and such
    // in this case the overlapping instructions will be overwritten with nops
    // so we can just write the jmp

    int size = 0;
    int limitSize = 5;
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

    *(unsigned short *)(Address) = 0x0b0f;
    *(unsigned short *)(Address + 2) = HookList->Count - 1;
    *(unsigned char *)(Address + 4) = entry ? 1 : 0;
    memset((void *)(Address + limitSize), 0x90, size - limitSize);

    return size;
}
