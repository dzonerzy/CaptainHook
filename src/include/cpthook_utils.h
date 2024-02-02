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

#pragma once
#include <cpthook.h>
#include <tlhelp32.h>

typedef enum _THREAD_OP
{
    THREAD_OP_SUSPEND,
    THREAD_OP_RESUME
} THREAD_OP;

// JMP [RIP-OFFSET]
#define JMP_RELATIVE64(Address, Destination)  \
    *(unsigned char *)(Address) = 0xFF;       \
    *(unsigned char *)((Address) + 1) = 0x25; \
    *(DWORD *)((Address) + 2) = (DWORD)(((uintptr_t)Destination) - ((uintptr_t)Address) - 6);

#define JMP_ABSOLUTE64(Address, Destination)  \
    *(unsigned char *)(Address) = 0xFF;       \
    *(unsigned char *)((Address) + 1) = 0x25; \
    *(unsigned short *)((Address) + 2) = 0x0; \
    *(uintptr_t *)((Address) + 6) = (uintptr_t)((uintptr_t)Destination);

#define JMP_RELATIVE32(Address, Destination) \
    *(unsigned char *)(Address) = 0xE9;      \
    *(DWORD *)((Address) + 1) = (DWORD)((uintptr_t)Destination) - (DWORD)((uintptr_t)Address) - 5;

uintptr_t cpthk_find_pattern(uint8_t *pBuffer, DWORD dwBufferSize, const char *pPattern);
void cpthk_get_text_section(uintptr_t *textSection, size_t *textSize);
bool cpthk_operate_threads(THREAD_OP Operation);
bool cpthk_protect_function(PCONTROL_FLOW_GRAPH Cfg, DWORD Protection);
bool cpthk_tiny_protect_function(uintptr_t Address, DWORD Protection);
size_t cpthk_write_ud2(uintptr_t Address, unsigned char *saveBuffer, bool entry);
