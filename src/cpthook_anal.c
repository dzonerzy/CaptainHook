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
#include <fadec.h>
#include <cpthook_utils.h>

PCFG_HASHMAP cpthk_create_hashmap(unsigned int Entries)
{
    PCFG_HASHMAP hashmap = (PCFG_HASHMAP)malloc(sizeof(CFG_HASHMAP));
    if (!hashmap)
    {
        return NULL;
    }

    memset(hashmap, 0, sizeof(CFG_HASHMAP));

    hashmap->Entries = (PCFG_HASHMAP_ENTRY *)malloc(sizeof(PCFG_HASHMAP_ENTRY) * Entries);
    if (!hashmap->Entries)
    {
        free(hashmap);
        return NULL;
    }

    memset(hashmap->Entries, 0, sizeof(PCFG_HASHMAP_ENTRY) * Entries);

    hashmap->Size = Entries;
    return hashmap;
}

void cpthk_hashmap_set(PFLOW_GRAPH_NODE Node, PCONTROL_FLOW_GRAPH Cfg)
{
    PCFG_HASHMAP_ENTRY entry = (PCFG_HASHMAP_ENTRY)malloc(sizeof(CFG_HASHMAP_ENTRY));
    if (!entry)
    {
        return;
    }

    memset(entry, 0, sizeof(CFG_HASHMAP_ENTRY));

    entry->Address = Node->Address;
    entry->Node = Node;

    unsigned int index = Node->Address % Cfg->Map->Size;
    entry->Next = Cfg->Map->Entries[index];
    Cfg->Map->Entries[index] = entry;
}

PFLOW_GRAPH_NODE cpthk_hashmap_get(uintptr_t Address, PCONTROL_FLOW_GRAPH Cfg)
{
    unsigned int index = Address % Cfg->Map->Size;
    PCFG_HASHMAP_ENTRY entry = Cfg->Map->Entries[index];

    while (entry)
    {
        if (entry->Address == Address)
        {
            return entry->Node;
        }

        entry = entry->Next;
    }

    return NULL;
}

PCONTROL_FLOW_GRAPH cpthk_build_cfg(uintptr_t Address)
{
    // build control flow graph
    PCONTROL_FLOW_GRAPH cfg = (PCONTROL_FLOW_GRAPH)malloc(sizeof(CONTROL_FLOW_GRAPH));
    if (!cfg)
    {
        return NULL;
    }

    memset(cfg, 0, sizeof(CONTROL_FLOW_GRAPH));

    cfg->Map = cpthk_create_hashmap(256);
    if (!cfg->Map)
    {
        free(cfg);
        return NULL;
    }

    cfg->Address = Address;
    cfg->Head = NULL;
    cfg->Tail = NULL;

    cpthk_create_node(Address, CFG_ISSTART, NULL, cfg);

    if (!(cfg->Head->Flags & CFG_HAVE_MEM_JMP))
        cfg->Size = (cfg->Tail->Address + cfg->Tail->Size) - cfg->Head->Address;
    else
        cfg->Size = (cfg->Tail->Address + cfg->Tail->Size) - cfg->Head->Branch->Address;

    return cfg;
}

PFLOW_GRAPH_NODE cpthk_fall_inside(PCONTROL_FLOW_GRAPH Cfg, uintptr_t Address)
{
    PFLOW_GRAPH_NODE node = Cfg->Head;
    while (node != NULL)
    {
        if (Address >= node->Address && Address < node->Address + node->Size)
        {
            return node;
        }

        node = node->Next;
    }

    return NULL;
}

PSTACK cpthk_create_stack(size_t Size)
{
    PSTACK stack = (PSTACK)malloc(sizeof(STACK));
    if (!stack)
    {
        return NULL;
    }

    memset(stack, 0, sizeof(STACK));

    stack->Entries = (PSTACK_ENTRY)malloc(sizeof(STACK_ENTRY) * Size);
    if (!stack->Entries)
    {
        free(stack);
        return NULL;
    }

    memset(stack->Entries, 0, sizeof(STACK_ENTRY) * Size);

    stack->Current = 0;
    stack->Size = Size;
    return stack;
}

void cpthk_free_stack(PSTACK Stack)
{
    free(Stack->Entries);
    free(Stack);
}

void cpthk_push_stack(PSTACK Stack, uintptr_t Address, DWORD Flags, PFLOW_GRAPH_NODE Prev, PCONTROL_FLOW_GRAPH Cfg)
{
    // if current is 75% of size, double the size
    if (Stack->Current >= Stack->Size * 0.75)
    {
        Stack->Size *= 2;
        Stack->Entries = (PSTACK_ENTRY)realloc(Stack->Entries, sizeof(STACK_ENTRY) * Stack->Size);
        if (!Stack->Entries)
        {
            return;
        }
    }

    PSTACK_ENTRY entry = (PSTACK_ENTRY)malloc(sizeof(STACK_ENTRY));
    if (!entry)
    {
        return;
    }

    memset(entry, 0, sizeof(STACK_ENTRY));

    entry->Address = Address;
    entry->Flags = Flags;
    entry->Cfg = Cfg;
    entry->Prev = Prev;
    // the first push current is 0, so we need to increment it first
    Stack->Entries[Stack->Current++] = *entry;
}

PSTACK_ENTRY cpthk_pop_stack(PSTACK Stack)
{
    if (Stack->Current == 0)
    {
        return NULL;
    }

    return &Stack->Entries[--Stack->Current];
}

bool cpthk_is_stack_empty(PSTACK Stack)
{
    return Stack->Current == 0;
}

void cpthk_create_node(uintptr_t Address, CFG_FLAGS Flags, PFLOW_GRAPH_NODE Prev, PCONTROL_FLOW_GRAPH Cfg)
{
    PFLOW_GRAPH_NODE oldNode = Prev;
    PFLOW_GRAPH_NODE newNode = NULL;
    FdInstr instr;

    // A stack for addresses to process
    PSTACK stack = cpthk_create_stack(128);
    if (!stack)
    {
        return;
    }

    cpthk_push_stack(stack, Address, Flags, Prev, Cfg);

    while (!cpthk_is_stack_empty(stack))
    {
        PSTACK_ENTRY entry = cpthk_pop_stack(stack);

        newNode = cpthk_hashmap_get(entry->Address, Cfg);
        if (newNode)
        {
            // if we already have a node for this address, we can skip it
            // still set branch for the previous node if any
            if (entry->Flags & CFG_ISMANDATORYBRANCH)
            {
                entry->Prev->Branch = newNode;
            }

            if (entry->Flags & CFG_ISFALLTHROUGH)
            {
                entry->Prev->BranchAlt = newNode;
            }

            newNode->Flags |= entry->Flags;

            continue;
        }

        newNode = cpthk_fall_inside(Cfg, entry->Address);
        if (newNode)
        {
            // if we are falling inside a node, we need to split it
            // and make 2 nodes out of it
            // node should end at entry->Address
            // and a new one should start at entry->Address and end at node->Address + node->Size

            PFLOW_GRAPH_NODE newNode2 = (PFLOW_GRAPH_NODE)malloc(sizeof(FLOW_GRAPH_NODE));
            if (!newNode2)
            {
                cpthk_free_stack(stack);
                return;
            }

            memset(newNode2, 0, sizeof(FLOW_GRAPH_NODE));

            newNode2->Address = entry->Address;
            newNode2->Size = newNode->Address + newNode->Size - entry->Address;
            newNode2->Flags |= (newNode->Flags & CFG_ISCONDJMP) ? CFG_ISCONDJMP : 0;
            newNode2->Flags |= (newNode->Flags & CFG_ISJMP) ? CFG_ISJMP : 0;
            newNode2->Visited = false;

            newNode2->Branch = NULL;
            newNode2->BranchAlt = NULL;

            // newNode2->Flags |= entry->Flags;

            if (entry->Flags & CFG_ISMANDATORYBRANCH)
            {
                entry->Prev->Branch = newNode2;
            }

            newNode2->Graph = Cfg;
            newNode2->Next = newNode->Next;
            newNode2->Prev = newNode;
            newNode2->Next->Prev = newNode2;
            newNode->Next = newNode2;

            newNode->Size = entry->Address - newNode->Address;

            // if splitted node has branches and flag CFG_ISCONDJMP | CFG_ISJMP is set on it , put those branches on the new node

            if (newNode->Flags & CFG_ISCONDJMP)
            {
                newNode2->Branch = newNode->Branch;
                newNode2->BranchAlt = newNode->BranchAlt;
                newNode->Branch = NULL;
                newNode->BranchAlt = NULL;
                newNode->Flags &= ~CFG_ISCONDJMP;
            }
            else if (newNode->Flags & CFG_ISJMP)
            {
                newNode2->Branch = newNode->Branch;
                newNode->Branch = NULL;
                newNode->Flags &= ~CFG_ISJMP;
            }
            else if (newNode->Flags & CFG_ISRET || newNode->Flags & CFG_ISEND)
            {
                if (newNode->Flags & CFG_ISRET)
                {
                    newNode2->Flags |= CFG_ISRET;
                    newNode->Flags &= ~CFG_ISRET;
                }

                if (newNode->Flags & CFG_ISEND)
                {
                    newNode2->Flags |= CFG_ISEND;
                    newNode->Flags &= ~CFG_ISEND;
                }

                Cfg->Tail = newNode2;
            }

            // we need to update the hashmap
            cpthk_hashmap_set(newNode2, Cfg);
            continue;
        }

        newNode = (PFLOW_GRAPH_NODE)malloc(sizeof(FLOW_GRAPH_NODE));
        if (!newNode)
        {
            cpthk_free_stack(stack);
            return;
        }

        memset(newNode, 0, sizeof(FLOW_GRAPH_NODE));

        newNode->Address = entry->Address;
        newNode->Size = 0;
        newNode->Flags = entry->Flags;
        newNode->Graph = Cfg;
        newNode->Next = NULL;
        newNode->Prev = NULL;
        newNode->Branch = NULL;
        newNode->BranchAlt = NULL;
        newNode->Visited = false;

        newNode->Prev = oldNode;
        if (oldNode)
        {
            oldNode->Next = newNode;
        }

        if (Cfg->Head == NULL)
        {
            Cfg->Head = oldNode ? oldNode : newNode;
        }

        if ((newNode->Flags & CFG_ISBRANCH) || (newNode->Flags & CFG_ISMANDATORYBRANCH))
        {
            entry->Prev->Branch = newNode;
        }

        if ((newNode->Flags & CFG_ISFALLTHROUGH))
        {
            entry->Prev->BranchAlt = newNode;
        }

        uintptr_t Addr = newNode->Address;

        do
        {
            int ret = fd_decode((uint8_t *)Addr, 15, FD_MODE, Addr, &instr);
            if (ret < 0)
            {
                cpthk_free_stack(stack);
                return;
            }

            Addr += ret;
            newNode->Size += ret;

            if (IS_JMP(instr) && FD_OP_TYPE(&instr, 0) == FD_OT_IMM)
            {
                newNode->Flags |= CFG_ISJMP;
                uintptr_t BranchAddress = FD_OP_IMM(&instr, 0);
                // create a new stack entry
                cpthk_push_stack(stack, BranchAddress, CFG_ISMANDATORYBRANCH, newNode, Cfg);
                // this is the end of the current node
                // so break out of the loop
                break;
            }
            else if (IS_CONDJMP(instr) && FD_OP_TYPE(&instr, 0) == FD_OT_IMM)
            {
                newNode->Flags |= CFG_ISCONDJMP;
                uintptr_t BranchAddress = FD_OP_IMM(&instr, 0);
                uintptr_t FallthroughAddress = Addr;
                // create 2 new stack entries
                // first one is the branch address
                // second one is the fallthrough address
                cpthk_push_stack(stack, FallthroughAddress, CFG_ISFALLTHROUGH, newNode, Cfg);
                cpthk_push_stack(stack, BranchAddress, CFG_ISBRANCH, newNode, Cfg);
                // this is the end of the current node
                // so break out of the loop
                break;
            }
            else if (IS_JMP(instr) && FD_OP_TYPE(&instr, 0) == FD_OT_MEM)
            {
                newNode->Flags |= CFG_ISJMP | CFG_HAVE_MEM_JMP;
                if (FD_OP_BASE(&instr, 0) == FD_REG_IP)
                {
                    uintptr_t *BranchAddress = (uintptr_t *)(Addr + FD_OP_DISP(&instr, 0));
                    // create a new stack entry
                    cpthk_push_stack(stack, *BranchAddress, CFG_ISMANDATORYBRANCH, newNode, Cfg);
                    // this is the end of the current node
                    // so break out of the loop
                }
                else
                {
                    uintptr_t BranchAddress = *(uintptr_t *)FD_OP_DISP(&instr, 0);
                    cpthk_push_stack(stack, BranchAddress, CFG_ISMANDATORYBRANCH, newNode, Cfg);
                }

                break;
            }
            else if (IS_RET(instr))
            {
                // if this is a ret instruction
                // then don't add ret instruction size to the node size
                newNode->Size -= ret;
                newNode->Flags |= CFG_ISRET | CFG_ISEND;
                break;
            }
            else
            {
                PFLOW_GRAPH_NODE testNode = cpthk_hashmap_get(Addr, Cfg);
                if (testNode)
                {
                    // reached an existing node
                    // stop here
                    newNode->Branch = testNode;
                    break;
                }
            }
        } while (TRUE);

        if (newNode->Flags & CFG_ISEND)
        {
            Cfg->Tail = newNode;
        }

        // add this node to the hashmap
        cpthk_hashmap_set(newNode, Cfg);

        oldNode = newNode;
        newNode = NULL;
    }

    cpthk_free_stack(stack);
}

void cpthk_dump_node(PFLOW_GRAPH_NODE Node)
{
    if (Node == NULL)
    {
        return;
    }
    if (FD_MODE == 32)
    {
        printf("--------------------\n");
        printf("Address: 0x%x\n", Node->Address);
        printf("Prev: 0x%x\n", Node->Prev ? Node->Prev->Address : 0);
        printf("Next: 0x%x\n", Node->Next ? Node->Next->Address : 0);
        printf("End: 0x%lx\n", Node->Address + Node->Size);
        printf("Size: %lu\n", Node->Size);
        printf("Flags: %lu\n", Node->Flags);
        if (Node->Branch)
            printf("Branch: 0x%llx\n", Node->Branch->Address);
        if (Node->BranchAlt)
            printf("BranchAlt: 0x%llx\n", Node->BranchAlt->Address);
        for (uintptr_t i = Node->Address; i < (unsigned long long)Node->Address + Node->Size;)
        {
            FdInstr instr;
            int ret = fd_decode((uint8_t *)i, 15, FD_MODE, i, &instr);
            if (ret < 0)
            {
                printf("fd_decode failed\n");
                return;
            }
            char buf[256];
            fd_format(&instr, buf, sizeof(buf));
            printf("0x%x: %s\n", i, buf);
            i += ret;
        }
        printf("--------------------\n");
    }
    else
    {
        printf("--------------------\n");
        printf("Address: 0x%llx\n", Node->Address);
        printf("Prev: 0x%llx\n", Node->Prev ? Node->Prev->Address : 0);
        printf("Next: 0x%llx\n", Node->Next ? Node->Next->Address : 0);
        printf("End: 0x%llx\n", Node->Address + Node->Size);
        printf("Size: %llu\n", Node->Size);
        printf("Flags: %llu\n", Node->Flags);
        if (Node->Branch)
            printf("Branch: 0x%llx\n", Node->Branch->Address);
        if (Node->BranchAlt)
            printf("BranchAlt: 0x%llx\n", Node->BranchAlt->Address);
        for (uintptr_t i = Node->Address; i < (unsigned long long)Node->Address + Node->Size;)
        {
            FdInstr instr;
            int ret = fd_decode((uint8_t *)i, 15, FD_MODE, i, &instr);
            if (ret < 0)
            {
                printf("fd_decode failed\n");
                return;
            }
            char buf[256];
            fd_format(&instr, buf, sizeof(buf));
            printf("0x%llx: %s\n", i, buf);
            i += ret;
        }
        printf("--------------------\n");
    }
}

void cpthk_free_node(PFLOW_GRAPH_NODE Node)
{
    if (Node != NULL)
    {
        free(Node);
        Node = NULL;
    }
}

void cpthk_free_hashmap(PCFG_HASHMAP Map)
{
    if (Map != NULL)
    {
        PCFG_HASHMAP_ENTRY entry;
        PCFG_HASHMAP_ENTRY next;

        for (unsigned int i = 0; i < Map->Size; i++)
        {
            entry = Map->Entries[i];
            while (entry)
            {
                next = entry->Next;
                cpthk_free_node(entry->Node); // Free the node here
                free(entry);
                entry = next;
            }
        }

        free(Map->Entries);
        Map->Entries = NULL;
        free(Map);
        Map = NULL;
    }
}

void cpthk_free_cfg(PCONTROL_FLOW_GRAPH Cfg)
{
    if (Cfg != NULL)
    {
        cpthk_free_hashmap(Cfg->Map); // This will free all nodes
        free(Cfg);
        Cfg = NULL;
    }
}

PXREFS cpthk_find_xref(uintptr_t Address)
{
    PXREFS xrefs = malloc(sizeof(XREFS));

    memset(xrefs, 0, sizeof(XREFS));

    xrefs->Size = 0;
    xrefs->Entries = NULL;
    uintptr_t textSectionAddress = 0;
    size_t textSectionSize = 0;

    size_t sizeOfImage = 0;
    uintptr_t baseAddress = (uintptr_t)GetModuleHandleA(NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);
    // check if 32 bit or 64 bit
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
        sizeOfImage = ntHeaders32->OptionalHeader.SizeOfImage;
    }
    else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
        sizeOfImage = ntHeaders64->OptionalHeader.SizeOfImage;
    }

    cpthk_get_text_section(&textSectionAddress, &textSectionSize);

    for (uintptr_t i = textSectionAddress;;)
    {
        if (i > (textSectionAddress + textSectionSize) - 15)
        {
            break;
        }

        FdInstr instr;
        memset(&instr, 0, sizeof(FdInstr));

        int ret = fd_decode((uint8_t *)i, 15, FD_MODE, i, &instr);

        if (ret > 0)
        {

            i += ret;

            FdInstrType iType = FD_TYPE(&instr);
            switch (iType)
            {
            case FDI_CALL:
                if (FD_OP_TYPE(&instr, 0) == FD_OT_IMM)
                {
                    uintptr_t CallAddress = FD_OP_IMM(&instr, 0);
                    if (CallAddress == Address)
                    {
                        xrefs->Size++;
                        xrefs->Entries = realloc(xrefs->Entries, sizeof(XREF) * xrefs->Size);
                        xrefs->Entries[xrefs->Size - 1].Address = i - ret;
                        xrefs->Entries[xrefs->Size - 1].Type = iType;
                        xrefs->Entries[xrefs->Size - 1].Instr = instr;
                    }
                }
                if (FD_OP_TYPE(&instr, 0) == FD_OT_MEM)
                {
                    if (FD_OP_BASE(&instr, 0) == FD_REG_IP && FD_OP_DISP(&instr, 0) != 0)
                    {
                        // 64 bit only case
                        uintptr_t disp = FD_OP_DISP(&instr, 0) + i;
                        if (disp >= baseAddress && disp <= (baseAddress + sizeOfImage))
                        {
                            if (*(uintptr_t *)(disp) == Address)
                            {
                                xrefs->Size++;
                                xrefs->Entries = realloc(xrefs->Entries, sizeof(XREF) * xrefs->Size);
                                xrefs->Entries[xrefs->Size - 1].Address = i - ret;
                                xrefs->Entries[xrefs->Size - 1].Type = iType;
                                xrefs->Entries[xrefs->Size - 1].Instr = instr;
                            }
                        }
                    }
                    else
                    {
                        // 32 bit only case
                        if (FD_OP_BASE(&instr, 0) == FD_REG_NONE && FD_OP_DISP(&instr, 0) != 0)
                        {
                            uintptr_t disp = FD_OP_DISP(&instr, 0);
                            if (disp >= baseAddress && disp <= (baseAddress + sizeOfImage))
                            {
                                if (*(uintptr_t *)(disp) == Address)
                                {
                                    xrefs->Size++;
                                    xrefs->Entries = realloc(xrefs->Entries, sizeof(XREF) * xrefs->Size);
                                    xrefs->Entries[xrefs->Size - 1].Address = i - ret;
                                    xrefs->Entries[xrefs->Size - 1].Type = iType;
                                    xrefs->Entries[xrefs->Size - 1].Instr = instr;
                                }
                            }
                        }
                    }
                }
                break;
            case FDI_LEA:
                if (FD_OP_TYPE(&instr, 1) == FD_OT_MEM)
                {
                    if (FD_OP_BASE(&instr, 1) == FD_REG_IP && FD_OP_DISP(&instr, 1) != 0)
                    {
                        uintptr_t CallAddress = FD_OP_DISP(&instr, 1) + i;
                        if (CallAddress == Address)
                        {
                            xrefs->Size++;
                            xrefs->Entries = realloc(xrefs->Entries, sizeof(XREF) * xrefs->Size);
                            xrefs->Entries[xrefs->Size - 1].Address = i - ret;
                            xrefs->Entries[xrefs->Size - 1].Type = iType;
                            xrefs->Entries[xrefs->Size - 1].Instr = instr;
                        }
                    }
                }
                break;
            default:
                break;
            }
        }
        else
        {
            i += 1;
        }
    }

    if (xrefs->Size == 0)
    {
        free(xrefs);
        xrefs = NULL;
    }

    return xrefs;
}
