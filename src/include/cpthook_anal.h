#pragma once
#include <cpthook_int.h>
#include <fadec.h>

// if 32bit define FD_MODE 32
// if 64bit define FD_MODE 64

#if defined(_WIN64)
#define FD_MODE 64
#else
#define FD_MODE 32
#endif

// FGN_ISRET
typedef enum _CFG_FLAGS
{
    CFG_NONE = 0x00000000,
    CFG_ISJMP = 0x00000001,
    CFG_ISCONDJMP = 0x00000002,
    CFG_ISRET = 0x00000004,
    CFG_ISBRANCH = 0x00000008,
    CFG_ISFALLTHROUGH = 0x000000010,
    CFG_ISMANDATORYBRANCH = 0x00000020,
    CFG_ISEND = 0x00000040,
    CFG_ISSTART = 0x00000080,
} CFG_FLAGS;

typedef struct _CONTROL_FLOW_GRAPH
{
    uintptr_t Address;
    SIZE_T Size;
    DWORD Flags;
    struct _FLOW_GRAPH_NODE *Head;
    struct _FLOW_GRAPH_NODE *Tail;
    struct _CFG_HASHMAP *Map;
} CONTROL_FLOW_GRAPH, *PCONTROL_FLOW_GRAPH;

typedef struct _FLOW_GRAPH_NODE
{
    bool Visited;
    uintptr_t Address;
    SIZE_T Size;
    DWORD Flags;
    struct _FLOW_GRAPH_NODE *Prev;
    struct _FLOW_GRAPH_NODE *Next;
    struct _FLOW_GRAPH_NODE *Branch;
    struct _FLOW_GRAPH_NODE *BranchAlt;
    PCONTROL_FLOW_GRAPH Graph;
} FLOW_GRAPH_NODE, *PFLOW_GRAPH_NODE;

typedef struct _CFG_HASHMAP_ENTRY
{
    uintptr_t Address;
    struct _FLOW_GRAPH_NODE *Node;
    struct _CFG_HASHMAP_ENTRY *Next;
} CFG_HASHMAP_ENTRY, *PCFG_HASHMAP_ENTRY;

typedef struct _CFG_HASHMAP
{
    PCFG_HASHMAP_ENTRY *Entries;
    SIZE_T Size;
} CFG_HASHMAP, *PCFG_HASHMAP;

typedef struct _STACK_ENTRY
{
    uintptr_t Address;
    DWORD Flags;
    PCONTROL_FLOW_GRAPH Cfg;
    PFLOW_GRAPH_NODE Prev;
} STACK_ENTRY, *PSTACK_ENTRY;

typedef struct _STACK
{
    PSTACK_ENTRY Entries;
    unsigned long long Current;
    SIZE_T Size;
} STACK, *PSTACK;

typedef struct _XREF
{
    uintptr_t Address;
    FdInstrType Type;
    FdInstr Instr;
} XREF, *PXREF;

typedef struct _XREFS
{
    PXREF Entries;
    SIZE_T Size;
} XREFS, *PXREFS;

#define IS_RET(instr) (FD_TYPE(&instr) == FDI_RET || FD_TYPE(&instr) == FDI_RETF || FD_TYPE(&instr) == FDI_IRET)
#define IS_JMP(instr) (FD_TYPE(&instr) == FDI_JMP)
#define IS_CALL(instr) (FD_TYPE(&instr) == FDI_CALL)
#define IS_CONDJMP(instr) (FD_TYPE(&instr) >= FDI_JA && FD_TYPE(&instr) <= FDI_JZ && FD_TYPE(&instr) != FDI_JMP)
#define IS_JMPREG(instr) (ISJMP(instr) || ISCONDJMP(instr) && FD_OP_TYPE(&instr, 0) == FD_OP_REG)
#define IS_BRANCH(flags) (flags & CFG_ISBRANCH)
#define IS_BRANCHALT(flags) (flags & CFG_ISBRANCHALT)

PSTACK cpthk_create_stack(size_t Size);
void cpthk_free_stack(PSTACK Stack);
PCFG_HASHMAP cpthk_create_hashmap(unsigned int Entries);
void cpthk_hashmap_set(PFLOW_GRAPH_NODE Node, PCONTROL_FLOW_GRAPH Cfg);
PFLOW_GRAPH_NODE cpthk_hashmap_get(uintptr_t Address, PCONTROL_FLOW_GRAPH Cfg);
PCONTROL_FLOW_GRAPH cpthk_build_cfg(uintptr_t Address);
void cpthk_create_node(uintptr_t Address, CFG_FLAGS Flags, PFLOW_GRAPH_NODE Prev, PCONTROL_FLOW_GRAPH Cfg);
void cpthk_free_node(PFLOW_GRAPH_NODE Node);
void cpthk_free_hashmap(PCFG_HASHMAP Map);
void cpthk_free_cfg(PCONTROL_FLOW_GRAPH Cfg);
void cpthk_dump_node(PFLOW_GRAPH_NODE Node);
PXREFS cpthk_find_xref(uintptr_t Address);
