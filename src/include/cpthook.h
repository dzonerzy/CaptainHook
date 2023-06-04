#include <cpthook_int.h>
#pragma once
#include <cpthook_anal.h>
#include <cpthook_utils.h>
#include <cpthook_ir.h>
#include <cpthook_temu.h>
#include <fadec-enc.h>

typedef struct _CPTHOOK_CTX
{
    CALLING_CONVENTION CallingConvention;
} CPTHOOK_CTX, *PCPTHOOK_CTX;

typedef void(__stdcall *HOOKFNC)(CPTHOOK_CTX Context);
