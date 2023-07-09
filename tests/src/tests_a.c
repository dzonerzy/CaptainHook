#include <testing.h>
#include <stdint.h>
#include <cpthook_anal.h>

TEST_FUNC(cpthk_init)
{
    TEST_START

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

TEST_FUNC(cpthk_init_twice)
{
    TEST_START

    if (bSkip)
    {
        return TEST_SKIPPED;
    }

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_init();
    ASSERT(status == CPTHK_ALREADY_INITIALIZED);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

TEST_FUNC(cpthk_uninit_twice)
{
    TEST_START

    if (bSkip)
    {
        return TEST_SKIPPED;
    }

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_NOT_INITIALIZED);

    TEST_END
}

unsigned long long factorial(int n)
{
    // use a loop to calculate the factorial
    unsigned long long result = 1;
    for (int i = 1; i <= n; ++i)
    {
        result *= i;
    }

    return result;
}

TEST_FUNC(cpthk_basic_cfg)
{
    TEST_START

    PCONTROL_FLOW_GRAPH cfg = cpthk_build_cfg((uintptr_t)factorial);
    ASSERT(cfg != NULL);
    ASSERT(cfg->Head->Address == (uintptr_t)factorial);

    PFLOW_GRAPH_NODE node = cfg->Head;
    ASSERT(node->Flags & CFG_ISSTART);

    TEST_END
}

float __stdcall t4flt(float f1, float f2, float f3, float f4)
{
    float res = 4.0f;
    if (f3 < 6.0)
    {
        res += f2 + f3;
    }
    else
    {
        res += f4 + f1;
    }
    return res;
}

TEST_FUNC(cpthk_basic_cfg2)
{
    TEST_START

    PCONTROL_FLOW_GRAPH cfg = cpthk_build_cfg((uintptr_t)t4flt);
    ASSERT(cfg != NULL);
    ASSERT(cfg->Head->Address == (uintptr_t)t4flt);

    PFLOW_GRAPH_NODE node = cfg->Head;
    ASSERT(node->Flags & CFG_ISSTART);

    // check it has 2 successors
    ASSERT(node->Branch != NULL);
    ASSERT(node->BranchAlt != NULL);

    TEST_END
}

TEST_FUNC(cpthk_calling_convention_int)
{
    TEST_START

    // call it to allow the emu engine to analyze it
    factorial(5);

    PCONTROL_FLOW_GRAPH cfg = cpthk_build_cfg((uintptr_t)factorial);
    ASSERT(cfg != NULL);
    ASSERT(cfg->Head->Address == (uintptr_t)factorial);

    PFLOW_GRAPH_NODE node = cfg->Head;
    ASSERT(node->Flags & CFG_ISSTART);

    PCALLING_CONVENTION cc = cpthk_find_calling_convention(cfg);

    ASSERT(cc != NULL);
    ASSERT(cc->ArgumentsCount == 1);

    TEST_END
}

TEST_FUNC(cpthk_calling_convention_float)
{
    TEST_START

    // call it to allow the emu engine to analyze it
    t4flt(1.0f, 2.0f, 3.0f, 4.0f);

    PCONTROL_FLOW_GRAPH cfg = cpthk_build_cfg((uintptr_t)t4flt);
    ASSERT(cfg != NULL);
    ASSERT(cfg->Head->Address == (uintptr_t)t4flt);

    PFLOW_GRAPH_NODE node = cfg->Head;
    ASSERT(node->Flags & CFG_ISSTART);

    // check it has 2 successors
    ASSERT(node->Branch != NULL);
    ASSERT(node->BranchAlt != NULL);

    PCALLING_CONVENTION cc = cpthk_find_calling_convention(cfg);

    ASSERT(cc != NULL);
    ASSERT(cc->ArgumentsCount == 4);

    TEST_END
}

bool factorial_hook_called = false;

CPTHK_HOOKFNC(factorial_hook_entry)
{
    factorial_hook_called = true;
}

TEST_FUNC(cpthk_hook_entry_only)
{
    TEST_START

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_hook_entry), NULL);
    ASSERT(status == CPTHK_OK);

    factorial(1337);

    ASSERT(factorial_hook_called);

    status = cpthk_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

unsigned long long factorial_hook_result = 0;

CPTHK_HOOKFNC(factorial_hook_exit)
{
    uintptr_t *ret = cpthk_get_return_param(ctx);
    factorial_hook_result = *ret;
}

TEST_FUNC(cpthk_hook_exit_only)
{
    TEST_START

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_hook((uintptr_t)factorial, NULL, CPTHK_HOOK_NAME(factorial_hook_exit));
    ASSERT(status == CPTHK_OK);

    factorial(9);

    ASSERT(factorial_hook_result == 362880);

    status = cpthk_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

CPTHK_HOOKFNC(factorial_hook_entry2)
{
    factorial_hook_called = true;
    cpthk_set_param_int(ctx, 0, 9);
}

CPTHK_HOOKFNC(factorial_hook_exit2)
{
    uintptr_t *ret = cpthk_get_return_param(ctx);
    factorial_hook_result = *ret;
}

TEST_FUNC(cpthk_hook_complete)
{
    TEST_START

    factorial_hook_called = false;
    factorial_hook_result = 0;

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_hook_entry2), CPTHK_HOOK_NAME(factorial_hook_exit2));
    ASSERT(status == CPTHK_OK);

    factorial(5);

    ASSERT(factorial_hook_result == 362880);
    ASSERT(factorial_hook_called);

    status = cpthk_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

TEST_FUNC(cpthk_hook_disable_enable)
{
    TEST_START

    factorial_hook_called = false;
    factorial_hook_result = 0;

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_hook_entry2), CPTHK_HOOK_NAME(factorial_hook_exit2));
    ASSERT(status == CPTHK_OK);

    factorial(5);

    ASSERT(factorial_hook_result == 362880);
    ASSERT(factorial_hook_called);

    status = cpthk_disable((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    unsigned long long ret = factorial(5);
    ASSERT(ret == 120);

    factorial_hook_called = false;
    factorial_hook_result = 0;

    status = cpthk_enable((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    factorial(5);

    ASSERT(factorial_hook_result == 362880);
    ASSERT(factorial_hook_called);

    status = cpthk_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

bool factorial_tinyhook_called = false;

CPTHK_HOOKFNC(factorial_tinyhook_entry)
{
    factorial_tinyhook_called = true;
}

TEST_FUNC(cpthk_tinyhook)
{
    TEST_START

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_tiny_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_tinyhook_entry));
    ASSERT(status == CPTHK_OK);

    factorial(5);

    ASSERT(factorial_hook_called);

    status = cpthk_tiny_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

uintptr_t factorial_tinyhook_param = 0;

CPTHK_HOOKFNC(factorial_tinyhook_entry2)
{
    factorial_tinyhook_called = true;
#ifdef _WIN64
    factorial_tinyhook_param = CPTHK_REG_CX(ctx);
#else
    uintptr_t ebp = CPTHK_REG_BP(ctx);
    factorial_tinyhook_param = *(uintptr_t *)(ebp - 24); // mov factorial_tinyhook_param, [EBP-24]
#endif
}

TEST_FUNC(cpthk_tinyhook_reg)
{
    TEST_START

    factorial_tinyhook_called = false;

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_tiny_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_tinyhook_entry2));
    ASSERT(status == CPTHK_OK);

    factorial(9);

    ASSERT(factorial_hook_called);
    ASSERT(factorial_tinyhook_param == 9)

    status = cpthk_tiny_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}

TEST_FUNC(cpthk_tinyhook_enable_disable)
{
    TEST_START

    factorial_tinyhook_called = false;
    factorial_tinyhook_param = 0;

    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_tiny_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_tinyhook_entry2));
    ASSERT(status == CPTHK_OK);

    status = cpthk_disable((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    factorial(2);

    ASSERT(!factorial_tinyhook_called);

    status = cpthk_enable((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    factorial(2);

    ASSERT(factorial_tinyhook_called);
    ASSERT(factorial_tinyhook_param == 2)

    status = cpthk_tiny_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);

    TEST_END
}