#include <cpthook.h>

#define FIRST_ARG(N, ...) N
#define TEST_FUNC(callingconvention, name, firsttype, firstname, ...) \
    void callingconvention name(firsttype firstname __VA_ARGS__)      \
    {                                                                 \
        char buffer[256];                                             \
        memcpy(buffer, firstname, sizeof(buffer));                    \
        return;                                                       \
    }
#define LOG_ERROR(fmt, ...) printf("[E] " fmt "\n", __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("[I] " fmt "\n", __VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printf("[D] " fmt "\n", __VA_ARGS__)
#define ASSERT(cond) \
    if (!(cond))     \
    {                \
        return;      \
    }

int fact(int n)
{
    switch (n)
    {
    case 0:
        return 1;
    case 1:
        return 2;
    case 2:
        return 3;
    default:
        return fact(n - 1) + fact(n - 2);
    }

    return 0;
}

unsigned int factorial(int n)
{
    // use a loop to calculate the factorial
    unsigned int result = 1;
    for (int i = 1; i <= n; ++i)
    {
        result *= i;
    }

    return result;
}

float __stdcall test4f(float f1, float f2, float f3, float f4)
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

unsigned int __stdcall test4i(int f1, int f2, int f3, int f4)
{
    int i = f1;
    if (i < f2 - f3)
    {
        i += f2 + f3;
    }
    else
    {
        i += f4;
    }
    return i;
}

unsigned long __stack_chk_guard;
void __stack_chk_guard_setup(void)
{
    __stack_chk_guard = 0xBAAAAAAD; // provide some magic numbers
}

void __stack_chk_fail(void)
{
    /* Error message */
}

void __stdcall entryhook(PCPTHOOK_CTX ctx)
{
    cpthk_set_param_int(ctx, 2, 25);
    cpthk_set_param_int(ctx, 3, 29);
}

void __stdcall exithook(PCPTHOOK_CTX ctx)
{
    uintptr_t *ret = cpthk_get_return_param(ctx);
    printf("next ret: %p\n", *ret);
}

int main(int argc, char **argv)
{
    printf("[+] Using %s\n", cpthk_version());

    if (cpthk_init() != CPTHK_OK)
    {
        LOG_ERROR("Failed to initialize cpthook", NULL);
        return 1;
    }

    CPTHK_STATUS status = cpthk_hook((uintptr_t)test4i, entryhook, exithook);

    if (status != CPTHK_OK)
    {
        LOG_ERROR("Failed to hook test4i (%s)", cpthk_str_error(status));
        return 1;
    }

    system("pause");

    printf("res = %p\n", test4i(1, 2, 3, 4));

    if (cpthk_disable((uintptr_t)test4i) != CPTHK_OK)
    {
        LOG_ERROR("Failed to disable test4i (%s)", cpthk_str_error(status));
        return 1;
    }

    printf("res = %p\n", test4i(1, 2, 3, 4));

    if (cpthk_enable((uintptr_t)test4i) != CPTHK_OK)
    {
        LOG_ERROR("Failed to enable test4i (%s)", cpthk_str_error(status));
        return 1;
    }

    printf("res = %p\n", test4i(1, 2, 3, 4));

    if (cpthk_unhook((uintptr_t)test4i) != CPTHK_OK)
    {
        LOG_ERROR("Failed to unhook test4i (%s)", cpthk_str_error(status));
        return 1;
    }

    printf("res = %p\n", test4i(1, 2, 3, 4));

    if ((status = cpthk_enable((uintptr_t)test4i)) != CPTHK_OK)
    {
        LOG_ERROR("Failed to enable test4i (%s)", cpthk_str_error(status));
        return 1;
    }

    cpthk_uninit();
    return 0;
}
