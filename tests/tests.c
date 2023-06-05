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

unsigned int __stdcall test4f(float f1, float f2, float f3, float f4, float f5, float f6, float f7, float f8)
{
    int i = f1;
    if (i < f2 + f3)
    {
        i += f2 + f3;
    }
    else
    {
        for (int j = 0; j < 10; ++j)
        {
            i *= f4 - (f5 + f6 + f7 + f8);
        }
    }
    return i;
}

unsigned int __stdcall test4i(int f1, int f2, int f3, int f4)
{
    int i = f1;
    if (i < f2 + f3)
    {
        i += f2 + f3;
    }
    else
    {
        i += f4;
    }
    return i;
}

__fastcall void entryhook(CPTHOOK_CTX ctx)
{
    LOG_INFO("Inside HookEntry", NULL);
}

__fastcall void exithook(CPTHOOK_CTX ctx)
{
    LOG_INFO("Inside HookExit", NULL);
    ctx.x64.regs[FD_REG_AX] = 1337;
}

int main(int argc, char **argv)
{
    if (!cpthk_init())
    {
        LOG_ERROR("Failed to initialize cpthook", NULL);
        return 1;
    }

    if (!cpthk_hook((uintptr_t)test4i, NULL, exithook))
    {
        LOG_ERROR("Failed to hook test4i", NULL);
        return 1;
    }

    printf("res = %d\n", test4i(1, 2, 3, 4));
    return 0;
}
