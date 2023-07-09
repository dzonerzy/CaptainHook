#pragma once
#include <cpthook.h>

#define TEST_START int tResult = TEST_OK;
#define TEST_END return tResult;

#define ASSERT(cond)                                                                           \
    if (!(cond))                                                                               \
    {                                                                                          \
        if (bVerbose)                                                                          \
            printf(RED "[-] Assertion " #cond " failed at %s:%d\n" RESET, __FILE__, __LINE__); \
        tResult = TEST_FAILED;                                                                 \
    }

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"
#define BLUE "\033[0;34m"
#define RESET "\033[0m"

#define EXT_TESTCASE(name) extern test_status_t test_##name(bool bSkip, bool bVerbose);

#define TEST(name)               \
    {                            \
        #name, test_##name, true \
    }

#define NULL_TEST         \
    {                     \
        NULL, NULL, false \
    }

#define TEST_FUNC(name) \
    test_status_t test_##name(bool bSkip, bool bVerbose)

#define TEST_WILLRUN(n, t, test_name) printf(BLUE "[%d/%d] Running testcase: %s\n" RESET, n + 1, t, test_name, test_name)
#define TEST_PASSED(test_name) printf(GREEN "[+] Passed: %s\n" RESET, test_name)
#define TEST_FAILED(test_name) printf(RED "[-] Failed: %s\n" RESET, test_name)
#define TEST_SKIPPED(test_name) printf(YELLOW "[*] Skipped: %s\n" RESET, test_name)

typedef enum _test_status
{
    TEST_OK,
    TEST_FAILED,
    TEST_SKIPPED
} test_status_t;

typedef struct _test_case
{
    const char *name;
    test_status_t (*testcase)(bool bSkip, bool bVerbose);
    bool enabled;
} test_case_t;

extern test_case_t test_cases[];