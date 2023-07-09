#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <testing.h>

EXT_TESTCASE(cpthk_init)
EXT_TESTCASE(cpthk_init_twice)
EXT_TESTCASE(cpthk_uninit_twice)
EXT_TESTCASE(cpthk_basic_cfg)
EXT_TESTCASE(cpthk_basic_cfg2)
EXT_TESTCASE(cpthk_calling_convention_int)
EXT_TESTCASE(cpthk_calling_convention_float)
EXT_TESTCASE(cpthk_hook_entry_only)
EXT_TESTCASE(cpthk_hook_exit_only)
EXT_TESTCASE(cpthk_hook_complete)
EXT_TESTCASE(cpthk_hook_disable_enable)
EXT_TESTCASE(cpthk_tinyhook)
EXT_TESTCASE(cpthk_tinyhook_reg)
EXT_TESTCASE(cpthk_tinyhook_enable_disable)

test_case_t test_cases[] = {
    TEST(cpthk_init),
    TEST(cpthk_init_twice),
    TEST(cpthk_uninit_twice),
    TEST(cpthk_basic_cfg),
    TEST(cpthk_basic_cfg2),
    TEST(cpthk_calling_convention_int),
    TEST(cpthk_calling_convention_float),
    TEST(cpthk_hook_entry_only),
    TEST(cpthk_hook_exit_only),
    TEST(cpthk_hook_complete),
    TEST(cpthk_hook_disable_enable),
    TEST(cpthk_tinyhook),
    TEST(cpthk_tinyhook_reg),
    TEST(cpthk_tinyhook_enable_disable),
    NULL_TEST,
};

typedef struct options
{
    bool list;
    bool skip;
    bool save;
    bool verbose;
    char *testcase;
} options_t;

void usage(char *argv[])
{
    // usage based on args t:lsSvh

    printf("Usage: %s [-t testcase] [-l] [-s] [-S] [-v] [-h]\n", argv[0]);
    printf("Options:\n");
    printf("  -t <testcase>  Run a specific testcase\n");
    printf("  -l             List all testcases\n");
    printf("  -s             Skip tests that are marked as skip\n");
    printf("  -S             Save test results to file\n");
    printf("  -v             Verbose output\n");
    printf("  -h             Show this help message\n");
}

char *optarg;
int optind = 1;
int opterr = 1;
int optopt;

int getopt(int argc, char *const argv[], const char *optstring)
{
    static char *next = NULL;
    char c;
    char *cp;

    if (optind >= argc || argv[optind] == NULL || argv[optind][0] != '-' || strcmp(argv[optind], "--") == 0)
        return -1;

    if (next == NULL || *next == '\0')
        next = argv[optind] + 1;

    optopt = c = *next++;
    cp = strchr(optstring, c);
    if (cp == NULL || c == ':')
    {
        if (opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        return '?';
    }

    if (cp[1] == ':')
    {
        if (*next != '\0')
        {
            optarg = next;
            next = NULL;
        }
        else if (optind < argc - 1)
        {
            optarg = argv[++optind];
            next = NULL;
        }
        else
        {
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            return optstring[0] == ':' ? ':' : '?';
        }
    }

    if (next == NULL || *next == '\0')
        ++optind;

    return c;
}

options_t *parse_options(int argc, char **argv)
{
    options_t *options = (options_t *)malloc(sizeof(options_t));
    if (options == NULL)
    {
        return NULL;
    }
    memset(options, 0, sizeof(options_t));

    int c;
    while ((c = getopt(argc, argv, "t:lsSvh")) != -1)
    {
        switch (c)
        {
        case 't':
            options->testcase = optarg;
            break;
        case 'l':
            options->list = true;
            break;
        case 's':
            options->skip = true;
            break;
        case 'S':
            options->save = true;
            break;
        case 'v':
            options->verbose = true;
            break;
        case 'h':
            usage(argv);
            exit(0);
            break;
        case ':':
            printf("Missing argument for option -%c\n", optopt);
            usage(argv);
            exit(1);
            break;
        case '?':
            printf("Unknown option -%c\n", optopt);
            usage(argv);
            exit(1);
            break;
        default:
            break;
        }
    }

    return options;
}

char *get_platform()
{
#ifdef _WIN64
// check compiler
#if defined(__MINGW64__)
    return "Windows x64 (MinGW-w64)";
#elif defined(_MSC_VER)
    return "Windows x64 (MSVC)";
#else
    return "Windows x64";
#endif
#else
// check compiler
#if defined(__MINGW32__)
    return "Windows x86 (MinGW-w32)";
#elif defined(_MSC_VER)
    return "Windows x86 (MSVC)";
#else
    return "Windows x86";
#endif
#endif
}

char *get_bits()
{
#ifdef _WIN64
    return "64";
#else
    return "32";
#endif
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    // parse options
    options_t *options = parse_options(argc, argv);

    char filename[256];
    FILE *fp;

    if (options->save)
    {
        snprintf(filename, sizeof(filename), "test-cpthook-v%s.%s.%s-%sbit.log", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION, get_bits());
        fp = freopen(filename, "w", stdout);
    }

    // run tests
    if (options->testcase == NULL)
    {
        printf("[*] Running %d %s\n", sizeof(test_cases) / sizeof(test_case_t) - 1, sizeof(test_cases) / sizeof(test_case_t) - 1 == 1 ? "test" : "tests");
    }
    else
    {
        printf("[*] Running %s\n", options->testcase);
    }
    printf("------------------------------------------------------------\n");
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    if (options->testcase != NULL)
    {
        for (int i = 0; test_cases[i].name != NULL; i++)
        {
            if (strcmp(test_cases[i].name, options->testcase) == 0)
            {
                TEST_WILLRUN(0, 1, test_cases[i].name);

                test_status_t status = test_cases[i].testcase(options->skip, options->verbose);

                if (status == TEST_OK)
                {
                    TEST_PASSED(test_cases[i].name);
                    passed++;
                }
                else if (status == TEST_SKIPPED)
                {
                    TEST_SKIPPED(test_cases[i].name);
                    skipped++;
                }
                else
                {
                    TEST_FAILED(test_cases[i].name);
                    failed++;
                }
            }
        }
    }
    else if (options->list)
    {
        printf("Available tests:\n");
        for (int i = 0; test_cases[i].name != NULL; i++)
        {
            printf("    - " BLUE "%s\n" RESET, test_cases[i].name);
        }
    }
    else
    {
        for (int i = 0; test_cases[i].name != NULL; i++)
        {
            if (test_cases[i].enabled)
            {
                TEST_WILLRUN(i, sizeof(test_cases) / sizeof(test_case_t) - 1, test_cases[i].name);

                test_status_t status = test_cases[i].testcase(options->skip, options->verbose);

                if (status == TEST_OK)
                {
                    TEST_PASSED(test_cases[i].name);
                    passed++;
                }
                else if (status == TEST_SKIPPED)
                {
                    TEST_SKIPPED(test_cases[i].name);
                    skipped++;
                }
                else
                {
                    TEST_FAILED(test_cases[i].name);
                    failed++;
                }
            }
        }
    }

    if (!options->list)
    {
        printf("------------------------------------------------------------\n");
        printf(BLUE "[I] Platform: %s\n" RESET, get_platform());
        printf(BLUE "[I] Tested CaptainHook v%s\n" RESET, cpthk_version());
        printf(GREEN "[+] Passed: %d\n" RESET, passed);
        printf(RED "[-] Failed: %d\n" RESET, failed);
        printf(YELLOW "[*] Skipped: %d\n" RESET, skipped);
    }

    if (options->save)
    {
        fclose(fp);
        freopen("CON", "w", stdout);
        freopen("CON", "w", stderr);

        printf(BLUE "[I] Saved log to %s\n" RESET, filename);
    }

    return 0;
}