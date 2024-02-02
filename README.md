## CaptainHook - A simple prototype-less hooking library for Windows

CaptainHook is a simple prototype-less hooking library for Windows. It is designed to be used in a similar way to the Detours library, but it allows to hook functions without prior knowledge of their prototypes. This is achieved by using a lightweight disassembler and emulator to understand the function's calling convention and to generate a trampoline that can be used to hook the function.

## Usage

The library is very simple to use. You can hook a function by calling the `cpthk_hook` function and passing the address of the function to hook, and two different callbacks:
 - onEnter: This callback is called before the original function is called. It receives the original function's arguments and can modify them.
 - onExit: This callback is called after the original function is called. It receives the original function's return value and can modify it.
  
the `cpthk_hook` function returns a status code that indicates if the hook was successful or not.

```c
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

void __stdcall cpthk_factorial_hook_entry(CPTHOOK_CTX *ctx)
{
    factorial_hook_called = true;
    cpthk_set_param_int(ctx, 0, 9);
}

void __stdcall cpthk_factorial_hook_exit(CPTHOOK_CTX *ctx)
{
    uintptr_t *ret = cpthk_get_return_param(ctx);
    factorial_hook_result = *ret;
}


void main(int argc, char ** argv)
{
    CPTHK_STATUS status = cpthk_init();
    ASSERT(status == CPTHK_OK);

    status = cpthk_hook((uintptr_t)factorial, CPTHK_HOOK_NAME(factorial_hook_entry), CPTHK_HOOK_NAME(factorial_hook_exit));

    ASSERT(status == CPTHK_OK);

    // call factorial and check the result
    // you will get factorial(9) instead of factorial(2)
    unsigned long long result = factorial(2);

    status = cpthk_unhook((uintptr_t)factorial);
    ASSERT(status == CPTHK_OK);

    status = cpthk_uninit();
    ASSERT(status == CPTHK_OK);
}

```  

The function `cpthk_unhook` is used to remove the hook from the function. It is important to call this function before the program exits, to avoid leaving the original function in a hooked state.

## Building

The library is built using meson. You can build it by running the following commands:

```bash
meson build
ninja -C build
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

```
Copyright (c) 2024 Daniele Linguaglossa

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```
