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

static JSValue cpthk_js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
    if (argc > 0)
    {
        const char *str = JS_ToCString(ctx, argv[0]);
        if (str != NULL)
        {
            printf("%s\n", str);
            JS_FreeCString(ctx, str);
        }
    }

    return JS_UNDEFINED;
}

void cpthk_js_native_pointer_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv)
{
}

void cpthk_js_populate_globals(PCPTHK_JS_ENGINE core)
{
    JSValue global_obj = JS_GetGlobalObject(core->ctx);

    JSValue captain_hook_obj = JS_NewObject(core->ctx);
    JS_SetPropertyStr(core->ctx, captain_hook_obj, "version", JS_NewString(core->ctx, cpthk_version()));
    JS_SetPropertyStr(core->ctx, global_obj, "CaptainHook", captain_hook_obj);

    JSValue captain_hook_error_obj = JS_NewObject(core->ctx);
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_OK", JS_NewInt32(core->ctx, CPTHK_OK));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_ALREADY_INITIALIZED", JS_NewInt32(core->ctx, CPTHK_ALREADY_INITIALIZED));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_NOT_INITIALIZED", JS_NewInt32(core->ctx, CPTHK_NOT_INITIALIZED));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_UNABLE_TO_CONTROL_THREADS", JS_NewInt32(core->ctx, CPTHK_UNABLE_TO_CONTROL_THREADS));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_UNABLE_TO_PROTECT_MEMORY", JS_NewInt32(core->ctx, CPTHK_UNABLE_TO_PROTECT_MEMORY));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_HOOK_ALREADY_EXISTS", JS_NewInt32(core->ctx, CPTHK_HOOK_ALREADY_EXISTS));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_HOOK_NOT_FOUND", JS_NewInt32(core->ctx, CPTHK_HOOK_NOT_FOUND));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_UNABLE_TO_BUILD_CFG", JS_NewInt32(core->ctx, CPTHK_UNABLE_TO_BUILD_CFG));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_OUT_OF_MEMORY", JS_NewInt32(core->ctx, CPTHK_OUT_OF_MEMORY));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION", JS_NewInt32(core->ctx, CPTHK_UNABLE_TO_FIND_CALLING_CONVENTION));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_INTERNAL_ERROR", JS_NewInt32(core->ctx, CPTHK_INTERNAL_ERROR));
    JS_SetPropertyStr(core->ctx, captain_hook_error_obj, "CPTHK_UNABLE_TO_QUERY_MEMORY", JS_NewInt32(core->ctx, CPTHK_UNABLE_TO_QUERY_MEMORY));

    JSValue console = JS_NewObject(core->ctx);
    JS_SetPropertyStr(core->ctx, console, "log", JS_NewCFunction(core->ctx, cpthk_js_console_log, "log", 1));

    JS_FreeValue(core->ctx, global_obj);
}

bool cpthk_js_init_module(PCPTHK_JS_ENGINE core)
{
    if (core == NULL)
    {
        if (!cpthk_js_init_core())
        {
            return false;
        }
    }

    return true;
}