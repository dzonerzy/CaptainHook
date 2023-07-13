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