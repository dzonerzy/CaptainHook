#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <quickjs.h>

static const JSClassDef gumjs_file_def = {
    .class_name = "File",
};

static const JSCFunctionListEntry gumjs_file_module_entries[] = {
    JS_PROP_INT32_DEF("SEEK_SET", SEEK_SET, JS_PROP_C_W_E),
    JS_PROP_INT32_DEF("SEEK_CUR", SEEK_CUR, JS_PROP_C_W_E),
    JS_PROP_INT32_DEF("SEEK_END", SEEK_END, JS_PROP_C_W_E),
};

int main(int argc, char **argv)
{
    JSRuntime *runtime = JS_NewRuntime();
    JSContext *ctx = JS_NewContext(runtime);
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyFunctionList(ctx, global, gumjs_file_module_entries, countof(gumjs_file_module_entries));

    JS_NewObjectProto(ctx, JS_NULL);
}