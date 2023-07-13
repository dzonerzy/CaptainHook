#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <quickjs.h>

typedef struct CPTHK_JS_ENGINE
{
    JSRuntime *rt;
    JSContext *ctx;
    PJS_CLASSID_HASHTABLE cidht;
} CPTHK_JS_ENGINE, *PCPTHK_JS_ENGINE;

typedef struct JS_CLASSID_HASHTABLE_ENTRY
{
    JSClassID id;
    JSClassDef *def;
    PJS_CLASSID_HASHTABLE_ENTRY Next;
} JS_CLASSID_HASHTABLE_ENTRY, *PJS_CLASSID_HASHTABLE_ENTRY;

typedef struct JS_CLASSID_HASHTABLE
{
    unsigned long Size;
    unsigned long Count;
    PJS_CLASSID_HASHTABLE_ENTRY *Entries;
} JS_CLASSID_HASHTABLE, *PJS_CLASSID_HASHTABLE;

#define CPTHK_DEFINE_FINALIZER(N) \
    static void cpthk_##N##_finalizer(JSRuntime *rt, JSValue val)

#define CPTHK_DEFINE_CLASS(N) \
    static JSValue cpthk_##N##_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv)

#define CPTHK_DEFINE_CLASS_DEF(N) \
    static const JSClassDef cpthk_##N##_class_def = {#N, .finalizer = cpthk_##N##_finalizer, .call = cpthk_##N##_constructor}

#define CPTHK_CREATE_CLASS(N) \
    JSValue cpthk_##N(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv);

#define CPTHK_CREATE_CLASS_DEF(N)                      \
    CPTHK_DEFINE_CLASS_DEF(N);                         \
    CPTHK_CREATE_CLASS(N)                              \
    {                                                  \
        return cpthk_##N(ctx, new_target, argc, argv); \
    }

void cpthk_js_add_to_global_object(PCPTHK_JS_ENGINE core, const char *name, JSValue val);
void cpthk_js_create_class(PCPTHK_JS_ENGINE core, JSContext *ctx, const JSClassDef *def, JSClassID *klass, JSValue *prototype);
JSClassID cpthk_get_class_id_for_class_def(PCPTHK_JS_ENGINE core, const JSClassDef *def);
bool cpthk_js_init_core(void);

extern PCPTHK_JS_ENGINE core;
