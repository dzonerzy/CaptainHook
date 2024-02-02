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

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <quickjs.h>

typedef struct CPTHK_JS_ENGINE
{
    JSRuntime *rt;
    JSContext *ctx;
    struct CPTHK_JS_ENGINE *cidht;
} CPTHK_JS_ENGINE, *PCPTHK_JS_ENGINE;

typedef struct JS_CLASSID_HASHTABLE_ENTRY
{
    JSClassID id;
    JSClassDef *def;
    struct JS_CLASSID_HASHTABLE_ENTRY *Next;
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
