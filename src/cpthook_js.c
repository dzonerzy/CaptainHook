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

#include <cpthook_js.h>

PCPTHK_JS_ENGINE core;

bool cpthk_js_init_core(void)
{
    core = malloc(sizeof(CPTHK_JS_ENGINE));
    if (core == NULL)
        return false;

    core->rt = JS_NewRuntime();
    if (core->rt == NULL)
    {
        free(core);
        return false;
    }

    core->ctx = JS_NewContext(core->rt);
    if (core->ctx == NULL)
    {
        JS_FreeRuntime(core->rt);
        free(core);
        return false;
    }

    core->cidht = cpthk_js_create_hashtable(128);
    if (core->cidht == NULL)
    {
        JS_FreeContext(core->ctx);
        JS_FreeRuntime(core->rt);
        free(core);
        return false;
    }

    return true;
}

PJS_CLASSID_HASHTABLE cpthk_js_create_hashtable(unsigned int Entries)
{
    PJS_CLASSID_HASHTABLE hashtable = (PJS_CLASSID_HASHTABLE)malloc(sizeof(JS_CLASSID_HASHTABLE));
    if (!hashtable)
    {
        return NULL;
    }

    memset(hashtable, 0, sizeof(JS_CLASSID_HASHTABLE));

    hashtable->Entries = (PJS_CLASSID_HASHTABLE *)malloc(sizeof(PJS_CLASSID_HASHTABLE) * Entries);
    if (!hashtable->Entries)
    {
        free(hashtable);
        return NULL;
    }

    memset(hashtable->Entries, 0, sizeof(PJS_CLASSID_HASHTABLE) * Entries);

    hashtable->Size = Entries;
    return hashtable;
}

void cpthk_js_hashtable_set(JSClassDef *def, JSClassID id, PJS_CLASSID_HASHTABLE hashtable)
{
    PJS_CLASSID_HASHTABLE_ENTRY entry = (PJS_CLASSID_HASHTABLE_ENTRY)malloc(sizeof(JS_CLASSID_HASHTABLE_ENTRY));
    if (!entry)
    {
        return;
    }

    memset(entry, 0, sizeof(JS_CLASSID_HASHTABLE_ENTRY));

    entry->def = def;
    entry->id = id;

    unsigned long long index = (uintptr_t)def % hashtable->Size;
    PJS_CLASSID_HASHTABLE_ENTRY current = hashtable->Entries[index];

    if (!current)
    {
        hashtable->Entries[index] = entry;
        hashtable->Count++;
        return;
    }
    else
    {
        while (current->Next)
        {
            current = current->Next;
        }

        current->Next = entry;
        hashtable->Count++;
        return;
    }
}

PJS_CLASSID_HASHTABLE_ENTRY cpthk_hashmap_get(JSClassDef *def, PJS_CLASSID_HASHTABLE hashtable)
{
    unsigned long long index = (uintptr_t)def % hashtable->Size;
    PJS_CLASSID_HASHTABLE_ENTRY entry = hashtable->Entries[index];

    while (entry)
    {
        if (entry->def == def)
        {
            return entry;
        }

        entry = entry->Next;
    }

    return NULL;
}

JSClassID cpthk_get_class_id_for_class_def(PCPTHK_JS_ENGINE core, const JSClassDef *def)
{
    JSClassID id;

    PJS_CLASSID_HASHTABLE_ENTRY entry = cpthk_hashmap_get(def, core->cidht);

    if (entry)
    {
        return entry->id;
    }
    else
    {
        JS_NewClassID(&id);
        cpthk_js_hashtable_set(def, id, core->cidht);
    }

    return id;
}

void cpthk_js_create_class(PCPTHK_JS_ENGINE core, JSContext *ctx, const JSClassDef *def, JSClassID *klass, JSValue *prototype)
{
    JSClassID id;
    JSValue proto;

    id = cpthk_get_class_id_for_class_def(core, def);

    JS_NewClass(core->rt, id, def);

    proto = JS_NewObject(ctx);

    JS_SetClassProto(ctx, id, proto);

    *klass = id;
    *prototype = proto;
}

void cpthk_js_add_to_global_object(PCPTHK_JS_ENGINE core, const char *name, JSValue val)
{
    JSContext *ctx = core->ctx;
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global_obj, name, val);
    JS_FreeValue(ctx, global_obj);
}
