#ifndef FILLI_INTRINSICS_H_INCLUDED
#define FILLI_INTRINSICS_H_INCLUDED

uint16_t print_id;
uint16_t typeof_id;
uint16_t len_id;
uint16_t keys_id;
uint16_t array_insert_id;
uint16_t array_remove_id;
uint16_t dict_remove_id;

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame)
{
    #define STACK_PUSH2(X) {\
        assert2(,frame->stackpos < FRAME_STACKSIZE);\
        frame->stack[frame->stackpos++] = X; }
    
    if (id == print_id)
    {
        for (size_t i = 0; i < argcount; i++)
        {
            long long int offset = i - argcount;
            int tag = frame->stack[frame->stackpos + offset].tag;
            if      (tag == VALUE_FLOAT)    prints(baddtostr(frame->stack[frame->stackpos + offset].u.f));
            else if (tag == VALUE_STRING)   prints(*frame->stack[frame->stackpos + offset].u.s);
            else if (tag == VALUE_ARRAY)    prints("<array>");
            else if (tag == VALUE_DICT)     prints("<dict>");
            else if (tag == VALUE_FUNC)     prints("<func>");
            else if (tag == VALUE_STATE)    prints("<funcstate>");
            else if (tag == VALUE_NULL)     prints("null");
            
            if (i + 1 < argcount) prints(" ");
        }
        prints("\n");
        frame->stackpos -= argcount;
        STACK_PUSH2(val_tagged(VALUE_NULL))
    }
    else if (id == typeof_id)
    {
        assert2(, argcount == 1, "Wrong number of arguments to function");
        
        int tag = frame->stack[frame->stackpos - 1].tag;
        frame->stackpos -= 1;
        if      (tag == VALUE_FLOAT)    STACK_PUSH2(val_string(stringdup("float")))
        else if (tag == VALUE_STRING)   STACK_PUSH2(val_string(stringdup("string")))
        else if (tag == VALUE_ARRAY)    STACK_PUSH2(val_string(stringdup("array")))
        else if (tag == VALUE_DICT)     STACK_PUSH2(val_string(stringdup("dict")))
        else if (tag == VALUE_FUNC)     STACK_PUSH2(val_string(stringdup("funcref")))
        else if (tag == VALUE_STATE)    STACK_PUSH2(val_string(stringdup("funcstate")))
        else if (tag == VALUE_NULL)     STACK_PUSH2(val_string(stringdup("null")))
    }
    else if (id == len_id)
    {
        assert2(, argcount == 1, "Wrong number of arguments to function");
        Value v = frame->stack[frame->stackpos - 1];
        int tag = v.tag;
        frame->stackpos -= 1;
        if      (tag == VALUE_ARRAY)    STACK_PUSH2(val_float(v.u.a->len))
        else if (tag == VALUE_STRING)   STACK_PUSH2(val_float(strlen(*v.u.s)))
        else if (tag == VALUE_DICT)     STACK_PUSH2(val_float(v.u.d->len))
        else panic2(,"Tried to use len() on something with no length");
    }
    else if (id == keys_id)
    {
        assert2(, argcount == 1, "Wrong number of arguments to function");
        Value v = frame->stack[frame->stackpos - 1];
        int tag = v.tag;
        frame->stackpos -= 1;
        if (tag == VALUE_DICT)
        {
            Value v2 = val_array(v.u.d->len);
            size_t j = 0;
            for (size_t i = 0; i < v.u.d->cap && j < v2.u.a->len; i++)
            {
                if (v.u.d->buf[i].l.tag != VALUE_INVALID)
                    v2.u.a->buf[j++] = v.u.d->buf[i].l;
            }
            STACK_PUSH2(v2)
        }
        else panic2(,"Tried to use keys() on a non-dictionary");
    }
    else if (id == array_insert_id)
    {
        assert2(, argcount == 3, "Wrong number of arguments to function");
        Value v = frame->stack[frame->stackpos - 3];
        Value v2 = frame->stack[frame->stackpos - 2];
        Value v3 = frame->stack[frame->stackpos - 1];
        if (v.tag == VALUE_ARRAY)
        {
            assert2(, v2.tag == VALUE_FLOAT, "Array indexes must be numbers");
            size_t index = v2.u.f;
            assert2(, index <= v.u.a->len, "Array index out of range");
            frame->stackpos -= 3;
            if (v.u.a->len + 1 >= v.u.a->cap)
            {
                size_t oldcap = v.u.a->cap;
                v.u.a->cap *= 2;
                if (v.u.a->cap < 4) v.u.a->cap = 4;
                Value * re = (Value *)zalloc(sizeof(Value) * v.u.a->cap);
                memcpy(re, v.u.a->buf, oldcap);
                v.u.a->buf = re;
            }
            for (size_t i = v.u.a->len; i > index; i--)
                v.u.a->buf[i] = v.u.a->buf[i - 1];
            v.u.a->buf[index] = v3;
            v.u.a->len += 1;
            STACK_PUSH2(v2)
        }
        else panic2(,"Tried to use array_insert_id() on a non-dictionary");
    }
    else if (id == array_remove_id)
    {
        assert2(, argcount == 2, "Wrong number of arguments to function");
        Value v = frame->stack[frame->stackpos - 2];
        Value v2 = frame->stack[frame->stackpos - 1];
        if (v.tag == VALUE_ARRAY)
        {
            assert2(, v2.tag == VALUE_FLOAT, "Array indexes must be numbers");
            size_t index = v2.u.f;
            assert2(, index < v.u.a->len, "Array index out of range");
            frame->stackpos -= 2;
            if (v.u.a->len + 1 >= v.u.a->cap)
            {
                v.u.a->cap *= 2;
                Value * re = (Value *)zalloc(sizeof(Value) * v.u.a->cap);
                memcpy(re, v.u.a->buf, v.u.a->cap / 2);
            }
            Value v3 = v.u.a->buf[index];
            for (size_t i = index; i < v.u.a->len - 1; i++)
                v.u.a->buf[i] = v.u.a->buf[i + 1];
            v.u.a->len -= 1;
            STACK_PUSH2(v3)
        }
        else panic2(,"Tried to use array_insert_id() on a non-dictionary");
    }
    else if (id == dict_remove_id)
    {
        assert2(, argcount == 2, "Wrong number of arguments to function");
        Value v = frame->stack[frame->stackpos - 2];
        Value v2 = frame->stack[frame->stackpos - 1];
        if (v.tag == VALUE_DICT)
        {
            frame->stackpos -= 2;
            BiValue * pair = dict_get_or_insert(v.u.d, v2);
            Value ret = pair->r;
            pair->l = val_tagged(VALUE_TOMBSTONE);
            pair->r = val_tagged(VALUE_INVALID);
            if (ret.tag == VALUE_INVALID) ret = val_tagged(VALUE_NULL);
            if (ret.tag == VALUE_INVALID) ret = val_tagged(VALUE_NULL);
            v.u.a->len -= 1;
            STACK_PUSH2(ret)
        }
        else panic2(,"Tried to use array_insert_id() on a non-dictionary");
    }
    else panic2(,"Unknown internal function");
}

void register_intrinsic_funcs(void)
{
    #define REGISTER(X) register_intrinsic_func(#X); X ## _id = lex_ident_offset - insert_or_lookup_id(#X, strlen(#X));
    REGISTER(print)
    REGISTER(typeof)
    REGISTER(len)
    REGISTER(keys)
    REGISTER(array_insert)
    REGISTER(array_remove)
    REGISTER(dict_remove)
}

#endif
