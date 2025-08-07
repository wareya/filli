#ifndef FILLI_INTRINSICS_H_INCLUDED
#define FILLI_INTRINSICS_H_INCLUDED

uint16_t print_id;
uint16_t typeof_id;
void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame)
{
    #define STACK_PUSH2(X) {\
        assert2(,frame->stackpos < FRAME_STACKSIZE);\
        frame->stack[frame->stackpos++] = X; }
    
    if (id == print_id)
    {
        for (size_t i = 0; i < argcount; i++)
        {
            int tag = frame->stack[frame->stackpos - 1 - i].tag;
            if      (tag == VALUE_FLOAT)    prints(baddtostr(frame->stack[frame->stackpos - 1 - i].u.f));
            else if (tag == VALUE_STRING)   prints(frame->stack[frame->stackpos - 1 - i].u.s);
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
        if      (tag == VALUE_FLOAT)    STACK_PUSH2(val_string("float"))
        else if (tag == VALUE_STRING)   STACK_PUSH2(val_string("string"))
        else if (tag == VALUE_ARRAY)    STACK_PUSH2(val_string("array"))
        else if (tag == VALUE_DICT)     STACK_PUSH2(val_string("dict"))
        else if (tag == VALUE_FUNC)     STACK_PUSH2(val_string("funcref"))
        else if (tag == VALUE_STATE)    STACK_PUSH2(val_string("funcstate"))
        else if (tag == VALUE_NULL)     STACK_PUSH2(val_string("null"))
    }
    else panic2(,"Unknown internal function");
}

void register_intrinsic_funcs(void)
{
    register_intrinsic_func("print");
    print_id = lex_ident_offset - insert_or_lookup_id("print", 5);
    register_intrinsic_func("typeof");
    typeof_id = lex_ident_offset - insert_or_lookup_id("typeof", 6);
}

#endif
