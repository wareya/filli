#ifndef FILLI_INTRINSICS_H_INCLUDED
#define FILLI_INTRINSICS_H_INCLUDED

uint16_t print_id;
void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame)
{
    if (id == print_id)
    {
        for (size_t i = 0; i < argcount; i++)
        {
            int tag = frame->stack[frame->stackpos - 1 - i].tag;
            if      (tag == VALUE_FLOAT)    prints(baddtostr(frame->stack[frame->stackpos - 1 - i].u.f));
            else if (tag == VALUE_STRING)   prints(frame->stack[frame->stackpos - 1 - i].u.s);
            else if (tag == VALUE_ARRAY)    prints("<array>");
            
            if (i + 1 < argcount) prints(" ");
        }
        prints("\n");
        frame->stack[frame->stackpos++] = val_float(0.0);
    }
    else panic("Unknown internal function");
}

void register_intrinsic_funcs(void)
{
    register_intrinsic_func("print");
    print_id = lex_ident_offset - insert_or_lookup_id("print", 5);
}

#endif
