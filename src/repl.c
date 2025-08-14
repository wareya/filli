#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifndef NO_GC
#define USE_GC
#endif

#ifdef USE_GC
#include <gc.h>
#define malloc(X) GC_MALLOC(X)
#define calloc(X, Y) GC_MALLOC(X*Y)
#define realloc(X, Y) GC_REALLOC(X, Y)
#define free(X) GC_FREE(X)
#else
#define MICROARENA
#include "microarena.h"
#define malloc(X) ma_malloc(X)
#define realloc(X, Y) ma_realloc(X, Y)
#define free(X)
#endif

#include "filli.h"

#define MAX_INPUT_LEN 200000
char input[MAX_INPUT_LEN];

int main(void)
{
#ifdef USE_GC
    GC_INIT();
#endif
    init_program();
    lex_init();
    compiler_state_init();
    register_intrinsic_funcs();
    
    char * cursor = input;
    size_t pc = 0;
    while (1)
    {
        if (cursor != input)
            fputs("... ", stdout);
        else
            fputs("  > ", stdout);
        
        char * s = fgets(cursor, MAX_INPUT_LEN, stdin);
        if (s == 0) { return 0; }
        
        if (strcmp(cursor, "exit\n") == 0) { return 0; }
        if (strcmp(cursor, "quit\n") == 0) { return 0; }
        
        size_t count = 0;
        
        if (cursor[0] == '\n' || cursor[0] == '\0')
        {
            cursor = input;
            
            Program old_prog = prog;
            CompilerState old_cs = *cs;
            
            Token * tokens = tokenize(input, &count);
            compile(input, tokens, count, 0);
            
            if (filli_err)
            {
                fputs("Compiler produced error:\n", stdout);
                fputs(filli_err, stdout);
                fputs("\n", stdout);
                filli_err = 0;
                prog = old_prog;
                *cs = old_cs;
                continue;
            }
            
            pc += interpret(pc);
            
            if (filli_err)
            {
                fputs("Interpreter produced error:\n", stdout);
                fputs(filli_err, stdout);
                fputs("\n", stdout);
                filli_err = 0;
                prog = old_prog;
            }
        }
        else
            cursor += strlen(cursor);
    }
    
    #ifdef MICROARENA
    ma_free_checkpoint(0);
    #endif
    
    return 0;
}
