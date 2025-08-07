// NOTE/WARNING: this REPL crashes on syntax errors. only meant as a demo!

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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
        
        if (strcmp(cursor, "exit") == 0) { return 0; }
        if (strcmp(cursor, "quit") == 0) { return 0; }
        
        size_t count = 0;
        
        if (cursor[0] == '\n' || cursor[0] == '\0')
        {
            cursor = input;
            Token * tokens = tokenize(input, &count);
            compile(input, tokens, count, 0);
            pc += interpret(pc);
        }
        else
            cursor += strlen(cursor);
    }
    
    return 0;
}
