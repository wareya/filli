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

int main(int argc, char ** argv)
{
#ifdef USE_GC
    GC_INIT();
#endif
    Program prog;
    global_prog = &prog;
    init_program(global_prog);
    lex_init();
    compiler_state_init();
    register_intrinsic_funcs();
    
    if (argc < 2) { prints("Usage: filli filename.fil\n"); return 0; }
    size_t total_size = 0;
    
    char * source = (char*)malloc(4096);
    if (!source) { perror("Out of memory"); return 1; }
    
    FILE * file = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "rb");
    
    if (!file) { perror("Error reading file"); return 1; }
    
    size_t bytes_read = 0;
    while ((bytes_read = fread(source + total_size, 1, 4096, file)) == 4096)
    {
        total_size += bytes_read;
        source = (char*)realloc(source, total_size + 4096);
        if (!source) { perror("Out of memory"); return 1; }
    }
    total_size += bytes_read;
    
    if (ferror(file)) { perror("Error reading file"); return 1; }
    fclose(file);
    source[total_size] = 0;
    
    size_t count = 0;
    Token * tokens = tokenize(source, &count);
    compile(source, tokens, count, 0);
    
    if (filli_err)
    {
        fputs("Compiler produced error:\n", stdout);
        fputs(filli_err, stdout);
        fputs("\n", stdout);
        return 0;
    }

    filli_aot();
    
    #ifdef MICROARENA
    ma_free_checkpoint(0);
    #endif
    
    return 0;
}
