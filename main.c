#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// TODO: "continue" and "break"

#define USE_GC

#ifdef USE_GC
#include <gc.h>
#define malloc(X) GC_MALLOC(X)
#define calloc(X, Y) GC_MALLOC(X*Y)
#define realloc(X, Y) GC_REALLOC(X, Y)
#define free(X) GC_FREE(X)
#endif

#include "filli.h"

int main(int argc, char ** argv)
{
#ifdef USE_GC
    GC_INIT();
#endif
    init_program();
    lex_init();
    register_intrinsic_funcs();
    
    if (argc < 2) { prints("Usage: filli filename.fil\n"); return 0; }
    char * source = 0;
    size_t total_size = 0;
    
    source = (char*)malloc(4096);
    if (!source) { perror("Out of memory"); return 1; }
    
    FILE * file;
    if (strcmp(argv[1], "-") == 0) file = stdin;
    else file = fopen(argv[1], "rb");
    
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
    
    for (size_t i = 0; i < prog_i; i++)
    {
        printu16hex(program[i]);
        prints("\n");
    }
    
    interpret();
    
    return 0;
}
