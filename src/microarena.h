#ifndef MICROARENA_INCLUDED
#define MICROARENA_INCLUDED

#include <stddef.h>
#include <stdint.h>

// Chain allocator with bulk chain segment freeing; baby's worst GC.
// NOT THREAD-SAFE!!!!!

void ** ma_chain = 0;
void * ma_malloc(size_t size)
{
    void * ret = malloc(size + 8);
    size_t * n = ret;
    *n = size;
    void ** chain = malloc(sizeof(void*) * 2);
    chain[0] = (void *)ma_chain;
    chain[1] = ret;
    ma_chain = chain;
    return ((char *)ret) + 8;
}
void * ma_realloc(void * orig, size_t size)
{
    size_t * n = (size_t *)(((char *)orig) - 8);
    void * ret = ma_malloc(size);
    size = size > *n ? *n : size;
    memcpy(ret, orig, size);
    return ret;
}
void ma_free(void * p) { (void)p; }

void ** ma_checkpoint(void) { return ma_chain; }
void ma_free_checkpoint(void ** chain)
{
    while (ma_chain && ma_chain != chain)
    {
        void ** ma_chain_2 = ma_chain;
        ma_chain = ma_chain_2[0];
        free(ma_chain_2[1]);
        free(ma_chain_2);
    }
}

#endif
