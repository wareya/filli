#ifndef MICROARENA_INCLUDED
#define MICROARENA_INCLUDED

#include <stddef.h>
#include <stdint.h>

// Chain allocator with bulk chain segment freeing; baby's worst GC.
// NOT THREAD-SAFE!!!!!

void ** ma_chain = 0;
void * ma_malloc(size_t size)
{
    void * ret = malloc(size);
    void ** chain = malloc(sizeof(void*) * 2);
    chain[0] = (void *)ma_chain;
    chain[1] = ret;
    ma_chain = chain;
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
