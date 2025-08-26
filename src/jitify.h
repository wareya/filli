#ifndef JITIFY_H
#define JITIFY_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#include <windows.h>

static void * VirtualAllocNearProcess(size_t * len)
{
    size_t check_size = 1 << 16;
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
    size_t start_at = (size_t)(void *)VirtualAllocNearProcess;
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
    start_at = (start_at >> 16) << 16;
    size_t start_at_2 = start_at;
    *len = ((*len + (1 << 16) - 1) >> 16) << 16;
    void * buffer = VirtualAlloc((void *)start_at, *len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    while (!buffer && (start_at - start_at_2) < (1ll<<31ll))
    {
        start_at += check_size;
        start_at_2 -= check_size;
        buffer = VirtualAlloc((void *)start_at, *len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (buffer)
            return buffer;
        buffer = VirtualAlloc((void *)start_at_2, *len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (buffer)
            return buffer;
    }
    if (!buffer)
    {
        printf("ERROR: failed to allocate buffer (tried up to 0x%zX distance)\n", (uint64_t)(start_at - start_at_2)/2);
        assert(0);
    }
    return buffer;
}

/// returns read-write memory near the process address space
/// actual size allocated is written into len, which must not be null
static uint8_t * alloc_near_executable(size_t * len)
{
    if (*len == 0)
        *len = 1;
    //printf("allocating %zu length\n", *len);
    // we want an allocation that's near our own process memory
    // so that we can do 32-bit relocations when calling non-JIT functions
    void * const buffer = VirtualAllocNearProcess(len);
    assert(buffer);
    ptrdiff_t diff = ((ptrdiff_t)buffer) - ((ptrdiff_t)VirtualAllocNearProcess);
    assert(diff > -(1ll<<30ll) && diff < (1ll<<30ll));
    
    return (uint8_t *)buffer;
}

/// marks an allocation previously returned by `alloc_near_executable` as being executable
/// MUST SPECIFICALLY be an allocation returned by alloc_near_executable
static void mark_as_executable(uint8_t * mem, size_t len)
{
    DWORD dummy;
    assert(VirtualProtect(mem, len, PAGE_EXECUTE_READ, &dummy));
}

static void free_near_executable(uint8_t * mem, size_t len)
{
    (void)len; // unused
    VirtualFree(mem, 0, MEM_RELEASE);
}

#else // of #ifdef _WIN32

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

static void * mmap_near_process(size_t * len)
{
    size_t check_size = 1 << 16;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    size_t start_at = (size_t)(void *)mmap_near_process;
#pragma GCC diagnostic pop
    start_at = (start_at >> 16) << 16;
    size_t orig_start_at = start_at;
    size_t start_at_2 = start_at;
    *len = ((*len + (1 << 16) - 1) >> 16) << 16;
    void * buffer = mmap((void *)start_at, *len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE , -1, 0);
    while (buffer == MAP_FAILED && (start_at - start_at_2) < (1ll<<31ll))
    {
        start_at += check_size;
        start_at_2 -= check_size;
        buffer = mmap((void *)start_at, *len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE , -1, 0);
        if (buffer != MAP_FAILED)
            return buffer;
        buffer = mmap((void *)start_at_2, *len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE , -1, 0);
        if (buffer != MAP_FAILED)
            return buffer;
    }
    if (buffer == MAP_FAILED)
    {
        printf("ERROR: failed to allocate buffer (tried up to 0x%zX distance) (started at 0x%zX)\n", (uint64_t)(start_at - start_at_2)/2, orig_start_at);
        printf("errno: %d\n", errno);
        printf("EEXIST: %d\n", EEXIST);
        printf("EINVAL: %d\n", EINVAL);
        printf("ENOMEM: %d\n", ENOMEM);
        printf("EPERM: %d\n", EPERM);
        printf("EAGAIN: %d\n", EAGAIN);
        printf("EACCES: %d\n", EACCES);
        assert(0);
    }
    return buffer;
}
/// returns read-write memory near the process address space
/// actual size allocated is written into len, which must not be null
static uint8_t * alloc_near_executable(size_t * len)
{
    if (*len == 0)
        *len = 1;
    printf("allocating %zu length\n", *len);
    // we want an allocation that's near our own process memory
    // so that we can do 32-bit relocations when calling non-JIT functions
    void * const buffer = mmap_near_process(len);
    assert(buffer);
    printf("%p\n", buffer);
    ptrdiff_t diff = ((ptrdiff_t)buffer) - ((ptrdiff_t)mmap_near_process);
    assert(diff > -(1ll<<30ll) && diff < (1ll<<30ll));
    
    return (uint8_t *)buffer;
}

/// marks an allocation previously returned by `alloc_near_executable` as being executable
/// MUST SPECIFICALLY be an allocation returned by alloc_near_executable
static void mark_as_executable(uint8_t * mem, size_t len)
{
    mprotect(mem, len, PROT_READ | PROT_EXEC);
}
static void free_near_executable(uint8_t * mem, size_t len)
{
    munmap(mem, len);
}

#endif // if-else over _WIN32

#endif // JITIFY_H