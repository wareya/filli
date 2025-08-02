musl-clang -Wl,-Bdynamic /usr/lib/libgc.so -Wl,-Bstatic -Os main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra && strip a.out
