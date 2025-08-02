musl-clang -Os main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -nostdlib ../musl/lib/libc.a ../bdwgc/out/libgc.a ../musl/lib/crt1.o && strip a.out
