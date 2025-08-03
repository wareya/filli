musl-clang -Os main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s ../bdwgc/out/libgc.a -static
