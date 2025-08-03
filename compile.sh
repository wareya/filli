clang -lgc -Os main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s
