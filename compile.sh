clang -lgc -Oz src/main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s -mllvm --inline-threshold=100
