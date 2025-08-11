clang -std=c23 -lgc -lm -Oz src/main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s -mllvm --inline-threshold=100 $1
