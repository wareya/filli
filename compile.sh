clang -std=c23 -lgc -Oz src/main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s -fno-math-errno -Xclang -target-feature -Xclang +slow-unaligned-mem-16 -mllvm --inline-threshold=100
