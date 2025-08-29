clang -fno-math-errno -std=c23 -lgc -Os src/main.c -flto -Wl,--gc-sections -fuse-ld=lld -Wall -Wextra -s -Xclang -target-feature -Xclang +slow-unaligned-mem-16 $@
