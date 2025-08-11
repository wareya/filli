./a.out $1 > asdfasdf.c \
&& clang -O3 -g -ggdb  -Isrc asdfasdf.c -o b.out -lgc -fno-math-errno \
	-flto -Xclang -target-feature -Xclang +slow-unaligned-mem-16 \
&& time ./b.out
