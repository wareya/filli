./a.out $1 > asdfasdf.c \
&& clang -O3 -g -ggdb  -Isrc asdfasdf.c -o b.out -lgc -lm \
	-flto -Xclang -target-feature -Xclang +slow-unaligned-mem-16 \
&& time ./b.out
