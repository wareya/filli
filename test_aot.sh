./a.out tests/toosimple.fil > asdfasdf.c \
&& clang -O3 -g -ggdb  -Isrc asdfasdf.c -o b.out -lgc \
	-flto -Xclang -target-feature -Xclang +slow-unaligned-mem-16 \
&& time ./b.out
