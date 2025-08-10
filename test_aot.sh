./a.out tests/toosimple.fil > asdfasdf.c && clang -O3 -g -ggdb -Isrc asdfasdf.c -o b.out -lgc -mtune=athlon64 -flto && time ./b.out
