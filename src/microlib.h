#ifndef FILLI_MICROLIB_H_INCLUDED
#define FILLI_MICROLIB_H_INCLUDED

// micro stdlib replacement stuff to reduce binary size (yes, this has a big effect)

// #define just_die() abort()
//      literally just die. don't print anything.
// #define die_now(X)
//      die with diagnostic information about the death location (e.g. __LINE__)
// #define assert(X, ...)
//      assert on untruth of X, but print ... instead of X if it's passed
// #define perror(X)
//      as though eprints(X)
// #define panic(...)
//      as though die_now(__VA_OPT__( __VA_ARGS__))

// char * stringdupn(const char * s, size_t len);
//      return a malloc-allocated copy of s, stopping at len, with len+1 bytes of zero-initialized backing memory.
//      null terminated. stop copying at any null byte.
// char * stringdup(const char * s);
//      return a malloc-allocated copy of s
//      null terminated

// void prints(const char * s);
//      dump every character in s to stdout, no implicit trailing newline
// void eprints(const char * s);
//      dump every character in s to stderr, no implicit trailing newline
// void printsn(const char * s, size_t len);
//      stdout print the first <len> characters from s, stopping at any null byte
//      no implicit trailing newline
// void printu16hex(uint16_t x);
//      stdout print the given short as if with "%04X", no trailing newline
// double badstrtod(const char * s);
//      parse the given string as a 64-bit float, silently stopping wherever it stops looking like a float
//      does not need to be accurate
// const char * baddtostr(double f);
//      return a malloc-allocated string containing something similar to sprintf %f
//      does not need to be accurate

#define STRINGIZE2(x) #x
#define STRINGIZE(x) STRINGIZE2(x)
#define LINE_STRING STRINGIZE(__LINE__)

#define just_die() abort()
#define die_now(X) { prints("Assert:\n" #X "\nat " LINE_STRING " in " __FILE__ "\n"); fflush(stdout); just_die(); }
#ifdef assert
    #undef assert
#endif
#define assert(X, ...) { if (!(X)) { if (__VA_OPT__(1)+0) die_now(__VA_ARGS__) else die_now(X) } }
#define perror(X) eprints(X)
#define panic(...) die_now(__VA_OPT__( __VA_ARGS__))

char * stringdupn(const char * s, size_t len)
{
    char * s2 = (char *)malloc(len+1);
    memset(s2, 0, len+1);
    //strncpy(s2, s, len); // throws a buggy/wrong warning in GCC
    size_t i = 0;
    while (*s && i < len) s2[i++] = *(s++);
    return s2;
}
char * stringdup(const char * s) { return stringdupn(s, strlen(s)); }

void prints(const char * s) { fputs(s, stdout); }
void eprints(const char * s) { fputs(s, stderr); }
void printu16hex(uint16_t x)
{
    char c[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    char s[5] = { c[(x>>12)&15], c[(x>>8)&15], c[(x>>4)&15], c[x&15], 0 };
    prints(s);
}
void printsn(const char * s, size_t len) { char * s2 = stringdupn(s, len); prints(s2); free(s2); }

double badstrtod(const char * s)
{
    if ((s[0]&~32) == 'N' && (s[1]&~32) == 'A' && (s[0]&~32) == 'N') return 0.0/0.0;
    
    double sign = 1.0;
    if (*s == '-') { sign = -1.0; s += 1; }
    if (!s[0]) return 0.0 * sign;
    if ((s[0]&~32) == 'I' && (s[1]&~32) == 'N' && (s[0]&~32) == 'F') return sign/0.0;
    
    double ret = 0.0;
    while (*s != 0 && *s != '.' && *s >= '0' && *s <= '9') { ret = ret*10.0 + (*(s++) - '0'); }
    if (*(s++) != '.') return ret * sign;
    double f2 = 0.1;
    while (*s != 0 && *s >= '0' && *s <= '9') { ret += (*(s++) - '0') * f2; f2 *= 0.1; }
    
    return ret * sign;
}

const char * baddtostr(double f)
{
    if (f != f) return "nan";
    if (f != 0.0 && f+f == f) return "inf";
    if (f != 0.0 && f-f == f) return "-inf";
    
    char buf[50] = {};
    size_t i = 0;
    
    uint64_t pun;
    memcpy(&pun, &f, 8);
    if (pun & 0x8000000000000000) { buf[i++] = '-'; pun ^= 0x8000000000000000; }
    memcpy(&f, &pun, 8);
    
    size_t mag = 0; while (f != 0.0 && f < 1000000000.0 / (i ? 10.0 : 1.0)) { f *= 10.0; mag++; }
    
    uint64_t fi2 = f;
    uint8_t d = i;
    while (fi2) { d++; fi2 /= 10; }
    if (d == i) d += 1;
    if (f == 0.0) { mag = 9 - i; d = 10; }
    
    fi2 = f;
    for (size_t j = d; j > i;) { buf[--j] = '0' + (fi2 % 10); fi2 /= 10; }
    for (size_t j = d; j > d - mag; j--) buf[j] = buf[j - 1];
    buf[d-mag] = '.';
    
    return stringdup(buf);
}


#endif
