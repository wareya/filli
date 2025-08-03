#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

float badstof(const char * s)
{
    double sign = 1.0;
    if (*s == '-') { sign = -1.0; s += 1; }
    
    if (s[0] && s[1] && s[2])
    {
        if (strncmp(s, "inf", 3) == 0) return sign/0.0;
        if (strncmp(s, "Inf", 3) == 0) return sign/0.0;
        if (strncmp(s, "INF", 3) == 0) return sign/0.0;
        if (strncmp(s, "NaN", 3) == 0) return 0.0/0.0;
        if (strncmp(s, "nan", 3) == 0) return 0.0/0.0;
    }
    
    double ret = 0.0;
    while (*s != 0 && *s != '.')
    {
        ret *= 10.0;
        ret += *s - '0';
        s += 1;
    }
    if (*s == '.')
    {
        s += 1;
        double f2 = 0.1;
        while (*s != 0)
        {
            ret += (*s - '0') * f2;
            f2 *= 0.1;
            s += 1;
        }
    }
    return ret * sign;
}

#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define LINE_STRING STRINGIZE(__LINE__)

#define IDENTIFIER_COUNT 32000
typedef struct _IdEntry {
    const char * where;
    uint16_t len;
} IdEntry;

void printc(char c)
{
    printf("%c", c);
}

void printu16hex(uint16_t x)
{
    //const char * chars[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
    char chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    printc(chars[(x >> 12) & 0xF]);
    printc(chars[(x >> 8) & 0xF]);
    printc(chars[(x >> 4) & 0xF]);
    printc(chars[(x >> 0) & 0xF]);
}
void printsn(const char * s, size_t l)
{
    while (l > 0) printc(s[l--]);
    //printf("%.*s", l, s);
}
void prints(const char * s)
{
    //while (*s != 0) printc(*(s++));
    fputs(s, stdout);
}

#define assert(X) if (!(X)) { prints("Assertion failed:\n" #X "\nline " LINE_STRING " in " __FILE__ "\n"); fflush(stdout); abort(); }
#define perror(X) fputs(X, stderr)
#define panic(...) assert((__VA_OPT__((void) __VA_ARGS__,)0))


int16_t highest_ident_id = 0;
int16_t insert_or_lookup_id(const char * text, uint16_t len)
{
    // FIXME make non-static
    static IdEntry ids[IDENTIFIER_COUNT];
    static int init = 0;
    if (!init)
    {
        init = 1;
        memset(&ids[0], 0, sizeof(ids[0]) * IDENTIFIER_COUNT);
    }
    
    for (int16_t j = 1; j <= IDENTIFIER_COUNT; j++)
    {
        if (ids[j].len == 0)
        {
            char * c = malloc(len+1);
            memcpy(c, text, len);
            c[len] = 0;
            
            ids[j].where = c;
            ids[j].len = len;
            
            highest_ident_id = j;
            return -j;
        }
        else if (ids[j].len == len && strncmp(ids[j].where, text, len) == 0)
        {
            return -j;
        }
    }
    panic("Ran out of unique IDs");
}

typedef struct _Token {
    uint32_t i;
    uint16_t len;
    int16_t kind; // negative: identifier. zero: number. one: string. two: punctuation. three: newline (if enabled as token).
} Token;

int token_is(const char * source, Token * tokens, size_t count, size_t i, const char * text)
{
    if (i >= count) return 0;
    size_t len = strlen(text);
    if (tokens[i].len != len) return 0;
    return strncmp(source + tokens[i].i, text, len) == 0;
}

Token mk_token(uint32_t i, uint16_t len, int16_t kind)
{
    Token t;
    t.i = i;
    t.len = len;
    t.kind = kind;
    return t;
}

int lex_ident_offset = 0;

Token * tokenize(const char * source, size_t * count)
{
    int newline_is_token = 1;
    
    // give keywords known ids
    insert_or_lookup_id("if", 2);        // 1
    insert_or_lookup_id("else", 4);      // 2
    insert_or_lookup_id("elif", 4);      // 3
    insert_or_lookup_id("func", 4);      // 4
    insert_or_lookup_id("while", 5);     // 5
    insert_or_lookup_id("for", 3);       // 6
    insert_or_lookup_id("break", 5);     // 7
    insert_or_lookup_id("continue", 8);  // 8
    insert_or_lookup_id("return", 6);    // 9
    insert_or_lookup_id("let", 3);       // 10
    insert_or_lookup_id("begin", 3);     // 11
    insert_or_lookup_id("end", 3);       // 12
    lex_ident_offset = highest_ident_id;
    
    const char * long_punctuation[] = {
        "==", "!=", ">=", "<=", "->",
    };
    
    size_t len = strlen(source);
    
    Token * ret = (Token *)malloc(sizeof(Token) * len);
    size_t t = 0;
    
    for (size_t i = 0; i < len; )
    {
        // skip comments and whitespace
        if (source[i] == '#') { while (source[i] != 0 && source[i] != '\n') { i++; } continue; }
        
        if (source[i] == ' ' || source[i] == '\t' || source[i] == '\r') { i++; continue; }
        
        if (source[i] == '\n')
        {
            if (newline_is_token && t > 0 && token_is(source, ret, t, t-1, "\\"))
                t -= 1;
            else if (newline_is_token)
                ret[t++] = mk_token(i++, 1, 3);
            else
                i++;
            continue;
        }
        
        // tokenize numbers
        if (source[i] >= '0' && source[i] <= '9')
        {
            int dot_ok = 1;
            size_t start_i = i;
            while ((source[i] >= '0' && source[i] <= '9') || (dot_ok && source[i] == '.'))
            {
                if (source[i++] == '.') dot_ok = 0;
            }
            ret[t++] = mk_token(start_i, i-start_i, 0);
            continue;
        }
        // tokenize identifiers and keywords
        if ((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z') || source[i] == '_')
        {
            size_t start_i = i;
            i++;
            while ((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z')
                   || source[i] == '_' || (source[i] >= '0' && source[i] <= '9')
                  )
                i++;
            
            ret[t++] = mk_token(start_i, i-start_i, insert_or_lookup_id(source + start_i, i - start_i));
            continue;
        }
        // tokenize strings
        if (source[i] == '\'' || source[i] == '"')
        {
            size_t start_i = i;
            i += 1;
            while (source[i] != source[start_i] && source[i] != 0)
            {
                if (source[i] == '\\') i += 2;
                else i += 1;
            }
            if (source[i] != 0) i += 1;
            ret[t++] = mk_token(start_i, i-start_i, 1);
            continue;
        }
        // long punctuation
        for (size_t j = 0; j < sizeof(long_punctuation) / sizeof(long_punctuation[0]); j++)
        {
            size_t len = strlen(long_punctuation[j]);
            if (strncmp(long_punctuation[j], source+i, len) == 0)
            {
                ret[t++] = mk_token(i, len, 2);
                i += len;
                goto fullcontinue;
            }
        }
        // normal punctuation
        ret[t++] = mk_token(i++, 1, 2);
        fullcontinue: {}
    }
    
    *count = t;
    
    return ret;
}

enum {
    INST_INVALID,
    // zero-op
    INST_EQ = 0x1000,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV,
    // 2byte-op
    PUSH_NAME = 0x2000,
    // 4byte-op
    INST_IF = 0x3000, // destination
    INST_JMP, // destination
    PUSH_NUM, // f32
    PUSH_STRING, // token index
    // 8byte-op
    INST_FUNCDEF = 0x5000, // 2 id 2 argcount 4 length
};

// FIXME: make non-global
uint16_t program[100000];
uint32_t prog_i = 0;

int tokenop_bindlevel(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return -1;
    
    if (token_is(source, tokens, count, i, "or")) return 1;
    if (token_is(source, tokens, count, i, "and")) return 2;
    if (token_is(source, tokens, count, i, "==")) return 3;
    if (token_is(source, tokens, count, i, "!=")) return 3;
    if (token_is(source, tokens, count, i, ">=")) return 3;
    if (token_is(source, tokens, count, i, "<=")) return 3;
    if (token_is(source, tokens, count, i, ">")) return 3;
    if (token_is(source, tokens, count, i, "<")) return 3;
    if (token_is(source, tokens, count, i, "+")) return 4;
    if (token_is(source, tokens, count, i, "-")) return 4;
    if (token_is(source, tokens, count, i, "*")) return 5;
    if (token_is(source, tokens, count, i, "/")) return 5;
    return -1;
}

// returns number of consumed tokens
size_t compile_value(const char * source, Token * tokens, size_t count, uint32_t i)
{
    if (i >= count) return 0;
    if (tokens[i].kind > 1) return 0;
    
    if (tokens[i].kind < 0)
    {
        program[prog_i++] = PUSH_NAME;
        program[prog_i++] = -tokens[i].kind;
    }
    else if (tokens[i].kind == 1)
    {
        program[prog_i++] = PUSH_STRING;
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        memcpy(program + prog_i - 2, &i, 4);
    }
    else if (tokens[i].kind == 0)
    {
        program[prog_i++] = PUSH_NUM;
        
        char * s = malloc(tokens[i].len + 1);
        memcpy(s, &source[tokens[i].i], tokens[i].len);
        s[tokens[i].len] = 0;
        float f = badstof(s);
        free(s);
        
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        memcpy(program + prog_i - 2, &f, 4);
    }
    
    return 1;
}

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power);
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i);

size_t compile_innerexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    if (token_is(source, tokens, count, i, "(")) // wrapped expr
    {
        size_t ret = compile_expr(source, tokens, count, i+1, 0) + 1;
        if (!token_is(source, tokens, count, i + ret, ")")) panic("Unterminated expression");
        return ret + 1;
    }
    return compile_value(source, tokens, count, i++);
}

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power)
{
    if (i >= count) return 0;
    
    size_t ret = compile_innerexpr(source, tokens, count, i);
    if (ret == 0) return 0;
    i += ret;
    
    while (i < count && right_bind_power < tokenop_bindlevel(source, tokens, count, i))
    {
        size_t r = compile_binexpr(source, tokens, count, i);
        ret += r;
        i += r;
        if (r == 0) break;
    }
    
    return ret;
}
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    
    int binding_power = tokenop_bindlevel(source, tokens, count, i);
    if (binding_power < 0) return 0;
    int r = compile_expr(source, tokens, count, i + 1, binding_power);
    if (r == 0) return 0;
    
    uint16_t inst;
    if (token_is(source, tokens, count, i, "-"))
        inst = INST_SUB;
    else if (token_is(source, tokens, count, i, "+"))
        inst = INST_DIV;
    else if (token_is(source, tokens, count, i, "=="))
        inst = INST_EQ;
    else
        panic("TODO");
    program[prog_i++] = inst;
    return r + 1;
}

size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i);
size_t compile_statement(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    size_t orig_i = i;
    if (tokens[i].kind == -1) // if
    {
        i += compile_expr(source, tokens, count, i+1, 0) + 1;
        assert(token_is(source, tokens, count, i, ":"));
        i++;
        program[prog_i++] = INST_IF;
        size_t jump_at = prog_i;
        program[prog_i++] = 0; // word 1
        program[prog_i++] = 0; // word 2
        
        i += compile_statementlist(source, tokens, count, i);
        assert(i < count);
        if (tokens[i].kind == -2 || tokens[i].kind == -3) // elif
        {
            panic("TODO 1");
        }
        else if (tokens[i].kind == -12) // end
        {
            memcpy(program + jump_at, &prog_i, 4);
            i += 1;
        }
        else panic("Missing end at end of if or if chain");
        
        return i - orig_i;
    }
    else if (tokens[i].kind == -12) // end
    {
        return i - orig_i;
    }
    else
    {
        prints("AT: ");
        printsn(source + tokens[i].i, tokens[i].len);
        prints("\n");
        panic("TODO");
    }
    panic("");
}
size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    size_t r;
    while (1)
    {
        if (i >= count) break;
        if (token_is(source, tokens, count, i, "\n")) { i += 1; continue; }
        size_t r = compile_statement(source, tokens, count, i);
        if (r == 0) break;
        i += r;
    }
    return i - orig_i;
}
size_t compile_func(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    if (tokens[i].kind >= -12) return 0;
    int16_t id = -tokens[i].kind;
    i += 1; // name
    if (!token_is(source, tokens, count, i, "(")) return 0;
    i += 1; // (
    int16_t args[256]; // at most 256 args per function
    uint32_t j = 0;
    while (1)
    {
        if (token_is(source, tokens, count, i, ")")) break;
        
        if (tokens[i].kind >= -12) return 0;
        assert(j < 256);
        args[j++] = -tokens[i].kind;
        i += 1;
        if (!(token_is(source, tokens, count, i, ")")
              || token_is(source, tokens, count, i, ","))) return 0;
        if (token_is(source, tokens, count, i, ",")) i++;
    }
    i += 1; // )
    if (!token_is(source, tokens, count, i, ":")) return 0;
    i += 1; // :
    
    program[prog_i++] = INST_FUNCDEF;
    program[prog_i++] = id;
    program[prog_i++] = j;
    size_t len_offs = prog_i;
    program[prog_i++] = 0; // part 1 of length
    program[prog_i++] = 0; // part 2 of length
    
    i += compile_statementlist(source, tokens, count, i);
    
    uint32_t len = prog_i - len_offs - 2;
    memcpy(program + prog_i, &len, 4);
    
    return i - orig_i;
}
size_t compile(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    while (i < count)
    {
        if (tokens[i].kind == -4) // func
        {
            size_t r = compile_func(source, tokens, count, i+1);
            if (r == 0)
                panic("function incomplete");
            i += r + 1;
            
            if (tokens[i].kind != -12) // end
                panic("Functions must end with the end keyword");
            i += 1;
        }
        else if (token_is(source, tokens, count, i, "\n"))
        {
            i += 1;
        }
        else
        {
            prints("AT: ");
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic("unexpected end of script: all root-level items must be function definitions");
            break;
        }
    }
    return i - orig_i;
}

struct _Value;
typedef struct _Array {
    struct _Value * first;
    size_t len;
} Array;
typedef struct _Value {
    union { float f; Array * a; } u;
    uint8_t tag;
} Value;
typedef struct _Frame {
    Value * stack;
    Value * vars;
    struct _Frame * return_to;
    size_t pc;
} Frame;

void interpret(void)
{
    Frame * frame = (Frame *)malloc(sizeof(Frame));
    if (!frame) return;
    memset(frame, 0, sizeof(Frame));
    while (1)
    {
        switch (program[frame->pc])
        {
        case INST_FUNCDEF: {
            
        }
        default:
            panic("unknown operation");
        }
    }
}

int main(int argc, char ** argv)
{
    if (argc < 2) { puts("Usage: filli filename.fil"); return 0; }
    char * source = 0;
    size_t total_size = 0;
    #define CHUNK_SIZE 4096
    size_t capacity = CHUNK_SIZE;
    source = (char*)malloc(capacity);
    if (!source) { perror("Out of memory"); return 1; }
    
    FILE * file = fopen(argv[1], "rb");
    if (!file) { perror("Error opening file"); return 1; }
    
    size_t bytes_read = 0;
    while ((bytes_read = fread(source + total_size, 1, capacity - total_size - 1, file)) > 0)
    {
        total_size += bytes_read;
        if (total_size >= capacity - 1)
        {
            capacity += CHUNK_SIZE;
            char * new_buffer = (char*)realloc(source, capacity);
            if (!new_buffer) { perror("Out of memory"); return 1; }
            source = new_buffer;
        }
    }
    if (ferror(file)) { perror("Error reading file"); return 1; }
    fclose(file);
    
    source[total_size] = 0;
    
    size_t count = 0;
    Token * tokens = tokenize(source, &count);
    for (size_t i = 0; i < count; i++)
    {
        prints("[");
        printsn(source + tokens[i].i, tokens[i].len);
        prints("]\n");
    }
    
    compile(source, tokens, count, 0);
    
    for (size_t i = 0; i < prog_i; i++)
    {
        //printf("%02X %02X\n", program[i] & 0xFF, program[i] >> 8);
        //printf("%04X\n", program[i]);
        printu16hex(program[i]);
        //fwrite(
        prints("\n");
    }
    
    // subnormals: 0x00800000
    // infs and nans: 0x7F800000
    //for (uint64_t i = (1ULL << 30); i < 00800000; i++)
    //for (uint64_t i = 0; i < 0x80000000; i++)
    //for (uint64_t i = 0; i < 0x80000000; i++)
    for (uint64_t i = 0; i < 0x80000000; i++)
    {
        if (!(i & 0xFFFFF)) printf("Progress: %f%%\n", (i)/(double)0x80000000*100.0);
        uint32_t i32 = i;
        float f;
        memcpy(&f, &i32, 4);
        char s[100];
        sprintf(s, "%.45f", f);
        
        float a = (float)badstof(s);
        float b = f;
        //float b = atof(s);
        if (a != b)
        {
            if ((a != a) != (b != b))
                printf("%s: %.45f\t%.45f\n", s, a, b);
        }
    }
    return 0;
}
