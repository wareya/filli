#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <locale.h>

#define IDENTIFIER_COUNT 32000

typedef struct _IdEntry {
    const char * where;
    uint16_t len;
} IdEntry;

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
            ids[j].where = text;
            ids[j].len = len;
            return -j;
        }
        else if (ids[j].len == len && strncmp(ids[j].where, text, len) == 0)
        {
            return -j;
        }
    }
    assert(0);
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

Token mk_token(uint32_t i, uint16_t len, int16_t kind) { Token t; t.i = i; t.len = len; t.kind = kind; return t; }

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
    
    const char * long_punctuation[] = {
        "==", "!=", ">=", "<=",
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

typedef struct _Inst {
    uint16_t op;
    uint16_t args[2];
} Inst;

enum {
    INST_INVALID,
    INST_IF, INST_JMP,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV,
    INST_EQ,
    PUSH_NUM, PUSH_STRING, PUSH_NAME,
};

Inst basic_inst(int n) { Inst ret; ret.op = n; ret.args[0] = 0; ret.args[1] = 0; return ret; }

// FIXME: make non-global
Inst program[100000];
size_t prog_i = 0;

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
    
    Inst n;
    if (tokens[i].kind < 0) { n.op = PUSH_NAME; n.args[0] = -tokens[i].kind; }
    if (tokens[i].kind == 1) { n.op = PUSH_STRING; memcpy(&n.args[0], &i, 4); }
    if (tokens[i].kind == 0)
    {
        n.op = PUSH_NUM;
        char * s = malloc(tokens[i].len + 1);
        memcpy(s, &source[tokens[i].i], tokens[i].len);
        s[tokens[i].len] = 0;
        float f = atof(s);
        memcpy(&n.args[0], &f, 4);
        free(s);
    }
    program[prog_i++] = n;
    
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
        if (!token_is(source, tokens, count, i + ret, ")")) assert(((void)"Unterminated expression", 0));
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
    
    Inst inst = basic_inst(0);
    if (token_is(source, tokens, count, i, "-"))
        inst.op = INST_SUB;
    else if (token_is(source, tokens, count, i, "+"))
        inst.op = INST_DIV;
    else if (token_is(source, tokens, count, i, "=="))
        inst.op = INST_EQ;
    else
        assert(((void)"TODO", 0));
    program[prog_i++] = inst;
    return r + 1;
}

size_t compile_ifblock(const char * source, Token * tokens, size_t count, size_t i)
{
    assert(((void)"TODO ifblock", 0));
}

size_t compile_statement(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    size_t orig_i = i;
    if (tokens[i].kind == -1) // if
    {
        i += compile_expr(source, tokens, count, i+1, 0) + 1;
        assert(i < count && tokens[i].kind == -11); // begin
        i++;
        size_t jump_at = prog_i;
        program[prog_i++] = basic_inst(INST_IF);
        compile_ifblock(source, tokens, count, i);
        assert(i < count);
        if (tokens[i].kind == -2 || tokens[i].kind == -3) // elif
        {
            
        }
        else if (tokens[i].kind == -12) // end
        {
            
        }
        else assert(((void)"Missing end at end of if or if chain", 0));
    }
}
size_t compile_func(const char * source, Token * tokens, size_t count, size_t i)
{
    puts("asdfjawe");
    if (i >= count) return 0;
    puts("kgear");
    if (tokens[i].kind >= -12) return 0;
    puts("egkjw35u");
}
size_t compile(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    while (i < count)
    {
        if (tokens[i].kind == -4) // func
        {
            i += compile_func(source, tokens, count, i+1) + 1;
        }
        else if (token_is(source, tokens, count, i, "\n"))
        {
            i += 1;
        }
        else
        {
            perror("unexpected end of script: all root-level items must be function definitions");
            break;
        }
    }
    return i - orig_i;
}

int main(int argc, char ** argv)
{
    if (setlocale(LC_ALL, "C") == NULL) { perror("Failed to set locale to 'C'"); return 1; }
    
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
        printf("[%.*s]\n", tokens[i].len, source + tokens[i].i);
    }
    
    compile(source, tokens, count, 0);
    
    for (size_t i = 0; i < prog_i; i++)
    {
        printf("%04X %04X %04X\n", program[i].op, program[i].args[0], program[i].args[1]);
    }
    
    return 0;
}
