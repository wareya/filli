#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define USE_GC

#ifdef USE_GC
#include <gc.h>
#define malloc(X) GC_MALLOC(X)
#define calloc(X, Y) GC_MALLOC(X*Y)
#define realloc(X, Y) GC_REALLOC(X, Y)
#define free(X) GC_FREE(X)
#endif

#define IDENTIFIER_COUNT 32000
#define FRAME_VARCOUNT 1024
#define FRAME_STACKSIZE 1024
#define PROGRAM_MAXLEN 100000
#define FORLOOP_COUNT_LIMIT 255

// micro stdlib replacement stuff to reduce binary size (yes, this has a big effect)

#define STRINGIZE2(x) #x
#define STRINGIZE(x) STRINGIZE2(x)
#define LINE_STRING STRINGIZE(__LINE__)

#define just_die() abort()
#define die_now(X) { prints("Assert:\n" #X "\non " LINE_STRING " in " __FILE__ "\n"); fflush(stdout); just_die(); }
#define assert(X, ...) { if (!(X)) { if (__VA_OPT__(1)+0) die_now(__VA_ARGS__) else die_now(X) } }
#define perror(X) eprints(X)
#define panic(...) die_now(__VA_OPT__( __VA_ARGS__))

char * stringdupn(const char * s, size_t len)
{
    char * s2 = (char *)malloc(len+1);
    s2[len] = 0;
    memcpy(s2, s, len);
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
void printsn(const char * s, size_t len) { prints(stringdupn(s, len)); }

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

// actual program

typedef struct _IdEntry {
    const char * where;
    uint16_t len;
} IdEntry;

int16_t highest_ident_id = 0;
int16_t insert_or_lookup_id(const char * text, uint16_t len)
{
    // FIXME make non-static
    static IdEntry ids[IDENTIFIER_COUNT] = {};
    for (int16_t j = 1; j <= IDENTIFIER_COUNT; j++)
    {
        if (ids[j].len == 0)
        {
            ids[j].where = stringdupn(text, len);
            ids[j].len = len;
            highest_ident_id = j;
            return -j;
        }
        else if (ids[j].len == len && strncmp(ids[j].where, text, len) == 0)
            return -j;
    }
    panic("Out of IDs");
}

typedef struct _Token {
    uint32_t i;
    uint16_t len;
    int16_t kind; // negative: identifier. zero: number. one: string. two: punctuation. three: newline (if enabled).
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
    Token t = {i, len, kind};
    return t;
}

int lex_ident_offset = 0;

void lex_init(void)
{
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
    insert_or_lookup_id("null", 4);      // 13
    lex_ident_offset = highest_ident_id;
}
#define MIN_KEYWORD -13

Token * tokenize(const char * source, size_t * count)
{
    int newline_is_token = 1;
    
    const char * long_punctuation[] = {
        "==", "!=", ">=", "<=", "->",
        "+=", "-=", "*=", "/="
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
        if ((source[i] >= '0' && source[i] <= '9')
            || (source[i] == '-' && source[i+1] >= '0' && source[i+1] <= '9'))
        {
            int dot_ok = 1;
            size_t start_i = i;
            if (source[i] == '-') i += 1;
            while ((source[i] >= '0' && source[i] <= '9') || (dot_ok && source[i] == '.'))
                dot_ok &= !(source[i++] == '.');
            ret[t++] = mk_token(start_i, i-start_i, 0);
            continue;
        }
        // tokenize identifiers and keywords
        if ((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z') || source[i] == '_')
        {
            size_t start_i = i;
            i++;
            while ((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z')
                   || source[i] == '_' || (source[i] >= '0' && source[i] <= '9'))
                i++;
            
            ret[t++] = mk_token(start_i, i-start_i, insert_or_lookup_id(source + start_i, i - start_i));
            continue;
        }
        // tokenize strings
        if (source[i] == '\'' || source[i] == '"')
        {
            size_t start_i = i++;
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
    INST_DISCARD = 0x100,
    INST_RETURN_VAL, INST_RETURN_VOID,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV,
    INST_CMP_EQ, INST_CMP_NE, INST_CMP_GT, INST_CMP_LT, INST_CMP_GE, INST_CMP_LE,
    INST_INDEX,
    // 1-op
    PUSH_FUNCNAME = 0x210,
    PUSH_STRING, // table index
    PUSH_LOCAL, PUSH_GLOBAL,
    INST_ASSIGN, INST_ASSIGN_GLOBAL,
    INST_ASSIGN_ADD, INST_ASSIGN_GLOBAL_ADD,
    INST_ASSIGN_SUB, INST_ASSIGN_GLOBAL_SUB,
    INST_ASSIGN_MUL, INST_ASSIGN_GLOBAL_MUL,
    INST_ASSIGN_DIV, INST_ASSIGN_GLOBAL_DIV,
    INST_FUNCCALL_EXPR, // arg count
    INST_ARRAY_LITERAL, // item count
    // 2-op
    INST_JMP = 0x320, // destination
    INST_JMP_IF_FALSE, // destination
    INST_JMP_IF_TRUE, // destination
    INST_FUNCDEF, // skip destination
    INST_FUNCCALL, // func id, arg count
    // 4-op
    INST_FOREND = 0x530, // var id (2), for slot (2), destination (4)
    INST_FORSTART, // var id (2), for slot (2), end of loop (4) (needed if loop val is 0)
    PUSH_NUM, // f64
};

// FIXME: make non-global
uint16_t program[PROGRAM_MAXLEN];
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
    if (token_is(source, tokens, count, i, "[")) return 500;
    if (token_is(source, tokens, count, i, "(")) return 500;
    return -1;
}

typedef struct _Funcdef {
    uint8_t exists;
    uint8_t intrinsic;
    uint8_t argcount;
    uint8_t id;
    uint32_t loc;
    uint16_t * args;
} Funcdef;

const char * compiled_strings[1<<16] = {};
uint16_t compiled_string_i = 0;

uint8_t in_global = 1;
Funcdef funcs_registered[IDENTIFIER_COUNT] = {};
uint8_t locals_registered[IDENTIFIER_COUNT] = {};
uint8_t globals_registered[IDENTIFIER_COUNT] = {};

uint8_t for_loop_index = 0;

// returns number of consumed tokens
size_t compile_value(const char * source, Token * tokens, size_t count, uint32_t i)
{
    if (i >= count) return 0;
    if (tokens[i].kind > 1) return 0;
    if (tokens[i].kind < 0 && tokens[i].kind >= MIN_KEYWORD) return 0;
    
    if (tokens[i].kind < 0)
    {
        if (!in_global && locals_registered[lex_ident_offset-tokens[i].kind])
            program[prog_i++] = PUSH_LOCAL;
        else if (globals_registered[lex_ident_offset-tokens[i].kind])
            program[prog_i++] = PUSH_GLOBAL;
        else if (funcs_registered[lex_ident_offset-tokens[i].kind].exists)
            program[prog_i++] = PUSH_FUNCNAME;
        else
        {
            prints(stringdupn(source + tokens[i].i, tokens[i].len));
            prints("\n");
            panic("Unknown identifier");
        }
        program[prog_i++] = lex_ident_offset - tokens[i].kind;
    }
    else if (tokens[i].kind == 1)
    {
        program[prog_i++] = PUSH_STRING;
        size_t l = tokens[i].len - 2;
        const char * sold = source + tokens[i].i + 1;
        char * s = stringdupn(sold, l);
        size_t j = 0;
        for (size_t i = 0; i < l; i++)
        {
            if      (sold[i] == '\\' && sold[i+1] ==  '"' && ++i) s[j++] = '"';
            else if (sold[i] == '\\' && sold[i+1] == '\\' && ++i) s[j++] = '\\';
            else if (sold[i] == '\\' && sold[i+1] ==  'r' && ++i) s[j++] = '\r';
            else if (sold[i] == '\\' && sold[i+1] ==  'n' && ++i) s[j++] = '\n';
            else if (sold[i] == '\\' && sold[i+1] ==  't' && ++i) s[j++] = '\t';
            else s[j++] = sold[i];
        }
        s[j] = 0;
        compiled_strings[compiled_string_i] = s;
        program[prog_i++] = compiled_string_i++;
    }
    else if (tokens[i].kind == 0)
    {
        program[prog_i++] = PUSH_NUM;
        
        char * s = stringdupn(source + tokens[i].i, tokens[i].len);
        double f = badstrtod(s);
        free(s);
        
        memcpy(program + prog_i, &f, 8);
        prog_i += 4;
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
        if (!token_is(source, tokens, count, i + ret, ")")) panic("Unclosed parens");
        return ret + 1;
    }
    if (token_is(source, tokens, count, i, "[")) // array literal
    {
        size_t orig_i = i++; // skip [
        
        uint16_t j = 0;
        while (!token_is(source, tokens, count, i, "]"))
        {
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            assert(j++ < 32000, "Too many values in array literal (limit is 32000)");
            i += r;
            
            if (!(token_is(source, tokens, count, i, "]") || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, "]")) return 0;
        
        program[prog_i++] = INST_ARRAY_LITERAL;
        program[prog_i++] = j;
        return i - orig_i;
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
    
    // func calls
    if (token_is(source, tokens, count, i, "("))
    {
        size_t orig_i = i++; // (
        uint16_t j = 0;
        while (!token_is(source, tokens, count, i, ")"))
        {
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            assert(j++ < 256, "Too many arguments to function (limit is 256)");
            i += r;
            
            if (!(token_is(source, tokens, count, i, ")")
                || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, ")")) return 0;
        
        program[prog_i++] = INST_FUNCCALL_EXPR;
        program[prog_i++] = j;
        return i - orig_i;
    }
    
    int r = compile_expr(source, tokens, count, i + 1, binding_power < 500 ? binding_power : 0);
    if (r == 0) return 0;
    
    uint16_t inst;
    if (token_is(source, tokens, count, i, "-")) inst = INST_SUB;
    else if (token_is(source, tokens, count, i, "/")) inst = INST_DIV;
    else if (token_is(source, tokens, count, i, "+")) inst = INST_ADD;
    else if (token_is(source, tokens, count, i, "*")) inst = INST_MUL;
    else if (token_is(source, tokens, count, i, "==")) inst = INST_CMP_EQ;
    else if (token_is(source, tokens, count, i, "!=")) inst = INST_CMP_NE;
    else if (token_is(source, tokens, count, i, ">=")) inst = INST_CMP_GE;
    else if (token_is(source, tokens, count, i, "<=")) inst = INST_CMP_LE;
    else if (token_is(source, tokens, count, i, ">")) inst = INST_CMP_GT;
    else if (token_is(source, tokens, count, i, "<")) inst = INST_CMP_LT;
    else if (token_is(source, tokens, count, i, "["))
    {
        inst = INST_INDEX;
        i += ++r;
        assert(token_is(source, tokens, count, i++, "]"));
    }
    else panic("TODO");
    program[prog_i++] = inst;
    return r + 1;
}


void inst_push3(uint16_t a, uint16_t b, uint16_t c)
    { program[prog_i++] = a; program[prog_i++] = b; program[prog_i++] = c; }

size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i);

size_t loop_nesting = 0;
uint32_t locs_cont[1024] = {};
size_t locs_cont_i = 0;
uint32_t locs_break[1024] = {};
size_t locs_break_i = 0;

size_t compile_statement(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    size_t orig_i = i;
    if (tokens[i].kind == -1) // if
    {
        i += compile_expr(source, tokens, count, i + 1, 0) + 1;
        assert(token_is(source, tokens, count, i++, ":"));
        program[prog_i++] = INST_JMP_IF_FALSE;
        size_t jump_at = prog_i;
        prog_i += 2;
        
        i += compile_statementlist(source, tokens, count, i);
        
        uint32_t end;
        if (tokens[i].kind == -3 || tokens[i].kind == -2)
            end = prog_i + 3;
        else
            end = prog_i;
        memcpy(program + jump_at, &end, 4);
        
        uint32_t skips[256] = {};
        size_t skip_i = 0;
        
        while (tokens[i].kind == -3 || tokens[i].kind == -2) // elif, else
        {
            // add on to previous block: skip this and the rest of the blocks
            program[prog_i++] = INST_JMP;
            skips[skip_i++] = prog_i;
            prog_i += 2;
            
            if (tokens[i].kind == -3)
            {
                i += compile_expr(source, tokens, count, i + 1, 0) + 1;
                assert(token_is(source, tokens, count, i++, ":"));
                program[prog_i++] = INST_JMP_IF_FALSE;
                size_t jump_at = prog_i;
                prog_i += 2;
                
                i += compile_statementlist(source, tokens, count, i);
                
                uint32_t end;
                if (tokens[i].kind == -3 || tokens[i].kind == -2)
                    end = prog_i + 3;
                else
                    end = prog_i;
                memcpy(program + jump_at, &end, 4);
            }
            else if (++i)
            {
                assert(token_is(source, tokens, count, i++, ":"));
                i += compile_statementlist(source, tokens, count, i);
            }
        }
        if (tokens[i].kind != -12) // end
            panic("Missing end keyword");
        uint32_t real_end = prog_i;
        while (skip_i > 0) memcpy(program + skips[--skip_i], &real_end, 4);
        i += 1;
        
        return i - orig_i;
    }
    if (tokens[i].kind == -5) // while
    {
        loop_nesting++;
        size_t expr_i = i + 1;
        i += compile_expr(source, tokens, count, expr_i, 0) + 1;
        assert(token_is(source, tokens, count, i++, ":"));
        program[prog_i++] = INST_JMP_IF_FALSE;
        size_t skip_at = prog_i;
        prog_i += 2;
        uint32_t loop_at = prog_i;
        
        i += compile_statementlist(source, tokens, count, i);
        assert(i < count);
        if (tokens[i].kind == -12) // end
        {
            compile_expr(source, tokens, count, expr_i, 0);
            program[prog_i++] = INST_JMP_IF_TRUE;
            prog_i += 2;
            memcpy(program + (prog_i - 2), &loop_at, 4);
            
            uint32_t end = prog_i;
            memcpy(program + skip_at, &end, 4);
            i += 1;
        }
        else panic("Missing end keyword");
        
        loop_nesting--;
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "let"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (in_global) globals_registered[id] = 1;
        else           locals_registered[id] = 1;
        if (token_is(source, tokens, count, i, "="))
        {
            size_t r = compile_expr(source, tokens, count, i + 1, 0);
            if (r)
            {
                i += r + 1;
                program[prog_i++] = INST_ASSIGN + in_global;
                program[prog_i++] = id;
            }
        }
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "for"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (in_global) globals_registered[id] = 1;
        else           locals_registered[id] = 1;
        assert(token_is(source, tokens, count, i++, "in"));
        uint16_t idx = for_loop_index++;
        assert(idx < FORLOOP_COUNT_LIMIT, "Too many for loops (max 256 per function or in root scope)")
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert(ret > 0, "For loop requires valid expression")
        i += ret;
        
        inst_push3(INST_FORSTART, id, idx);
        prog_i += 2;
        
        uint32_t head = prog_i;
        
        assert(token_is(source, tokens, count, i++, ":"));
        
        i += compile_statementlist(source, tokens, count, i);
        assert(tokens[i++].kind == -12, "Missing end keyword");
        
        inst_push3(INST_FOREND, id, idx);
        size_t at = prog_i;
        prog_i += 2;
        memcpy(program + at, &head, 4);
        
        uint32_t end = prog_i;
        memcpy(program + (head - 2), &end, 4);
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
             && (token_is(source, tokens, count, i+1, "=")
                 || token_is(source, tokens, count, i+1, "+=")
                 || token_is(source, tokens, count, i+1, "-=")
                 || token_is(source, tokens, count, i+1, "*=")
                 || token_is(source, tokens, count, i+1, "/=")
            ))
    {
        const char * opstr = stringdupn(source + tokens[i+1].i, tokens[i+1].len);
        size_t oplen = tokens[i+1].len;
        
        int16_t id = lex_ident_offset - tokens[i++].kind;
        i += 1; // =
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert(ret > 0, "Assignment requires valid expression")
        i += ret;
        
        uint8_t is_global;
        if (!in_global && locals_registered[id]) is_global = 0;
        else if (globals_registered[id]) is_global = 1;
        else panic("Unknown variable");
        
        if (strncmp(opstr, "=", oplen) == 0)       program[prog_i++] = INST_ASSIGN;
        else if (strncmp(opstr, "+=", oplen) == 0) program[prog_i++] = INST_ASSIGN_ADD;
        else if (strncmp(opstr, "-=", oplen) == 0) program[prog_i++] = INST_ASSIGN_SUB;
        else if (strncmp(opstr, "*=", oplen) == 0) program[prog_i++] = INST_ASSIGN_MUL;
        else if (strncmp(opstr, "/=", oplen) == 0) program[prog_i++] = INST_ASSIGN_DIV;
        
        if (is_global) program[prog_i - 1] += 1;
        program[prog_i++] = id;
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
             && token_is(source, tokens, count, i+1, "(")
             && funcs_registered[lex_ident_offset - tokens[i].kind].exists)
    {
        uint16_t id = lex_ident_offset - tokens[i++].kind;
        i += 1; // (
        
        uint16_t j = 0;
        while (!token_is(source, tokens, count, i, ")"))
        {
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            assert(j++ < 256, "Too many arguments to function (limit is 256)");
            i += r;
            
            if (!(token_is(source, tokens, count, i, ")")
                || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, ")")) return 0;
        
        inst_push3(INST_FUNCCALL, id, j);
        
        program[prog_i++] = INST_DISCARD;
        return i - orig_i;
    }
    else if (tokens[i].kind == -12 || tokens[i].kind == -3 || tokens[i].kind == -2) // end, elif, else
        return i - orig_i;
    else if (token_is(source, tokens, count, i, "\n")
             || token_is(source, tokens, count, i, ";"))
        return 1;
    else if (token_is(source, tokens, count, i, "return"))
    {
        i += 1;
        size_t r = compile_expr(source, tokens, count, i, 0);
        if (r == 0) program[prog_i++] = INST_RETURN_VOID;
        else        program[prog_i++] = INST_RETURN_VAL;
        return r + 1;
    }
    else
    {
        size_t r = compile_expr(source, tokens, count, i, 0);
        if (r == 0)
        {
            prints("AT: ");
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic("TODO");
        }
        program[prog_i++] = INST_DISCARD;
        return r;
    }
    panic();
}
size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    while (1)
    {
        if (i >= count) break;
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
    if (tokens[i].kind >= MIN_KEYWORD) return 0;
    int16_t id = lex_ident_offset - tokens[i++].kind;
    if (!token_is(source, tokens, count, i++, "(")) return 0;
    uint16_t args[256]; // at most 256 args per function
    uint32_t j = 0;
    while (1)
    {
        if (token_is(source, tokens, count, i, ")")) { i += 1; break; }
        if (tokens[i].kind >= MIN_KEYWORD) return 0;
        assert(j < 256);
        args[j++] = lex_ident_offset - tokens[i++].kind;
        locals_registered[args[j - 1]] = 1;
        if (!(token_is(source, tokens, count, i, ")")
              || token_is(source, tokens, count, i, ","))) return 0;
        if (token_is(source, tokens, count, i, ",")) i++;
    }
    if (!token_is(source, tokens, count, i++, ":")) return 0;
    
    program[prog_i++] = INST_FUNCDEF;
    size_t len_offs = prog_i;
    prog_i += 2;
    
    funcs_registered[id].exists = 1;
    funcs_registered[id].argcount = j;
    funcs_registered[id].id = id;
    funcs_registered[id].loc = prog_i;
    if (j > 0)
    {
        funcs_registered[id].args = (uint16_t *)malloc(sizeof(uint16_t)*j);
        memcpy(funcs_registered[id].args, &args, j * sizeof(uint16_t));
    }
    
    i += compile_statementlist(source, tokens, count, i);
    memcpy(program + len_offs, &prog_i, 4);
    
    return i - orig_i;
}
size_t compile(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    while (i < count)
    {
        size_t r;
        if (tokens[i].kind == -4) // func
        {
            in_global = 0;
            memset(locals_registered, 0, sizeof(locals_registered));
            r = compile_func(source, tokens, count, i+1);
            memset(locals_registered, 0, sizeof(locals_registered));
            in_global = 1;
            if (r == 0) panic("Incomplete function");
            i += r + 1;
            
            if (tokens[i++].kind != -12) panic("Missing end keyword");
        }
        else if ((r = compile_statement(source, tokens, count, i)))
            i += r;
        else
        {
            prints("AT: ");
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic("Expected function or statement");
            break;
        }
    }
    return i - orig_i;
}

struct _Value;
typedef struct _Array { struct _Value * buf; size_t len; size_t cap; } Array;

enum { VALUE_FLOAT, VALUE_ARRAY, VALUE_STRING, VALUE_FUNC, VALUE_NULL }; // tag
typedef struct _Value {
    union { double f; Array * a; char * s; Funcdef * fn; } u;
    uint8_t tag;
} Value;

Value array_get(Array * a, size_t i) { assert(i < a->len); return a->buf[i]; }

Value val_float(double f) { Value v; v.tag = VALUE_FLOAT; v.u.f = f; return v; }
Value val_string(char * s) { Value v; v.tag = VALUE_STRING; v.u.s = s; return v; }
Value val_func(uint16_t id) { Value v; v.tag = VALUE_FUNC; v.u.fn = &funcs_registered[id]; return v; }

uint8_t val_truthy(Value v)
{
    if (v.tag == VALUE_FLOAT) return v.u.f != 0.0;
    if (v.tag == VALUE_STRING) return v.u.s[0] != 0;
    if (v.tag == VALUE_ARRAY) return v.u.a->len > 0;
    if (v.tag == VALUE_FUNC) return 1;
    return 0;
}

typedef struct _Frame {
    size_t pc;
    struct _Frame * return_to;
    size_t stackpos;
    Value vars[FRAME_VARCOUNT];
    Value stack[FRAME_STACKSIZE];
    double forloops[FORLOOP_COUNT_LIMIT];
} Frame;

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame)
{
    if (id == lex_ident_offset - insert_or_lookup_id("print", 5))
    {
        for (size_t i = 0; i < argcount; i++)
        {
            int tag = frame->stack[frame->stackpos - 1 - i].tag;
            if (tag == VALUE_FLOAT)
                prints(baddtostr(frame->stack[frame->stackpos - 1 - i].u.f));
            else if (tag == VALUE_STRING)
                prints(frame->stack[frame->stackpos - 1 - i].u.s);
            else if (tag == VALUE_ARRAY)
                prints("<array>");
            if (i + 1 < argcount) prints(" ");
        }
        prints("\n");
    }
    else
        panic("Unknown internal function");
}

void print_op_and_panic(uint16_t op)
{
    prints("---\n");
    printu16hex(op);
    prints("\n---\n");
    panic("TODO");
}

void interpret(void)
{
    Frame * frame = (Frame *)malloc(sizeof(Frame));
    if (!frame) panic("Out of memory");
    
    Frame * global_frame = frame;

    #define CASES_START() \
    while (1) {\
        uint16_t opraw = program[frame->pc];\
        uint16_t op = opraw;\
        switch (op) {
    #define CASES_END() } }
    
    #define PC_INC() frame->pc += op >> 8
    
    #define MARK_CASE(X) case X: {
    #define END_CASE() PC_INC(); continue; }
    #define DECAULT_CASE() default: print_op_and_panic(op);
    
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)

    memset(frame, 0, sizeof(Frame));
    
    CASES_START()
        
        MARK_CASE(INST_INVALID)    return;
        
        NEXT_CASE(INST_DISCARD)    --frame->stackpos;
        
        NEXT_CASE(INST_FUNCDEF)
            uint32_t target;
            memcpy(&target, program + (frame->pc + 1), 4);
            frame->pc = target;
            continue;
        NEXT_CASE(INST_ARRAY_LITERAL)
            uint16_t itemcount = program[frame->pc + 1];
            Value v;
            v.tag = VALUE_ARRAY;
            v.u.a = (Array *)malloc(sizeof(Array));
            v.u.a->buf = (Value *)malloc(sizeof(Value) * itemcount);
            v.u.a->len = itemcount;
            v.u.a->cap = itemcount;
            while (itemcount > 0)
                v.u.a->buf[--itemcount] = frame->stack[--frame->stackpos];
            frame->stack[frame->stackpos++] = v;
        
        #define ENTER_FUNC()\
            assert(fn->exists);\
            if (fn->intrinsic)\
            {\
                handle_intrinsic_func(fn->id, argcount, frame);\
                frame->stackpos -= argcount;\
            }\
            else\
            {\
                Frame * prev = frame;\
                Frame * next = (Frame *)malloc(sizeof(Frame));\
                if (!next) panic("Out of memory");\
                PC_INC();\
                next->return_to = frame;\
                frame = next;\
                assert(argcount == fn->argcount);\
                for (size_t i = fn->argcount; i > 0;)\
                    frame->vars[fn->args[--i]] = prev->stack[--prev->stackpos];\
                prev->stack[--prev->stackpos];\
                frame->pc = fn->loc;\
                continue;\
            }
        
        NEXT_CASE(INST_FUNCCALL)
            uint16_t id = program[frame->pc + 1];
            uint16_t argcount = program[frame->pc + 2];
            Funcdef * fn = &funcs_registered[id];
            ENTER_FUNC()
        NEXT_CASE(INST_FUNCCALL_EXPR)
            uint16_t argcount = program[frame->pc + 1];
            Value v_func = frame->stack[frame->stackpos - argcount - 1];
            assert(v_func.tag == VALUE_FUNC);
            Funcdef * fn = v_func.u.fn;
            ENTER_FUNC()
        
        NEXT_CASE(INST_RETURN_VAL)
            Value v = frame->stack[--frame->stackpos];
            if (!frame->return_to) return;
            frame = frame->return_to;
            frame->stack[frame->stackpos++] = v;
            continue;
        
        NEXT_CASE(INST_RETURN_VOID)
            if (!frame->return_to) return;
            frame = frame->return_to;
            frame->stack[frame->stackpos++] = val_float(0.0);
            continue;
        
        NEXT_CASE(PUSH_NUM)
            double f;
            memcpy(&f, program + frame->pc + 1, 8);
            frame->stack[frame->stackpos++] = val_float(f);
        NEXT_CASE(PUSH_GLOBAL)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = global_frame->vars[id];
        
        NEXT_CASE(INST_ASSIGN_GLOBAL)
            Value v = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            global_frame->vars[id] = v;
        
        #define GLOBAL_MATH_SHARED()\
            Value v2 = frame->stack[--frame->stackpos];\
            uint16_t id = program[frame->pc + 1];\
            Value v1 = global_frame->vars[id];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
        
        NEXT_CASE(INST_ASSIGN_GLOBAL_ADD)    GLOBAL_MATH_SHARED()
            global_frame->vars[id] = val_float(v1.u.f + v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_SUB)    GLOBAL_MATH_SHARED()
            global_frame->vars[id] = val_float(v1.u.f - v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_MUL)    GLOBAL_MATH_SHARED()
            global_frame->vars[id] = val_float(v1.u.f * v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_DIV)    GLOBAL_MATH_SHARED()
            global_frame->vars[id] = val_float(v1.u.f / v2.u.f);
        
        #define MATH_SHARED()\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
        
        NEXT_CASE(INST_ADD)    MATH_SHARED()
            frame->stack[frame->stackpos++] = val_float(v1.u.f + v2.u.f);
        NEXT_CASE(INST_SUB)    MATH_SHARED()
            frame->stack[frame->stackpos++] = val_float(v1.u.f - v2.u.f);
        NEXT_CASE(INST_MUL)    MATH_SHARED()
            frame->stack[frame->stackpos++] = val_float(v1.u.f * v2.u.f);
        NEXT_CASE(INST_DIV)    MATH_SHARED()
            frame->stack[frame->stackpos++] = val_float(v1.u.f / v2.u.f);
        
        #define EQ_SHARED()\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            int8_t equality = 0;\
            if (v2.tag != v1.tag) equality = 2;\
            else if (v1.tag == VALUE_FLOAT && (v1.u.f != v1.u.f || v2.u.f != v2.u.f)) equality = 2;\
            else if (v1.tag == VALUE_FLOAT && v1.u.f < v2.u.f) equality = -1;\
            else if (v1.tag == VALUE_FLOAT && v1.u.f > v2.u.f) equality = 1;\
            else if (v1.tag == VALUE_FLOAT && v1.u.f == v2.u.f) equality = 0;\
            else if (v1.tag == VALUE_STRING) equality = strcmp(v1.u.s, v2.u.s);\
            else if (v1.tag == VALUE_ARRAY) equality = (v1.u.a != v2.u.a) * 2;
            // 0: equal, 1: neq (unordered). -2: lt. -1: gt.
        
        NEXT_CASE(INST_CMP_EQ)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality == 0);
        NEXT_CASE(INST_CMP_NE)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality != 0);
        NEXT_CASE(INST_CMP_LE)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality == 0 || equality == 1);
        NEXT_CASE(INST_CMP_GE)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality == 0 || equality == -1);
        NEXT_CASE(INST_CMP_LT)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality == 1);
        NEXT_CASE(INST_CMP_GT)    EQ_SHARED()
            frame->stack[frame->stackpos++] = val_float(equality == -1);
        
        #define READ_AND_GOTO_TARGET(X)\
            { uint32_t target;\
            memcpy(&target, program + (frame->pc + X), 4);\
            frame->pc = target;\
            continue; }
            
        NEXT_CASE(INST_FORSTART)
            Value v = frame->stack[--frame->stackpos];
            assert(v.tag == VALUE_FLOAT, "For loops can only operate on numbers");
            uint16_t id = program[frame->pc + 1];
            uint16_t idx = program[frame->pc + 2];
            frame->forloops[idx] = v.u.f;
            double temp = v.u.f;
            assert(temp - 1.0 != temp, "For loop value is too large and will never terminate");
            frame->vars[id] = val_float(0.0);
            if (temp < 1.0)
                READ_AND_GOTO_TARGET(3)
        NEXT_CASE(INST_FOREND)
            uint16_t id = program[frame->pc + 1];
            assert(frame->vars[id].tag == VALUE_FLOAT, "For loops can only operate on numbers");
            uint16_t idx = program[frame->pc + 2];
            frame->vars[id].u.f += 1.0;
            if (frame->vars[id].u.f < frame->forloops[idx])
                READ_AND_GOTO_TARGET(3)
        
        NEXT_CASE(INST_JMP)
            READ_AND_GOTO_TARGET(1)
        NEXT_CASE(INST_JMP_IF_FALSE)
            if (!val_truthy(frame->stack[--frame->stackpos])) READ_AND_GOTO_TARGET(1)
        NEXT_CASE(INST_JMP_IF_TRUE)
            if (val_truthy(frame->stack[--frame->stackpos])) READ_AND_GOTO_TARGET(1)
        
        NEXT_CASE(PUSH_STRING)
            uint16_t id = program[frame->pc + 1];
            char * s = stringdup(compiled_strings[id]);
            frame->stack[frame->stackpos++] = val_string(s);
        NEXT_CASE(PUSH_LOCAL)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = frame->vars[id];
        NEXT_CASE(PUSH_FUNCNAME)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = val_func(id);
        
        NEXT_CASE(INST_ASSIGN)
            Value v = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            frame->vars[id] = v;
        
        #define LOCAL_MATH_SHARED()\
            Value v2 = frame->stack[--frame->stackpos];\
            uint16_t id = program[frame->pc + 1];\
            Value v1 = frame->vars[id];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
        
        NEXT_CASE(INST_ASSIGN_ADD)    LOCAL_MATH_SHARED()
            frame->vars[id] = val_float(v1.u.f + v2.u.f);
        NEXT_CASE(INST_ASSIGN_SUB)    LOCAL_MATH_SHARED()
            frame->vars[id] = val_float(v1.u.f - v2.u.f);
        NEXT_CASE(INST_ASSIGN_MUL)    LOCAL_MATH_SHARED()
            frame->vars[id] = val_float(v1.u.f * v2.u.f);
        NEXT_CASE(INST_ASSIGN_DIV)    LOCAL_MATH_SHARED()
            frame->vars[id] = val_float(v1.u.f /     v2.u.f);
        
        NEXT_CASE(INST_INDEX)
            Value v2 = frame->stack[--frame->stackpos];
            Value v1 = frame->stack[--frame->stackpos];
            assert(v1.tag != VALUE_FLOAT);
            if (v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY)
                assert(v2.tag == VALUE_FLOAT);
            if (v1.tag == VALUE_STRING)
            {
                assert(((size_t)v2.u.f) < strlen(v1.u.s));
                v1.u.s = stringdupn(v1.u.s + (size_t)v2.u.f, 1);
            }
            if (v1.tag == VALUE_ARRAY)
                v1 = array_get(v1.u.a, v2.u.f);
            frame->stack[frame->stackpos++] = v1;
        END_CASE()
        DECAULT_CASE()
    CASES_END()
}

void register_intrinsic_func(const char * s)
{
    int16_t id = lex_ident_offset - insert_or_lookup_id(s, strlen(s));
    funcs_registered[id].exists = 1;
    funcs_registered[id].intrinsic = 1;
    funcs_registered[id].id = id;
}
int main(int argc, char ** argv)
{
#ifdef USE_GC
    GC_INIT();
#endif
    lex_init();
    register_intrinsic_func("print");
    
    if (argc < 2) { prints("Usage: filli filename.fil\n"); return 0; }
    char * source = 0;
    size_t total_size = 0;
    
    #define CHUNK_SIZE 4096
    size_t capacity = CHUNK_SIZE;
    source = (char*)malloc(capacity);
    if (!source) { perror("Out of memory"); return 1; }
    
    FILE * file;
    if (strcmp(argv[1], "-") == 0) file = stdin;
    else file = fopen(argv[1], "rb");
    
    if (!file) { perror("Error reading file"); return 1; }
    
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
    compile(source, tokens, count, 0);
    
    for (size_t i = 0; i < prog_i; i++)
    {
        printu16hex(program[i]);
        prints("\n");
    }
    
    interpret();
    
    return 0;
}
