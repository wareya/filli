#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IDENTIFIER_COUNT 32000
#define FRAME_VARCOUNT 1024
#define FRAME_STACKSIZE 1024
#define PROGRAM_MAXLEN 100000
#define FORLOOP_COUNT_LIMIT 255

// micro stdlib replacement stuff to reduce binary size (yes, this has a big effect)

#define STRINGIZE2(x) #x
#define STRINGIZE(x) STRINGIZE2(x)
#define LINE_STRING STRINGIZE(__LINE__)

#define just_die() __builtin_abort()
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
char * stringdup(const char * s)
{
    return stringdupn(s, strlen(s));
}

void prints(const char * s) { fputs(s, stdout); }
void eprints(const char * s) { fputs(s, stderr); }
void printu16hex(uint16_t x)
{
    char c[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    char s[5] = { c[(x>>12)&15], c[(x>>8)&15], c[(x>>4)&15], c[x&15], 0 };
    prints(s);
}
void printsn(const char * s, size_t len)
{
    prints(stringdupn(s, len));
}

double badstrtod(const char * s)
{
    if ((s[0]&~32) == 'N' && (s[1]&~32) == 'A' && (s[0]&~32) == 'N') return 0.0/0.0;
    
    double sign = 1.0;
    if (*s == '-') { sign = -1.0; s += 1; }
    if (!s[0]) return 0.0 * sign;
    
    if ((s[0]&~32) == 'I' && (s[1]&~32) == 'N' && (s[0]&~32) == 'F') return sign/0.0;
    
    double ret = 0.0;
    while (*s != 0 && *s != '.' && *s >= '0' && *s <= '9')
        ret = ret * 10.0 + (*(s++) - '0');
    if (*(s++) != '.')
        return ret * sign;
    
    double f2 = 0.1;
    while (*s != 0 && *s >= '0' && *s <= '9')
        (ret = ret + (*(s++) - '0') * f2), (f2 *= 0.1);
    
    return ret * sign;
}

float badstrtof(const char * s)
{
    return badstrtod(s);
}

const char * badftostr(double f)
{
    if (f != f) return "nan";
    if (f+f == f) return "inf";
    if (f-f == f) return "-inf";
    
    char buf[50] = {};
    size_t i = 0;
    
    uint32_t pun;
    memcpy(&pun, &f, 4);
    if (pun & 0x80000000) buf[i++] = '-';
    
    size_t mag = 0;
    while (f < 1000000000.0)
    {
        f *= 10.0;
        mag += 1;
    }
    
    uint64_t ipart = f;
    uint8_t digits = 0;
    uint64_t ipart2 = ipart;
    while (ipart2) { digits++; ipart2 /= 10; }
    if (digits == 0) digits = 1;
    ipart2 = ipart;
    for (size_t j = digits; j > 0;)
    {
        buf[--j] = '0' + (ipart2 % 10);
        ipart2 /= 10;
    }
    
    for (size_t j = digits; j > digits - mag; j--)
        buf[j] = buf[j - 1];
    buf[digits-mag] = '.';
    
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
        if ((source[i] >= '0' && source[i] <= '9') || (source[i] == '-' && source[i+1] >= '0' && source[i+1] <= '9'))
        {
            int dot_ok = 1;
            size_t start_i = i;
            if (source[i] == '-') i += 1;
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
    INST_EQ = 0x100,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV,
    // 1-op
    PUSH_LOCAL = 0x210,
    PUSH_GLOBAL,
    PUSH_FUNCNAME,
    INST_ASSIGN,
    INST_ASSIGN_GLOBAL,
    INST_ASSIGN_ADD,
    INST_ASSIGN_GLOBAL_ADD,
    INST_ASSIGN_SUB,
    INST_ASSIGN_GLOBAL_SUB,
    INST_ASSIGN_MUL,
    INST_ASSIGN_GLOBAL_MUL,
    INST_ASSIGN_DIV,
    INST_ASSIGN_GLOBAL_DIV,
    // 2-op
    INST_IF = 0x320, // destination
    INST_JMP, // destination
    PUSH_STRING, // token index
    INST_FUNCDEF, // skip destination
    INST_FORSTART, // var id (2), for slot (2)
    INST_FUNCCALL, // func id, arg count
    // 4-op
    INST_FOREND = 0x530, // var id (2), for slot (2), destination (4)
    PUSH_NUM, // f64
};

#define INSTRUCTIONS_XMACRO(X) \
    INST_XXXX(INST_INVALID)\
    INST_XXXX(INST_EQ)\
    INST_XXXX(INST_ADD)\
    INST_XXXX(INST_SUB)\
    INST_XXXX(INST_MUL)\
    INST_XXXX(INST_DIV)\
    INST_XXXX(PUSH_LOCAL)\
    INST_XXXX(PUSH_GLOBAL)\
    INST_XXXX(PUSH_FUNCNAME)\
    INST_XXXX(INST_ASSIGN)\
    INST_XXXX(INST_ASSIGN_GLOBAL)\
    INST_XXXX(INST_ASSIGN_ADD)\
    INST_XXXX(INST_ASSIGN_GLOBAL_ADD)\
    INST_XXXX(INST_ASSIGN_SUB)\
    INST_XXXX(INST_ASSIGN_GLOBAL_SUB)\
    INST_XXXX(INST_ASSIGN_MUL)\
    INST_XXXX(INST_ASSIGN_GLOBAL_MUL)\
    INST_XXXX(INST_ASSIGN_DIV)\
    INST_XXXX(INST_ASSIGN_GLOBAL_DIV)\
    INST_XXXX(INST_IF)\
    INST_XXXX(INST_JMP)\
    INST_XXXX(PUSH_NUM)\
    INST_XXXX(PUSH_STRING)\
    INST_XXXX(INST_FUNCDEF)\
    INST_XXXX(INST_FORSTART)\
    INST_XXXX(INST_FUNCCALL)\
    INST_XXXX(INST_FOREND)

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
    return -1;
}

typedef struct _Funcdef {
    uint8_t exists;
    uint8_t intrinsic;
    uint8_t argcount;
    uint16_t * args;
} Funcdef;

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
    
    if (tokens[i].kind < 0)
    {
        if (!in_global && locals_registered[lex_ident_offset-tokens[i].kind])
            program[prog_i++] = PUSH_LOCAL;
        else if (globals_registered[lex_ident_offset-tokens[i].kind])
            program[prog_i++] = PUSH_GLOBAL;
        else if (funcs_registered[lex_ident_offset-tokens[i].kind].exists)
            program[prog_i++] = PUSH_FUNCNAME;
        program[prog_i++] = lex_ident_offset-tokens[i].kind;
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
        
        char * s = stringdupn(source + tokens[i].i, tokens[i].len);
        double f = badstrtod(s);
        free(s);
        
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        memcpy(program + prog_i - 4, &f, 8);
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
    if (token_is(source, tokens, count, i, "-")) inst = INST_SUB;
    else if (token_is(source, tokens, count, i, "/")) inst = INST_DIV;
    else if (token_is(source, tokens, count, i, "+")) inst = INST_ADD;
    else if (token_is(source, tokens, count, i, "*")) inst = INST_MUL;
    else if (token_is(source, tokens, count, i, "==")) inst = INST_EQ;
    else panic("TODO");
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
        i += compile_expr(source, tokens, count, i + 1, 0) + 1;
        assert(token_is(source, tokens, count, i++, ":"));
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
        else panic("Missing end keyword");
        
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "let"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (in_global)
            globals_registered[id] = 1;
        else
            locals_registered[id] = 1;
        if (token_is(source, tokens, count, i, "="))
        {
            size_t r = compile_expr(source, tokens, count, i + 1, 0);
            if (r)
            {
                i += r + 1;
                if (in_global)
                    program[prog_i++] = INST_ASSIGN_GLOBAL;
                else
                    program[prog_i++] = INST_ASSIGN;
                program[prog_i++] = id;
            }
        }
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "for"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (in_global)
            globals_registered[id] = 1;
        else
            locals_registered[id] = 1;
        assert(token_is(source, tokens, count, i++, "in"));
        uint16_t idx = for_loop_index++;
        if (in_global)
            assert(idx < FORLOOP_COUNT_LIMIT, "Too many for loops in global scope")
        else
            assert(idx < FORLOOP_COUNT_LIMIT, "Too many for loops in function")
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert(ret > 0, "For loop requires valid expression")
        i += ret;
        
        program[prog_i++] = INST_FORSTART;
        program[prog_i++] = id;
        program[prog_i++] = idx;
        
        uint32_t head = prog_i;
        
        assert(token_is(source, tokens, count, i++, ":"));
        
        i += compile_statementlist(source, tokens, count, i);
        assert(tokens[i++].kind == -12, "Missing end keyword");
        
        program[prog_i++] = INST_FOREND;
        program[prog_i++] = id;
        program[prog_i++] = idx;
        size_t at = prog_i;
        program[prog_i++] = 0;
        program[prog_i++] = 0;
        memcpy(program + at, &head, 4);
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
        
        uint8_t isglobal;
        if (!in_global && locals_registered[id]) isglobal = 0;
        else if (globals_registered[id]) isglobal = 1;
        else panic("Unknown variable");
        
        if (strncmp(opstr, "=", oplen) == 0)
        {
            if (!isglobal) program[prog_i++] = INST_ASSIGN;
            else           program[prog_i++] = INST_ASSIGN_GLOBAL;
        }
        else if (strncmp(opstr, "+=", oplen) == 0)
        {
            if (!isglobal) program[prog_i++] = INST_ASSIGN_ADD;
            else           program[prog_i++] = INST_ASSIGN_GLOBAL_ADD;
        }
        else if (strncmp(opstr, "-=", oplen) == 0)
        {
            if (!isglobal) program[prog_i++] = INST_ASSIGN_SUB;
            else           program[prog_i++] = INST_ASSIGN_GLOBAL_SUB;
        }
        else if (strncmp(opstr, "*=", oplen) == 0)
        {
            if (!isglobal) program[prog_i++] = INST_ASSIGN_MUL;
            else           program[prog_i++] = INST_ASSIGN_GLOBAL_MUL;
        }
        else if (strncmp(opstr, "/=", oplen) == 0)
        {
            if (!isglobal) program[prog_i++] = INST_ASSIGN_DIV;
            else           program[prog_i++] = INST_ASSIGN_GLOBAL_DIV;
        }
        program[prog_i++] = id;
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
             && token_is(source, tokens, count, i+1, "("))
    {
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (!funcs_registered[id].exists) return 0;
        i += 1; // (
        
        uint16_t j = 0;
        while (1)
        {
            if (token_is(source, tokens, count, i, ")")) break;
            
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            assert(j++ < 256, "Too many arguments to function (limit is 256)");
            i += r;
            
            if (!(token_is(source, tokens, count, i, ")")
                || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, ")")) return 0;
        
        program[prog_i++] = INST_FUNCCALL;
        program[prog_i++] = id;
        program[prog_i++] = j;
        return i - orig_i;
    }
    else if (tokens[i].kind == -12) // end
    {
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "\n"))
        return 1;
    else
    {
        prints("AT: ");
        printsn(source + tokens[i].i, tokens[i].len);
        prints("\n");
        panic("TODO");
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
    memset(locals_registered, 0, sizeof(locals_registered));
    size_t orig_i = i;
    if (i >= count) return 0;
    if (tokens[i].kind >= -12) return 0;
    int16_t id = lex_ident_offset - tokens[i].kind;
    i += 1; // name
    if (!token_is(source, tokens, count, i, "(")) return 0;
    i += 1; // (
    uint16_t args[256]; // at most 256 args per function
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
    size_t len_offs = prog_i;
    program[prog_i++] = 0; // part 1 of length
    program[prog_i++] = 0; // part 2 of length
    
    i += compile_statementlist(source, tokens, count, i);
    
    memcpy(program + len_offs, &prog_i, 4);
    
    funcs_registered[id].exists = 1;
    funcs_registered[id].argcount = j;
    if (j > 0)
    {
        funcs_registered[id].args = (uint16_t *)malloc(sizeof(uint16_t)*j);
        memcpy(funcs_registered[id].args, &args, j * sizeof(uint16_t));
    }
    
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
            r = compile_func(source, tokens, count, i+1);
            if (r == 0)
                panic("Incomplete function");
            i += r + 1;
            
            if (tokens[i].kind != -12) // end
                panic("Missing end keyword");
            i += 1;
            in_global = 1;
        }
        else if ((r = compile_statement(source, tokens, count, i)))
        {
            i += r;
        }
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
typedef struct _Array {
    struct _Value * first;
    size_t len;
} Array;

typedef struct _Value {
    union { double f; Array * a; } u;
    uint8_t tag;
} Value;

enum {
    VALUE_FLOAT,
    VALUE_ARRAY,
};

Value val_float(double f)
{
    Value v;
    v.tag = VALUE_FLOAT;
    v.u.f = f;
    return v;
}

typedef struct _Forloop {
    double limit;
} Forloop;

typedef struct _Frame {
    size_t pc;
    struct _Frame * return_to;
    size_t stackpos;
    Value vars[FRAME_VARCOUNT];
    Value stack[FRAME_STACKSIZE];
    Forloop forloops[FORLOOP_COUNT_LIMIT];
} Frame;

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame)
{
    if (id == lex_ident_offset - insert_or_lookup_id("print", 5))
    {
        for (size_t i = 0; i < argcount; i++)
            //printf("%f ", frame->stack[frame->stackpos - 1 - i].u.f);
            prints(badftostr(frame->stack[frame->stackpos - 1 - i].u.f));
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

#define USE_LOOP_DISPATCH

#ifdef USE_LOOP_DISPATCH
    
    #define CASES_START() \
    while (1) {\
        uint16_t opraw = program[frame->pc];\
        uint16_t op = opraw;\
        switch (op) {
    #define CASES_END() } }
    
    #define MARK_CASE(X) case X: {
    #define END_CASE() frame->pc += op >> 8; continue; }
    #define DECAULT_CASE() default: print_op_and_panic(op);
    
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)

#else
    
    void ** handlers[0xFF];
    for (size_t i = 0; i < 0xFF; i++)
        handlers[i] = &&_handler_default;
    
    #define CASE_INSTALL(X) handlers[X & 0xFF] = &&_handler_##X;
    
    #define INST_XXXX CASE_INSTALL
    INSTRUCTIONS_XMACRO()
    
    uint16_t opraw = 0;
    uint16_t op = 0;
    
    #define CASES_HANDLE() \
        if (frame->pc >= prog_i) return;\
        opraw = program[frame->pc];\
        op = opraw & 0xFF; \
        goto *handlers[op];
    
    #define CASES_START() \
    while (1) { CASES_HANDLE()
    
    #define CASES_END() }
    
    #define MARK_CASE(X) _handler_##X: {
    #define END_CASE() frame->pc += opraw >> 8; CASES_HANDLE(); }
    #define DECAULT_CASE() _handler_default: print_op_and_panic(opraw);
    
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)

#endif

    memset(frame, 0, sizeof(Frame));
    
    CASES_START()
        
        MARK_CASE(INST_INVALID)
            return;
        NEXT_CASE(INST_FUNCDEF)
            panic("TODO funcdef");
        NEXT_CASE(INST_FUNCCALL)
            uint16_t id = program[frame->pc + 1];
            uint16_t argcount = program[frame->pc + 2];
            assert(funcs_registered[id].exists);
            if (funcs_registered[id].intrinsic)
            {
                handle_intrinsic_func(id, argcount, frame);
                frame->stackpos -= argcount;
            }
            else
                panic("TODO funccall");
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
        
        NEXT_CASE(INST_ASSIGN_GLOBAL_ADD)
            Value v2 = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            Value v1 = global_frame->vars[id];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            global_frame->vars[id] = val_float(v1.u.f + v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_SUB)
            Value v2 = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            Value v1 = global_frame->vars[id];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            global_frame->vars[id] = val_float(v1.u.f - v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_MUL)
            Value v2 = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            Value v1 = global_frame->vars[id];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            global_frame->vars[id] = val_float(v1.u.f * v2.u.f);
        NEXT_CASE(INST_ASSIGN_GLOBAL_DIV)
            Value v2 = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            Value v1 = global_frame->vars[id];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            global_frame->vars[id] = val_float(v1.u.f / v2.u.f);
        
        NEXT_CASE(INST_ADD)
            Value v2 = frame->stack[--frame->stackpos];
            Value v1 = frame->stack[--frame->stackpos];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            frame->stack[frame->stackpos++] = val_float(v1.u.f + v2.u.f);
        NEXT_CASE(INST_SUB)
            Value v2 = frame->stack[--frame->stackpos];
            Value v1 = frame->stack[--frame->stackpos];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            frame->stack[frame->stackpos++] = val_float(v1.u.f - v2.u.f);
        NEXT_CASE(INST_MUL)
            Value v2 = frame->stack[--frame->stackpos];
            Value v1 = frame->stack[--frame->stackpos];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            frame->stack[frame->stackpos++] = val_float(v1.u.f * v2.u.f);
        NEXT_CASE(INST_DIV)
            Value v2 = frame->stack[--frame->stackpos];
            Value v1 = frame->stack[--frame->stackpos];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            frame->stack[frame->stackpos++] = val_float(v1.u.f / v2.u.f);
        
        NEXT_CASE(INST_FORSTART)
            Value v = frame->stack[--frame->stackpos];
            assert(v.tag == VALUE_FLOAT, "For loops can only operate on numbers");
            uint16_t id = program[frame->pc + 1];
            uint16_t idx = program[frame->pc + 2];
            frame->forloops[idx].limit = v.u.f;
            frame->vars[id] = val_float(0.0f);
        NEXT_CASE(INST_FOREND)
            uint16_t id = program[frame->pc + 1];
            uint16_t idx = program[frame->pc + 2];
            uint32_t target;
            memcpy(&target, program + (frame->pc + 3), 4);
            
            double limit = frame->forloops[idx].limit;
            
            Value v = frame->vars[id];
            assert(v.tag == VALUE_FLOAT, "For loops can only operate on numbers");
            
            v.u.f += 1.0f;
            frame->vars[id] = v;
            if (v.u.f < limit)
            {
                frame->pc = target;
                continue;
            }
        NEXT_CASE(INST_JMP)
            panic("TODO");
        NEXT_CASE(PUSH_STRING)
            panic("TODO");
        NEXT_CASE(INST_IF)
            panic("TODO");
        NEXT_CASE(INST_EQ)
            panic("TODO");
        NEXT_CASE(PUSH_LOCAL)
            panic("TODO");
        NEXT_CASE(PUSH_FUNCNAME)
            panic("TODO");
        NEXT_CASE(INST_ASSIGN)
            panic("TODO");
        NEXT_CASE(INST_ASSIGN_ADD)
            panic("TODO");
        NEXT_CASE(INST_ASSIGN_SUB)
            panic("TODO");
        NEXT_CASE(INST_ASSIGN_MUL)
            panic("TODO");
        NEXT_CASE(INST_ASSIGN_DIV)
            panic("TODO");
        END_CASE()
        DECAULT_CASE()
    CASES_END()
}

int main(int argc, char ** argv)
{
    if (argc < 2) { prints("Usage: filli filename.fil\n"); return 0; }
    char * source = 0;
    size_t total_size = 0;
    #define CHUNK_SIZE 4096
    size_t capacity = CHUNK_SIZE;
    source = (char*)malloc(capacity);
    if (!source) { perror("Out of memory"); return 1; }
    
    FILE * file = fopen(argv[1], "rb");
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
    
    for (size_t i = 0; i < count; i++)
    {
        prints("[");
        printsn(source + tokens[i].i, tokens[i].len);
        prints("]\n");
    }
    
    //register_intrinsic_func
    int16_t id = lex_ident_offset - insert_or_lookup_id("print", 5);
    funcs_registered[id].exists = 1;
    funcs_registered[id].intrinsic = 1;
    
    compile(source, tokens, count, 0);
    
    for (size_t i = 0; i < prog_i; i++)
    {
        printu16hex(program[i]);
        prints("\n");
    }
    
    interpret();
    
    return 0;
}
