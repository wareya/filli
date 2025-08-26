#ifndef FILLI_H_INCLUDED
#define FILLI_H_INCLUDED

// INTEGRATION:
// - include and link boehm GC and use #define to replace stdlib malloc/free with boehm funcs
// - - or, INSTEAD, include microarena.h and use #defines to map malloc/free to ma_malloc/ma_free, and use ma_free_checkpoint after running Filli
// - rewrite intrinsics.h, adding whatever functionality you need (e.g. trig, array insert/delete/splice)
// - skim microlib.h, consider replacing it with thin stdlib wrappers

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
#define FI_LIT(X)
#else
#define FI_LIT(X) (X)
#endif

// 40% speed boost on clang, but increases binary size by ~7KB (from ~34KB to ~41KB). worth it, IMO.
#define USE_TAIL_DISPATCH 1

#define IDENTIFIER_COUNT 32000 // max number of uniquely-spelled identifiers per program
#define FRAME_VARCOUNT 1024 // increases memory usage of stack frames
#define FRAME_STACKSIZE 1024 // increases memory usage of stack frames
#define PROGRAM_MAXLEN 100000 // default max length of program
#define FORLOOP_COUNT_LIMIT 255 // increases memory usage of stack frames
#define ARGLIMIT 255 // affects risk of stack smashing during compilation
#define ELIFLIMIT 255 // affects risk of stack smashing during compilation
#define CAPTURELIMIT 255
#define LAMBDA_COUNT 4096

// this library just does stuff that the stdlib does but with less stdlib involvement
// why? smaller statically linked (e.g. musl) binaries. yes, the difference is significant!
#include "microlib.h"

const char * filli_err = 0;

#define assert2(N, X, ...) { if (!(X)) { if (__VA_OPT__(1)+0 && !filli_err) filli_err = #__VA_ARGS__; else if (!filli_err) filli_err = #X; return N; } }
//#define assert2(N, X, ...) assert(X, __VA_ARGS__)
#define assert3(X, ...) (( (!(X)) ? ( (__VA_OPT__(1)+0 && !filli_err) ? filli_err = #__VA_ARGS__ : (!filli_err) ? filli_err = #X : "") : ""), (void) 0 )
#define panic2(N, X) { if (!filli_err) filli_err = #X; return N; }
//#define panic2(N, X) panic(X)
#define repanic(N) {}

/*
#define assert2(N, X, ...) ((void)(X))
#define assert3(X, ...) ((void)(X))
#define panic2(N, X) panic(X)
#define repanic(N) { if (filli_err) return N; }
*/

void * zalloc(size_t s) { char * r = (char *)malloc(s); if (!r) panic("Out of memory"); memset(r, 0, s); return r; }

// actual program

typedef struct _IdEntry { const char * where; uint16_t len; } IdEntry;

int16_t insert_or_lookup_id(const char * text, uint16_t len)
{
    // TODO: make non-static
    static IdEntry ids[IDENTIFIER_COUNT] = {};
    for (int16_t j = 1; j <= IDENTIFIER_COUNT; j++)
    {
        if (ids[j].len == 0) ids[j] = FI_LIT(IdEntry) { stringdupn(text, len), len };
        if (ids[j].len == len && strncmp(ids[j].where, text, len) == 0) return -j;
    }
    panic2(0, "Out of IDs");
}

typedef struct _Token { uint32_t i; uint16_t len; int16_t kind; } Token;
// key to kind:
// negative: identifier
// zero: number
// one: string
// two: punctuation
// three: newline (if enabled)

int token_is(const char * source, Token * tokens, size_t count, size_t i, const char * text)
{
    if (i >= count) return 0;
    size_t len = strlen(text);
    if (tokens[i].len != len) return 0;
    return strncmp(source + tokens[i].i, text, len) == 0;
}

Token mk_token(uint32_t i, uint16_t len, int16_t kind) { Token t = {i, len, kind}; return t; }

void lex_init(void)
{
    // give keywords known ids
    const char * keywords[] = { "if", "else", "elif", "func", "while", "for", "break", "continue", "return", "let", "end", "lambda", "yield"};
    for (size_t j = 0; j < sizeof(keywords) / sizeof(keywords[0]); j++)
        insert_or_lookup_id(keywords[j], strlen(keywords[j]));

    // 1: if
    // 2: else
    // 3: elif
    // 4: func
    // 5: while
    // 6: for
    // 7: break
    // 8: continue
    // 9: return
    // 10: let
    // 11: end
    // 12: lambda
    // 13: lambda
}
int lex_ident_offset = 13;

Token * tokenize(const char * src, size_t * count)
{
    int newline_is_token = 1;
    
    const char * longpunc[] = { "==", "!=", ">=", "<=", "+=", "-=", "*=", "/=", "{}" };
    
    size_t len = strlen(src);
    
    Token * ret = (Token *)zalloc(sizeof(Token) * len);
    size_t t = 0;
    
    for (size_t i = 0; i < len; )
    {
        // skip comments and whitespace
        if (src[i] == '#') { while (src[i] != '\0' && src[i] != '\n') { i++; } continue; }
        if (src[i] == ' ' || src[i] == '\t' || src[i] == '\r') { i++; continue; }
        
        if (src[i] == '\n')
        {
            if (newline_is_token && t > 0 && token_is(src, ret, t, t-1, "\\")) { t -= 1; i++; }
            else if (newline_is_token) ret[t++] = mk_token(i++, 1, 3);
        }
        // tokenize numbers
        else if ((src[i] >= '0' && src[i] <= '9') || (src[i] == '-' && src[i+1] >= '0' && src[i+1] <= '9'))
        {
            size_t start_i = i;
            if (src[i] == '-') i += 1;
            uint8_t dok = 1; // dot OK or not?
            while ((src[i] >= '0' && src[i] <= '9') || (dok && src[i] == '.')) dok &= src[i++] != '.';
            ret[t++] = mk_token(start_i, i-start_i, 0);
        }
        // tokenize identifiers and keywords
        else if ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z') || src[i] == '_')
        {
            size_t start_i = i++;
            while ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z')
                   || src[i] == '_' || (src[i] >= '0' && src[i] <= '9')) i++;
            
            ret[t++] = mk_token(start_i, i - start_i, insert_or_lookup_id(src + start_i, i - start_i));
        }
        // tokenize strings
        else if (src[i] == '\'' || src[i] == '"')
        {
            size_t start_i = i++;
            while (src[i] != src[start_i] && src[i] != 0) i += (src[i] == '\\') ? 2 : 1;
            if (src[i] != 0) i += 1;
            ret[t++] = mk_token(start_i, i-start_i, 1);
        }
        else
        {
            // long punctuation
            for (size_t j = 0; j < sizeof(longpunc) / sizeof(longpunc[0]); j++)
            {
                if (strncmp(longpunc[j], src+i, strlen(longpunc[j])) == 0)
                {
                    ret[t++] = mk_token(i, strlen(longpunc[j]), 2);
                    i += strlen(longpunc[j]);
                    goto fullcontinue;
                }
            }
            // normal punctuation
            ret[t++] = mk_token(i++, 1, 2);
            
            fullcontinue: {}
        }
    }
    
    *count = t;
    return ret;
}

enum { INST_INVALID = 0x000,
    // zero-op
    INST_RETURN_VOID = 0x100,
    // 1-op
    INST_RETURN_VAL = 0x210, INST_YIELD, PUSH_NULL, PUSH_DICT_EMPTY,
    INST_SET_LOC, INST_SET_LOC_ADD, INST_SET_LOC_SUB, INST_SET_LOC_MUL, INST_SET_LOC_DIV,
    INST_INDEX, INST_INDEX_LOC, INST_CMP_EQ, INST_CMP_NE, INST_CMP_GT, INST_CMP_LT, INST_CMP_GE, INST_CMP_LE,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV, INST_CMP_AND, INST_CMP_OR, INST_BITAND, INST_BITOR, INST_BITXOR, INST_INTMOD,
    // 2-op
    PUSH_FUNCNAME = 0x340, INST_FUNCCALL_REF, PUSH_STRING, INST_ARRAY_LITERAL,
    PUSH_LOCAL, PUSH_GLOBAL, PUSH_CAP, INST_SET, INST_SET_GLOBAL, INST_SET_CAP,
    INST_SET_ADD, INST_SET_GLOBAL_ADD, INST_SET_CAP_ADD, INST_SET_SUB, INST_SET_GLOBAL_SUB, INST_SET_CAP_SUB,
    INST_SET_MUL, INST_SET_GLOBAL_MUL, INST_SET_CAP_MUL, INST_SET_DIV, INST_SET_GLOBAL_DIV, INST_SET_CAP_DIV,
    
    INST_JMP, INST_FUNCDEF,
    // 3-op
    INST_JMP_IF_FALSE = 0x460, INST_JMP_IF_TRUE, INST_FUNCCALL,
    // jumps: destination
    // INST_FUNCDEF: skip destination
    // INST_FUNCCALL: func id, arg count
    // 4-op
    INST_FOREND = 0x580,
    // 5-op
    PUSH_NUM = 0x6a0, INST_LAMBDA, INST_FORSTART 
};

#define INST_XMACRO() INSTX(INST_INVALID) INSTX(PUSH_NULL) INSTX(PUSH_DICT_EMPTY) INSTX(INST_RETURN_VAL) INSTX(INST_RETURN_VOID) INSTX(INST_YIELD) INSTX(INST_ADD) INSTX(INST_SUB) INSTX(INST_MUL) INSTX(INST_DIV) INSTX(INST_CMP_AND) INSTX(INST_CMP_OR) INSTX(INST_SET_LOC) INSTX(INST_SET_LOC_ADD) INSTX(INST_SET_LOC_SUB) INSTX(INST_SET_LOC_MUL) INSTX(INST_SET_LOC_DIV) INSTX(INST_INDEX) INSTX(INST_INDEX_LOC) INSTX(INST_CMP_EQ) INSTX(INST_CMP_NE) INSTX(INST_CMP_GT) INSTX(INST_CMP_LT) INSTX(INST_CMP_GE) INSTX(INST_CMP_LE) INSTX(PUSH_FUNCNAME) INSTX(INST_FUNCCALL_REF) INSTX(PUSH_STRING) INSTX(INST_ARRAY_LITERAL) INSTX(PUSH_LOCAL) INSTX(PUSH_GLOBAL) INSTX(PUSH_CAP) INSTX(INST_SET) INSTX(INST_SET_GLOBAL) INSTX(INST_SET_CAP) INSTX(INST_SET_ADD) INSTX(INST_SET_GLOBAL_ADD) INSTX(INST_SET_CAP_ADD) INSTX(INST_SET_SUB) INSTX(INST_SET_GLOBAL_SUB) INSTX(INST_SET_CAP_SUB) INSTX(INST_SET_MUL) INSTX(INST_SET_GLOBAL_MUL) INSTX(INST_SET_CAP_MUL) INSTX(INST_SET_DIV) INSTX(INST_SET_GLOBAL_DIV) INSTX(INST_SET_CAP_DIV) INSTX(INST_JMP) INSTX(INST_JMP_IF_FALSE) INSTX(INST_JMP_IF_TRUE) INSTX(INST_FUNCDEF) INSTX(INST_FUNCCALL) INSTX(PUSH_NUM) INSTX(INST_FOREND) INSTX(INST_FORSTART) INSTX(INST_LAMBDA) INSTX(INST_BITAND) INSTX(INST_BITOR) INSTX(INST_BITXOR) INSTX(INST_INTMOD)

typedef struct _Program { uint16_t * code; uint32_t capacity; uint32_t i; } Program;
Program prog = {0, PROGRAM_MAXLEN, 0};
void init_program() { prog.code = (uint16_t *)zalloc(sizeof(uint16_t) * prog.capacity); }

void prog_write(uint16_t a) { if (prog.i < PROGRAM_MAXLEN) prog.code[prog.i++] = a; else panic2(,"Compiled program longer than PROGRAM_MAXLEN"); }
void prog_write2(uint16_t a, uint16_t b) { prog_write(a); prog_write(b); }
void prog_write3(uint16_t a, uint16_t b, uint16_t c) { prog_write2(a, b); prog_write(c); }
void prog_write4(uint16_t a, uint16_t b, uint16_t c, uint16_t d) { prog_write3(a, b, c); prog_write(d); }
void prog_write5(uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e) { prog_write3(a, b, c); prog_write2(d, e); }
void prog_write6(uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e, uint16_t f) { prog_write3(a, b, c); prog_write3(d, e, f); }

int tokenop_bindlevel(const char * source, Token * tokens, size_t count, size_t i)
{
    const char * ops[] = { "or", "\1", "and", "\1", "==", "\3", "!=", "\3", ">=", "\3", "<=", "\3", ">", "\3", "<", "\3",
                           "+", "\4", "-", "\4", "^", "\4", "*", "\5", "/", "\5", "%", "\5", "&", "\5", "|", "\5", "[", "\111", "(", "\111" };
    for (size_t j = 0; i < count && j < sizeof(ops) / sizeof(ops[0]); j += 2)
        if (token_is(source, tokens, count, i, ops[j])) return ops[j + 1][0];
    return -1;
}

struct _Value;

typedef struct _Funcdef {
    uint8_t exists, intrinsic, poolsafe;
    uint16_t argcount, id;
    uint16_t * args;
    uint16_t cap_count;
    uint32_t loc;
    int16_t * caps;
    struct _Value ** cap_data;
} Funcdef;

typedef struct _CompilerData {
    const char * compiled_strings[1<<16];
    uint16_t globals_reg[IDENTIFIER_COUNT];
    Funcdef funcs_reg[IDENTIFIER_COUNT + LAMBDA_COUNT];
    
    uint32_t lambda_id, compiled_string_i, locals_reg_i, globals_n, locals_n, caps_reg_i, for_loop_index, func_depth;

    uint16_t * locals_reg, * caps_reg, * locals_reg_stack[1024], * caps_reg_stack[1024];
    
    uint32_t loop_nesting, loop_cont_i, loop_break_i, loop_conts[1024], loop_breaks[1024], stackpos[1024];
} CompilerState;

CompilerState * cs;
void compiler_state_init(void)
{
    cs = (CompilerState *)zalloc(sizeof(CompilerState));
    *cs = FI_LIT(CompilerState) { {}, {}, {}, IDENTIFIER_COUNT, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, {}, {}, 0, 0, 0, {}, {}, {} };
}

//#define COMP_SPUSH ( assert(((void)"Stack exceeded limit.", cs->stackpos[cs->func_depth] < 1024)), cs->stackpos[cs->func_depth]++ )
#define COMP_SPUSH ( assert3(((void)"Stack exceeded limit.", cs->stackpos[cs->func_depth] < 1024)), (cs->stackpos[cs->func_depth] += (cs->stackpos[cs->func_depth] < 1024)) - 1 )
#define COMP_S cs->stackpos[cs->func_depth]
#define COMP_SPOP ( assert(cs->stackpos[cs->func_depth] != 0), --cs->stackpos[cs->func_depth] )

// returns number of consumed tokens
size_t compile_value(const char * source, Token * tokens, size_t count, uint32_t i)
{
    if (i >= count) return 0;
    
    if (token_is(source, tokens, count, i, "{}")) return prog_write2(PUSH_DICT_EMPTY, COMP_SPUSH), 1;
    
    if (tokens[i].kind > 1) return 0;
    if (tokens[i].kind < 0 && tokens[i].kind >= -lex_ident_offset) return 0;
    
    if (tokens[i].kind < 0)
    {
        uint16_t id = lex_ident_offset - tokens[i].kind;
        if (token_is(source, tokens, count, i, "true"))         return prog_write6(PUSH_NUM, 0, 0, 0, 0x3FF0, COMP_SPUSH), 1;
        else if (token_is(source, tokens, count, i, "false"))   return prog_write6(PUSH_NUM, 0, 0, 0, 0, COMP_SPUSH), 1;
        else if (token_is(source, tokens, count, i, "null"))    return prog_write2(PUSH_NULL, COMP_SPUSH), 1;
        else if (cs->func_depth > 0 && cs->locals_reg[id])      prog_write3(PUSH_LOCAL, cs->locals_reg[id] - 1, COMP_SPUSH);
        else if (cs->func_depth > 0 && cs->caps_reg[id])        prog_write3(PUSH_CAP, cs->caps_reg[id] - 1, COMP_SPUSH);
        else if (cs->globals_reg[id])                           prog_write3(PUSH_GLOBAL, cs->globals_reg[id] - 1, COMP_SPUSH);
        else if (cs->funcs_reg[id].exists)                      prog_write3(PUSH_FUNCNAME, id, COMP_SPUSH);
        else
        {
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic2(0, "Unknown identifier");
        }
    }
    else if (tokens[i].kind == 1)
    {
        assert2(0, tokens[i].len >= 2, "Invalid string literal");
        size_t l = tokens[i].len - 2;
        const char * sold = source + tokens[i].i + 1;
        char * s = stringdupn(sold, l);
        size_t j = 0;
        for (size_t i = 0; i < l; i++)
        {
            if      (sold[i] == '\\' && sold[i+1] ==  '"' && ++i)   s[j++] = '"';
            else if (sold[i] == '\\' && sold[i+1] == '\\' && ++i)   s[j++] = '\\';
            else if (sold[i] == '\\' && sold[i+1] ==  'r' && ++i)   s[j++] = '\r';
            else if (sold[i] == '\\' && sold[i+1] ==  'n' && ++i)   s[j++] = '\n';
            else if (sold[i] == '\\' && sold[i+1] ==  't' && ++i)   s[j++] = '\t';
            else s[j++] = sold[i];
        }
        s[j] = 0;
        cs->compiled_strings[cs->compiled_string_i] = s;
        prog_write3(PUSH_STRING, cs->compiled_string_i++, COMP_SPUSH);
        assert2(0, cs->compiled_string_i < (1<<16), "Too many string literals used in prog.code, limit is 65k");
    }
    else if (tokens[i].kind == 0)
    {
        char * s = stringdupn(source + tokens[i].i, tokens[i].len);
        double f = badstrtod(s);
        free(s);
        
        prog_write6(PUSH_NUM, 0, 0, 0, 0, COMP_SPUSH);
        memcpy(prog.code + (prog.i - 5), &f, 8);
    }
    
    return 1;
}

#define PARSE_COMMALIST(END, BREAK, BREAK2, LIMITER, HANDLER)\
    uint32_t j = 0;\
    while (!token_is(source, tokens, count, i, END)) {\
        LIMITER; HANDLER; j += 1;\
        if (!(token_is(source, tokens, count, i, END) || token_is(source, tokens, count, i, ","))) BREAK;\
        if (token_is(source, tokens, count, i, ",")) i++;\
    } if (!token_is(source, tokens, count, i++, END)) BREAK2;

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power);
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i);

void compile_func_start(void)
{
    cs->locals_reg_stack[cs->locals_reg_i++] = cs->locals_reg;
    cs->locals_reg = (uint16_t *)zalloc(sizeof(uint16_t) * IDENTIFIER_COUNT);
    cs->caps_reg_stack[cs->caps_reg_i++] = cs->caps_reg;
    cs->caps_reg = (uint16_t *)zalloc(sizeof(uint16_t) * IDENTIFIER_COUNT);
    assert2(, cs->caps_reg_i < 1024 && cs->locals_reg_i < 1024);
}
void compile_func_end(void)
{
    free(cs->locals_reg);
    cs->locals_reg = cs->locals_reg_stack[--cs->locals_reg_i];
    free(cs->caps_reg);
    cs->caps_reg = cs->caps_reg_stack[--cs->caps_reg_i];
}
size_t compile_lambda(const char * source, Token * tokens, size_t count, size_t i, int16_t * caps, uint16_t caps_count);

size_t compile_innerexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    if (token_is(source, tokens, count, i, "lambda"))
    {
        size_t orig_i = i++;
        
        if (!token_is(source, tokens, count, i++, "[")) return 0;
        int16_t * caps = (int16_t *)zalloc(sizeof(int16_t) * CAPTURELIMIT);
        uint16_t * caps_reg_next = (uint16_t *)zalloc(sizeof(uint16_t) * IDENTIFIER_COUNT);
        PARSE_COMMALIST("]", return 0, return 0, assert2(0, j < CAPTURELIMIT),
            if (tokens[i].kind >= -lex_ident_offset) return 0;
            int16_t id = lex_ident_offset - tokens[i++].kind;
            int16_t accessor_id = 0;
            if      (cs->func_depth > 0 && cs->locals_reg[id])   accessor_id = cs->locals_reg[id] - 1;
            else if (cs->func_depth > 0 && cs->caps_reg  [id])   accessor_id = cs->caps_reg[id] - 1;
            else
            {
                printsn(source + tokens[i - 1].i, tokens[i - 1].len);
                prints("\n");
                panic2(0, "Unable to capture identifier");
            }
            caps[j] = accessor_id;
            caps_reg_next[id] = j + 1;
        )
        
        uint32_t prev_locals_n = cs->locals_n;
        cs->locals_n = 0;
        compile_func_start();
        
        memcpy(cs->caps_reg, caps_reg_next, sizeof(uint16_t) * IDENTIFIER_COUNT);
        size_t r = compile_lambda(source, tokens, count, i, caps, j);
        assert2(0, r != 0, "Lambda body is invalid");
        
        compile_func_end();
        cs->locals_n = prev_locals_n;
        
        return i + r - orig_i;
    }
    if (token_is(source, tokens, count, i, "(")) // wrapped expr
    {
        size_t start_prog_i = prog.i;
        size_t ret = compile_expr(source, tokens, count, i+1, 0) + 1;
        assert2(0, token_is(source, tokens, count, i + ret, ")"), "Unclosed parens");
        assert2(0, prog.i != start_prog_i, "Paren expressions must not be empty");
        return ret + 1;
    }
    if (token_is(source, tokens, count, i, "[")) // array literal
    {
        size_t orig_i = i++; // skip [
        
        PARSE_COMMALIST("]", return 0, return 0, assert2(0, j < 32000, "Too many values in array literal"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0; else i += r;
        )
        for (size_t i = 0; i < j; i++) COMP_SPOP;
        prog_write3(INST_ARRAY_LITERAL, j, COMP_SPUSH);
        
        return i - orig_i;
    }
    return compile_value(source, tokens, count, i++);
}

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power)
{
    size_t ret = compile_innerexpr(source, tokens, count, i);
    if (ret == 0) return 0; else i += ret;
    
    while (i < count && right_bind_power < tokenop_bindlevel(source, tokens, count, i))
    {
        size_t r = compile_binexpr(source, tokens, count, i);
        ret += r;
        if (r == 0) break; else i += r;
    }
    
    return ret;
}
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count || filli_err) return 0;
    int binding_power = tokenop_bindlevel(source, tokens, count, i);
    if (binding_power < 0) return 0;
    
    // func calls
    if (token_is(source, tokens, count, i, "("))
    {
        size_t orig_i = i++; // skip (
        PARSE_COMMALIST(")",  return 0, return 0, assert2(0, j < ARGLIMIT, "Too many arguments to function"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0; else i += r;
        )
        for (size_t i = 0; i < j; i++) COMP_SPOP;
        COMP_SPOP;
        prog_write3(INST_FUNCCALL_REF, j, COMP_SPUSH);
        return i - orig_i;
    }
    
    size_t r = compile_expr(source, tokens, count, i + 1, binding_power < 50 ? binding_power : 0);
    if (r == 0) return 0;
    
    if (token_is(source, tokens, count, i, "["))
    {
        i += ++r;
        assert2(0, token_is(source, tokens, count, i++, "]"));
        COMP_SPOP;
        COMP_SPOP;
        prog_write2(INST_INDEX, COMP_SPUSH);
        return r + 1;
    }
    
    const char * ops[] = {"-", "/", "+", "*", "%", "and", "or", "==", "!=", ">=", "<=", ">", "<", "&", "|", "^"};
    const uint16_t opcodes[] = {INST_SUB, INST_DIV, INST_ADD, INST_MUL, INST_INTMOD, INST_CMP_AND, INST_CMP_OR,
        INST_CMP_EQ, INST_CMP_NE, INST_CMP_GE, INST_CMP_LE, INST_CMP_GT, INST_CMP_LT, INST_BITAND, INST_BITOR, INST_BITXOR};
    
    for (size_t j = 0; i < count && j < sizeof(ops) / sizeof(ops[0]); j++)
        if (token_is(source, tokens, count, i, ops[j])) { prog_write2(opcodes[j], COMP_SPOP - 1); return r + 1; }
    
    printsn(source + tokens[i].i, tokens[i].len);
    prints("\n");
    panic2(0, "Unknown infix operator");
}


size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i);

size_t compile_statement(const char * source, Token * tokens, size_t count, size_t i)
{
    repanic(0)
    if (i >= count) return 0;
    size_t orig_i = i;
    if (tokens[i].kind == -1) // if
    {
        size_t r = compile_expr(source, tokens, count, i + 1, 0);
        i += r + 1;
        assert2(0, token_is(source, tokens, count, i++, ":") && r != 0, "Conditions must not be empty");
        prog_write4(INST_JMP_IF_FALSE, 0, 0, COMP_SPOP);
        size_t jump_at = prog.i - 3;
        
        i += compile_statementlist(source, tokens, count, i);
        
        uint32_t end = prog.i + ((tokens[i].kind == -3 || tokens[i].kind == -2) ? 3 : 0);
        memcpy(prog.code + jump_at, &end, 4);
        
        uint32_t skips[ELIFLIMIT] = {};
        size_t skip_i = 0;
        
        while (tokens[i].kind == -3 || tokens[i].kind == -2) // elif, else
        {
            // add on to previous block: skip this and the rest of the blocks
            prog_write3(INST_JMP, 0, 0);
            skips[skip_i++] = prog.i - 2;
            assert2(0, skip_i < ELIFLIMIT-1, "Too many elifs in if-else chain");
            
            if (tokens[i].kind == -3) // elif
            {
                size_t r = compile_expr(source, tokens, count, i + 1, 0);
                i += r + 1;
                assert2(0, token_is(source, tokens, count, i++, ":") && r != 0, "Conditions must not be empty");
                prog_write4(INST_JMP_IF_FALSE, 0, 0, COMP_SPOP);
                size_t jump_at = prog.i - 3;
                
                i += compile_statementlist(source, tokens, count, i);
                
                uint32_t end = prog.i + ((tokens[i].kind == -3 || tokens[i].kind == -2) ? 3 : 0);
                memcpy(prog.code + jump_at, &end, 4);
            }
            else
            {
                assert2(0, token_is(source, tokens, count, ++i, ":"), "Expected ':'");
                i += compile_statementlist(source, tokens, count, i + 1) + 1;
            }
        }
        assert2(0, tokens[i].kind == -11, "Expected 'end'");
        uint32_t real_end = prog.i;
        while (skip_i > 0) memcpy(prog.code + skips[--skip_i], &real_end, 4);
        return i + 1 - orig_i;
    }
    if (tokens[i].kind == -5) // while
    {
        cs->loop_nesting++;
        size_t loop_cont_base = cs->loop_cont_i;
        size_t loop_break_base = cs->loop_break_i;
        
        size_t expr_i = i + 1;
        size_t r = compile_expr(source, tokens, count, expr_i, 0);
        i += r + 1;
        assert2(0, token_is(source, tokens, count, i++, ":") && r != 0, "Conditions must not be empty");
        prog_write4(INST_JMP_IF_FALSE, 0, 0, COMP_SPOP);
        size_t skip_at = prog.i - 3;
        uint32_t loop_at = prog.i;
        
        i += compile_statementlist(source, tokens, count, i);
        assert2(0, i < count && tokens[i].kind == -11, "Expected 'end'"); // end
        
        uint32_t cont_to = prog.i;
        compile_expr(source, tokens, count, expr_i, 0); // recompile test expr
        prog_write4(INST_JMP_IF_TRUE, 0, 0, COMP_SPOP);
        memcpy(prog.code + (prog.i - 3), &loop_at, 4);
        
        uint32_t end = prog.i;
        memcpy(prog.code + skip_at, &end, 4);
        
        uint32_t break_to = prog.i;
        while (cs->loop_break_i > loop_break_base) memcpy(prog.code + cs->loop_breaks[--cs->loop_break_i], &break_to, 4);
        while (cs->loop_cont_i  > loop_cont_base ) memcpy(prog.code + cs->loop_conts [--cs->loop_cont_i ], &cont_to , 4);
        cs->loop_nesting--;
        
        return i + 1- orig_i;
    }
    else if (token_is(source, tokens, count, i, "let"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        
        if (cs->func_depth == 0) cs->globals_reg[id] = ++cs->globals_n;
        else                     cs->locals_reg [id] = ++cs->locals_n;
        assert2(0, cs->globals_n < FRAME_VARCOUNT && cs->locals_n < FRAME_VARCOUNT, "Too many variables");
        
        if (token_is(source, tokens, count, i, "="))
        {
            size_t r = compile_expr(source, tokens, count, i + 1, 0);
            if (!r) return i - orig_i;
            i += r + 1;
            prog_write3(INST_SET + (cs->func_depth == 0), (cs->func_depth == 0) ? cs->globals_n - 1 : cs->locals_n - 1, COMP_SPOP);
        }
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "for"))
    {
        if (++i >= count) return 0;
        
        cs->loop_nesting++;
        size_t loop_cont_base = cs->loop_cont_i;
        size_t loop_break_base = cs->loop_break_i;
        
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (cs->func_depth == 0) cs->globals_reg[id] = ++cs->globals_n;
        else                     cs->locals_reg [id] = ++cs->locals_n;
        uint16_t idnum = (cs->func_depth == 0) ? cs->globals_n - 1 : cs->locals_n - 1;
        assert2(0, cs->globals_n < FRAME_VARCOUNT && cs->locals_n < FRAME_VARCOUNT, "Too many variables");
        assert2(0, token_is(source, tokens, count, i++, "in"), "Expected 'in'");
        uint16_t idx = cs->for_loop_index++;
        assert2(0, idx < FORLOOP_COUNT_LIMIT, "Too many for loops");
        
        size_t r = compile_expr(source, tokens, count, i, 0);
        i += r;
        assert2(0, token_is(source, tokens, count, i++, ":") && r > 0, "For loop requires valid expression");
        
        prog_write6(INST_FORSTART, idnum, idx, 0, 0, COMP_SPOP);
        
        uint32_t head = prog.i;
        
        i += compile_statementlist(source, tokens, count, i);
        assert2(0, tokens[i++].kind == -11, "Expected 'end'");
        
        uint32_t cont_to = prog.i;
        prog_write5(INST_FOREND, idnum, idx, 0, 0);
        memcpy(prog.code + (prog.i - 2), &head, 4);
        
        uint32_t end = prog.i;
        memcpy(prog.code + (head - 3), &end, 4);
        
        uint32_t break_to = prog.i;
        while (cs->loop_break_i > loop_break_base) memcpy(prog.code + cs->loop_breaks[--cs->loop_break_i], &break_to, 4);
        while (cs->loop_cont_i  > loop_cont_base ) memcpy(prog.code + cs->loop_conts [--cs->loop_cont_i ], &cont_to , 4);
        cs->loop_nesting--;
        
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
        && (token_is(source, tokens, count, i+1, "=")
            || token_is(source, tokens, count, i+1, "+=") || token_is(source, tokens, count, i+1, "-=")
            || token_is(source, tokens, count, i+1, "*=") || token_is(source, tokens, count, i+1, "/=")))
    {
        int16_t id = lex_ident_offset - tokens[i++].kind;
        
        const char * opstr = stringdupn(source + tokens[i].i, tokens[i].len);
        size_t oplen = tokens[i++].len;
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert2(0, ret > 0, "Assignment requires valid expression");
        i += ret;
        
        uint8_t mode = 10;
        if (cs->func_depth > 0 && cs->locals_reg[id]) mode = 0;
        else if (cs->func_depth > 0 && cs->caps_reg[id]) mode = 2;
        else if (cs->globals_reg[id]) mode = 1;
        else panic2(0, "Unknown variable");
        
        if (strncmp(opstr, "=", oplen) == 0)       prog_write(INST_SET + mode);
        else if (strncmp(opstr, "+=", oplen) == 0) prog_write(INST_SET_ADD + mode);
        else if (strncmp(opstr, "-=", oplen) == 0) prog_write(INST_SET_SUB + mode);
        else if (strncmp(opstr, "*=", oplen) == 0) prog_write(INST_SET_MUL + mode);
        else if (strncmp(opstr, "/=", oplen) == 0) prog_write(INST_SET_DIV + mode);
        
        prog_write2((mode == 0 ? cs->locals_reg[id] : mode == 1 ? cs->globals_reg[id] : cs->caps_reg[id]) - 1, COMP_SPOP);
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
             && token_is(source, tokens, count, i+1, "(")
             && cs->funcs_reg[lex_ident_offset - tokens[i].kind].exists)
    {
        uint16_t id = lex_ident_offset - tokens[i++].kind;
        i += 1; // (
        
        PARSE_COMMALIST(")", return 0, return 0, assert2(0, j < ARGLIMIT, "Too many arguments to function"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0; else i += r;
        )
        
        for (size_t i = 0; i < j; i++) (void)COMP_SPOP;
        prog_write4(INST_FUNCCALL, id, j, COMP_S);
        
        return i - orig_i;
    }
    else if (tokens[i].kind == -11 || tokens[i].kind == -3 || tokens[i].kind == -2) // end, elif, else
        return i - orig_i;
    else if (token_is(source, tokens, count, i, "\n") || token_is(source, tokens, count, i, ";"))
        return 1;
    else if (token_is(source, tokens, count, i, "continue") || token_is(source, tokens, count, i, "break"))
    {
        assert2(0, cs->loop_nesting > 0, "Tried to use break/continue outside of loop");
        prog_write3(INST_JMP, 0, 0);
        if (token_is(source, tokens, count, i, "continue"))
            cs->loop_conts[cs->loop_cont_i++] = prog.i - 2;
        else
            cs->loop_breaks[cs->loop_break_i++] = prog.i - 2;
        return 1;
    }
    else if (token_is(source, tokens, count, i, "return"))
    {
        size_t r = compile_expr(source, tokens, count, ++i, 0);
        if (r == 0) prog_write(INST_RETURN_VOID);
        else        prog_write2(INST_RETURN_VAL, COMP_SPOP);
        return r + 1;
    }
    else if (token_is(source, tokens, count, i, "yield"))
    {
        size_t r = compile_expr(source, tokens, count, ++i, 0);
        if (r == 0) prog_write3(PUSH_NULL, INST_YIELD, COMP_S);
        else        prog_write2(INST_YIELD, COMP_SPOP);
        return r + 1;
    }
    else
    {
        size_t r = compile_expr(source, tokens, count, i, 0);
        if (r == 0)
        {
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic2(0, "Unrecognized expression or statement");
        }
        i += r;
        
        if (prog.i >= 2 && prog.code[prog.i - 2] == INST_INDEX && (token_is(source, tokens, count, i, "=")
             || token_is(source, tokens, count, i, "+=") || token_is(source, tokens, count, i, "-=")
             || token_is(source, tokens, count, i, "*=") || token_is(source, tokens, count, i, "/=")))
        {
            size_t old_i = i;
            uint32_t checkpoint = prog.i - 2;
            size_t r2 = compile_expr(source, tokens, count, i + 1, 0);
            if (!r2) { COMP_SPOP; return r; }
            r += r2 + 1;
            prog.code[checkpoint] = INST_INDEX_LOC;
            if (token_is(source, tokens, count, old_i, "=" )) prog_write2(INST_SET_LOC, COMP_SPOP);
            if (token_is(source, tokens, count, old_i, "+=")) prog_write2(INST_SET_LOC_ADD, COMP_SPOP);
            if (token_is(source, tokens, count, old_i, "-=")) prog_write2(INST_SET_LOC_SUB, COMP_SPOP);
            if (token_is(source, tokens, count, old_i, "*=")) prog_write2(INST_SET_LOC_MUL, COMP_SPOP);
            if (token_is(source, tokens, count, old_i, "/=")) prog_write2(INST_SET_LOC_DIV, COMP_SPOP);
            COMP_SPOP;
        }
        else { COMP_SPOP; }
        return r;
    }
}
size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    while (1)
    {
        if (i >= count) return i - orig_i;
        size_t r = compile_statement(source, tokens, count, i);
        if (r == 0) return i - orig_i; else i += r;
    }
}

size_t closure_count = 0;

size_t compile_register_func(const char * source, Token * tokens, size_t count, uint16_t id, uint32_t i)
{
    cs->func_depth++;
    cs->stackpos[cs->func_depth] = 0;
    
    size_t orig_i = i;
    
    if (!token_is(source, tokens, count, i++, "(")) panic2(0, "Invalid funcdef");
    uint16_t args[ARGLIMIT];
    PARSE_COMMALIST(")", panic2(0, "Invalid funcdef"), panic2(0, "Invalid funcdef"),
                    assert2(0, j < ARGLIMIT, "Too many arguments to function"),
        if (tokens[i].kind >= -lex_ident_offset) panic2(0, "Invalid funcdef");
        args[j] = lex_ident_offset - tokens[i++].kind;
        cs->locals_reg[args[j]] = ++cs->locals_n;
    )
    if (!token_is(source, tokens, count, i++, ":")) panic2(0, "Invalid funcdef");
    
    cs->funcs_reg[id] = FI_LIT(Funcdef) {1, 0, 0, (uint16_t)j, id, 0, 0, prog.i, 0, 0};
    if (j > 0)
    {
        cs->funcs_reg[id].args = (uint16_t *)zalloc(sizeof(uint16_t)*j);
        memcpy(cs->funcs_reg[id].args, args, j * sizeof(uint16_t));
    }
    
    size_t closure_count_start = closure_count;
    
    i += compile_statementlist(source, tokens, count, i);
    prog_write(INST_RETURN_VOID);
    cs->func_depth--;
    assert2(0, tokens[i++].kind == -11, "Expected 'end'");
    assert(cs->stackpos[cs->func_depth + 1] == 0);
    
    if (closure_count == closure_count_start)
        cs->funcs_reg[id].poolsafe = 1;
    
    return i - orig_i;
}

size_t compile_func(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    if (tokens[i].kind >= -lex_ident_offset) return 0;
    int16_t id = lex_ident_offset - tokens[i++].kind;
    
    prog_write3(INST_FUNCDEF, 0, 0);
    size_t len_offs = prog.i - 2;
    
    size_t r = compile_register_func(source, tokens, count, id, i);
    if (!r) return 0; i += r;
    
    memcpy(prog.code + len_offs, &prog.i, 4);
    
    return i - orig_i;
}
size_t compile_lambda(const char * source, Token * tokens, size_t count, size_t i, int16_t * caps, uint16_t caps_count)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    uint32_t id = cs->lambda_id++;
    
    prog_write6(INST_LAMBDA, 0, 0, 0, 0, COMP_SPUSH);
    size_t id_offs = prog.i - 5;
    memcpy(prog.code + id_offs, &id, 4);
    
    size_t r = compile_register_func(source, tokens, count, id, i);
    if (!r) return 0; i += r;
    
    cs->funcs_reg[id].caps = caps;
    cs->funcs_reg[id].cap_count = caps_count;
    
    if (caps_count > 0) closure_count += 1;
    
    memcpy(prog.code + id_offs + 2, &prog.i, 4);
    
    return i - orig_i;
}
size_t compile(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t r, orig_i = i;
    while (i < count)
    {
        repanic(0)
        if (tokens[i].kind == -4) // func
        {
            cs->locals_n = 0;
            compile_func_start();
            r = compile_func(source, tokens, count, i+1);
            assert2(0, r != 0, "Incomplete function");
            compile_func_end();
            i += r + 1;
        }
        else if ((r = compile_statement(source, tokens, count, i))) i += r;
        else
        {
            prints("AT: "); printsn(source + tokens[i].i, tokens[i].len); prints("\n"); panic2(0, "Expected function or statement");
            break;
        }
    }
    prog_write(INST_RETURN_VOID);
    return i - orig_i;
}

struct _BiValue;
typedef struct _Array { struct _Value * buf; size_t len; size_t cap; } Array;
typedef struct _Dict { struct _BiValue * buf; size_t len; size_t cap; size_t tombs; } Dict;

struct _Frame;

// tag
enum { VALUE_NULL, VALUE_INVALID, VALUE_FLOAT, VALUE_ARRAY, VALUE_DICT, VALUE_STRING, VALUE_FUNC, VALUE_STATE, VALUE_TOMBSTONE = 0x7F, };

typedef struct _Value {
    union { double f; Array * a; Dict * d; char ** s; Funcdef * fn; struct _FState * fs; } u;
    // suppress 128-bit copy optimizations; they kill store-load forwarding on current hardware
    uint32_t _unused_opt_killer;
    uint8_t tag;
} Value;
typedef struct _BiValue { struct _Value l; struct _Value r; } BiValue;

Value val_tagged(uint8_t tag) { Value v; memset(&v, 0, sizeof(Value)); v.tag = tag; return v; }
Value val_float(double f) { Value v = val_tagged(VALUE_FLOAT); v.u.f = f; return v; }
Value val_string(char * s) { Value v = val_tagged(VALUE_STRING); v.u.s = (char **)zalloc(sizeof(char *)); *v.u.s = s; return v; }
Value val_func(uint16_t id) { Value v = val_tagged(VALUE_FUNC); v.u.fn = &cs->funcs_reg[id]; return v; }

typedef struct _FState { Funcdef * fn; struct _Frame * frame; } FState;
FState * new_fstate(Funcdef * fn) { FState * r = (FState *)zalloc(sizeof(FState)); r->fn = fn; return r; }
Value val_funcstate(Funcdef * fn, struct _Frame * frame) { Value v = val_tagged(VALUE_STATE); v.u.fs = new_fstate(fn); v.u.fs->frame = frame; return v; }

Value val_array(size_t n) { Value v = val_tagged(VALUE_ARRAY); v.u.a = (Array *)zalloc(sizeof(Array));
    *v.u.a = FI_LIT(Array) { (Value *)zalloc(sizeof(Value) * n), n, n }; return v; }

Value * array_get(Array * a, size_t i) { assert2(0, i < a->len); return a->buf + i; }

int8_t val_cmp(Value v1, Value v2)
{
    // -1: less than
    //  0: equal
    //  1: greater than
    //  2: unordered-and-unequal
    if (v2.tag != v1.tag || (v1.tag == VALUE_FLOAT && (v1.u.f != v1.u.f || v2.u.f != v2.u.f))) return 2;
    else if (v1.tag == VALUE_FLOAT && v1.u.f < v2.u.f) return -1;
    else if (v1.tag == VALUE_FLOAT && v1.u.f > v2.u.f) return 1;
    else if (v1.tag == VALUE_STRING) return v1.u.s == v2.u.s ? 0 : strcmp(*v1.u.s, *v2.u.s);
    else if ((v1.tag == VALUE_ARRAY && v1.u.a != v2.u.a) || (v1.tag == VALUE_DICT && v1.u.d != v2.u.d)) return 2;
    else if ((v1.tag == VALUE_FUNC && v1.u.f != v2.u.f) || (v1.tag == VALUE_STATE && v1.u.fs != v2.u.fs)) return 2;
    return 0;
}


uint64_t double_bits_safe(double f) { if (f == 0.0) return 0; uint64_t n = 0; memcpy(&n, &f, 8); return n; }
uint64_t val_hash(Value * v)
{
    assert2(0, v->tag == VALUE_STRING || v->tag == VALUE_FLOAT || v->tag == VALUE_FUNC || v->tag == VALUE_NULL,
           "Tried to use an unhashable type (dict or array) as a dict key");
    uint64_t hash = 0;
    uint64_t hv = 0xf6f1029eab913ac5;
    
    hash = (hash + v->tag) * hv;
    if (v->tag == VALUE_FLOAT)  hash = (hash + double_bits_safe(v->u.f)) * hv;
    else if (v->tag == VALUE_STRING) for (size_t i = 0; (*v->u.s)[i] != 0; i++) hash = (hash + (*v->u.s)[i]) * hv;
    else if (v->tag == VALUE_FUNC)   hash = (hash + v->u.fn->id) * hv;
    
    return hash ^ (hash >> 6);
}

// newcap must be a power of 2
void dict_reallocate(Dict * d, size_t newcap)
{
    BiValue * newbuf = (BiValue *)zalloc(sizeof(BiValue) * newcap);
    for (size_t i = 0; i < newcap; i++)
        newbuf[i] = FI_LIT(BiValue) { val_tagged(VALUE_INVALID), val_tagged(VALUE_INVALID) };
    for (size_t i = 0; i < d->cap; i++)
    {
        if (d->buf[i].l.tag == VALUE_TOMBSTONE || d->buf[i].l.tag == VALUE_INVALID) continue;
        uint64_t hash = val_hash(&d->buf[i].l) & (newcap - 1);
        while (newbuf[hash].l.tag != VALUE_INVALID && val_cmp(d->buf[i].l, newbuf[hash].l) != 0) hash = (hash + 1) & (d->cap - 1);
        newbuf[hash] = FI_LIT(BiValue) { d->buf[i].l, d->buf[i].r };
    }
    d->tombs = 0;
    d->cap = newcap;
    d->buf = newbuf;
}
// Open-addressing hashmap that uses tombstones for deletion.
BiValue * dict_get_or_insert(Dict * d, Value v)
{
    if (d->cap == 0) dict_reallocate(d, 8);
    // max 50% load factor
    if ((d->len + 1 + d->tombs) * 2 > d->cap) dict_reallocate(d, d->cap * 2);
    
    uint64_t hash = val_hash(&v) & (d->cap - 1);
    while (d->buf[hash].l.tag != VALUE_INVALID && val_cmp(v, d->buf[hash].l) != 0) hash = (hash + 1) & (d->cap - 1);
    if (d->buf[hash].l.tag == VALUE_INVALID) 
    {
        d->len++;
        d->buf[hash] = FI_LIT(BiValue) { v, val_tagged(VALUE_NULL) };
    }
    return &d->buf[hash];
}

uint8_t val_truthy(Value v)
{
    if (v.tag == VALUE_FLOAT)   return v.u.f != 0.0;
    if (v.tag == VALUE_STRING)  return (*v.u.s)[0] != 0;
    if (v.tag == VALUE_ARRAY)   return v.u.a->len > 0;
    if (v.tag == VALUE_DICT)    return v.u.d->len > 0;
    if (v.tag == VALUE_FUNC)    return 1;
    return 0;
}

    // deliberately do not store _unused_opt_killer, to suppress bad optimizations
__attribute__((always_inline)) static inline void value_store(Value * p, Value v) { p->tag = v.tag; p->u = v.u; }

typedef struct _LoopPair { uint64_t l; uint64_t r; } LoopPair;

typedef struct _Frame {
    uint32_t pc, return_slot;
    struct _Frame * return_to;
    Value * set_tgt_agg;
    char * set_tgt_char;
    Value vars[FRAME_VARCOUNT], stack[FRAME_STACKSIZE];
    LoopPair forloops[FORLOOP_COUNT_LIMIT];
    Value ** caps;
    Funcdef * fn;
} Frame;

void print_op_and_panic(uint16_t op) { prints("---\n"); printu16hex(op); prints("\n---\n"); panic2(, "Unknown operation"); }

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame, size_t stackpos, size_t return_slot);

Frame * framepool = 0;
Frame * framepoolpop(void) { Frame * ret = framepool; framepool = framepool->return_to; ret->return_to = 0; return ret; }
void framepoolpush(Frame * frame) { memset(frame, 0, sizeof(Frame)); frame->return_to = framepool; framepool = frame; }

#if USE_TAIL_DISPATCH
#define INSTX(X)  static size_t _handler_##X(Program * prog, void * _ops, size_t pc, uint16_t * code, Frame *, Frame *);
INST_XMACRO()
#undef INSTX
#endif

typedef  size_t (*handler)(Program * prog, void * _ops, size_t pc, uint16_t * code, Frame * frame, Frame * global_frame);
static handler ops[0x100] = {};

uint32_t fi_mem_read_u32(void * from) { uint32_t n; memcpy(&n, from, 4); return n; }
double fi_mem_read_f64(void * from) { double f; memcpy(&f, from, 8); return f; }

size_t _to_pc = 0;
size_t interpret(size_t from_pc)
{
    Frame * frame = (Frame *)zalloc(sizeof(Frame));
    Frame * global_frame = frame;
    
    frame->pc = from_pc;

#if USE_TAIL_DISPATCH
    
    // Tail-call "threaded" dispatch is an interpreter design technique where opcode handlers are functions that
    //  jump directly to the next opcode instead of returning to a handler. This suppresses code-sharing optimizations
    //  that can cause the compiler to generate code that thrashes the branch predictor, and also forces each dispatch
    //  to depend on which opcode it's coming from. This allows the CPU's branch predictor to learn that, for example,
    //  a particular opcode is almost always followed by a particular other opcode, and to always predict that other
    //  opcode when proceeding from the first one.
    
    // To avoid code duplication, we use macros to swap out the dispatch system, instead of hardcoding both systems.
    
    for (size_t i = 0; i < 0x100; i++) ops[i] = _handler_INST_INVALID;
    
    #define INSTX(X) ops[(X&0xFF)] = _handler_##X;
    INST_XMACRO()
    
    #define CASES_START() uint16_t op = prog.code[frame->pc]; return ops[op & 0xFF](&prog, (void *) ops, frame->pc, prog.code, frame, global_frame);
    #define CASES_END()
    
    #define PC_INC() frame->pc += op >> 8; pc = frame->pc; op = code[pc];
    
    #define MARK_CASE(X) }  static size_t _handler_##X(Program * prog, void * _ops, size_t pc, uint16_t * code, Frame * frame, Frame * global_frame) { uint16_t op = X; repanic(frame->pc); handler * ops = (handler *)_ops; _to_pc = frame->pc;
    #define END_CASE() PC_INC(); __attribute__((musttail)) return ops[op & 0xFF](prog, _ops, pc, code, frame, global_frame);
    #define DECAULT_CASE()
    
    #define DISPATCH_IMMEDIATELY() op = code[pc]; __attribute__((musttail)) return ops[op & 0xFF](prog, _ops, pc, code, frame, global_frame);
#else
    
    // This, on the other hand, is a conventional loop-over-switch-statement interpreter dispatch system.
    
    #define CASES_START() \
    while (frame->pc < prog.i) { repanic(frame->pc); uint16_t op = prog.code[frame->pc]; size_t pc = frame->pc; (void)pc; uint16_t * code = prog.code; (void)code; switch (op) {
    #define CASES_END() } } return frame->pc;
    
    #define PC_INC() { frame->pc += op >> 8; pc = frame->pc; }
    
    #define MARK_CASE(X) case X: {
    #define END_CASE() PC_INC(); continue; }
    #define DECAULT_CASE() default: print_op_and_panic(op);
    
    #define DISPATCH_IMMEDIATELY() continue
#endif 
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)

    CASES_START()
        #define READ_AND_GOTO_TARGET(X)\
            { uint32_t target = fi_mem_read_u32(code + (pc + X)); frame->pc = target; pc = target; DISPATCH_IMMEDIATELY(); }
        
        MARK_CASE(INST_INVALID)     { panic("sdfakarwiu"); }
        NEXT_CASE(INST_FUNCDEF)     READ_AND_GOTO_TARGET(1)
        
        #define PROG_IDX(X) code[pc + (X)]
        #define STACK_PUSH(X, Y) { value_store(&frame->stack[PROG_IDX(X)], (Y)); }
        
        NEXT_CASE(INST_ARRAY_LITERAL)
            uint16_t itemcount = PROG_IDX(1);
            Value v = val_array(itemcount);
            for (size_t i = 0; i < itemcount; i++) v.u.a->buf[i] = frame->stack[PROG_IDX(2) + i];
            STACK_PUSH(2, v)
        
        #define ENTER_FUNC(IDX, RETURN_SLOT, FORCED)\
            uint32_t idx = (IDX); uint32_t return_slot = (RETURN_SLOT);\
            assert2(0, fn->exists, "Function does not exist");\
            if (!fn->intrinsic) {\
                PC_INC(); Frame * prev = frame;\
                Frame * next = (FORCED) ? (FORCED) : \
                    (fn->poolsafe && framepool) ? framepoolpop() : (Frame *)zalloc(sizeof(Frame));\
                next->fn = fn;\
                next->return_to = frame;\
                frame->return_slot = return_slot;\
                frame = next;\
                pc = frame->pc;\
                assert2(0, argcount == fn->argcount, "Function arg count doesn't match");\
                if (!(FORCED)) for (size_t i = 0; i < fn->argcount; i++) {\
                    frame->vars[i] = prev->stack[idx + i]; Value * v = &frame->vars[i];\
                    if (v->tag == VALUE_STRING) { char ** ss = (char **)zalloc(sizeof(char *)); *ss = *v->u.s; v->u.s = ss; } }\
                if (!(FORCED)) { frame->pc = fn->loc; pc = fn->loc; if (fn->cap_data) frame->caps = fn->cap_data; }\
                DISPATCH_IMMEDIATELY(); }\
            handle_intrinsic_func(fn->id, argcount, frame, idx, return_slot); // intrinsics
        
        NEXT_CASE(INST_FUNCCALL)
            uint16_t argcount = PROG_IDX(2);
            Funcdef * fn = &cs->funcs_reg[PROG_IDX(1)];
            ENTER_FUNC(PROG_IDX(3), PROG_IDX(3), 0)
        
        NEXT_CASE(INST_FUNCCALL_REF)
            uint16_t argcount = PROG_IDX(1);
            Value v_func = frame->stack[PROG_IDX(2)];
            assert2(0, v_func.tag == VALUE_FUNC || v_func.tag == VALUE_STATE, "Tried to call a non-function");
            Funcdef * fn = v_func.tag == VALUE_FUNC ? v_func.u.fn : v_func.u.fs->fn;
            ENTER_FUNC(PROG_IDX(2) + 1, PROG_IDX(2), v_func.tag == VALUE_FUNC ? 0 : v_func.u.fs->frame)
        
        #define RETURN_WITH(POOLABLE, X) if (!frame->return_to) { PC_INC(); return frame->pc; }\
            Frame * oldframe = frame; Value retval = (X); frame = frame->return_to; pc = frame->pc; value_store(&frame->stack[frame->return_slot], retval);\
            if (POOLABLE && oldframe->fn && oldframe->fn->poolsafe) framepoolpush(oldframe);\
            DISPATCH_IMMEDIATELY();
        
        NEXT_CASE(INST_YIELD)
            if (!frame->return_to) panic2(0, "Attempted to yield from not inside of a function");
            
            PC_INC();
            
            Value v = frame->stack[PROG_IDX(1)];
            Value v2 = val_array(2);
            v2.u.a->buf[0] = v;
            v2.u.a->buf[1] = val_funcstate(frame->fn, frame);
            
            RETURN_WITH(0, v2);
        
        NEXT_CASE(INST_RETURN_VAL)
            RETURN_WITH(1, frame->stack[PROG_IDX(1)]);
        
        NEXT_CASE(INST_RETURN_VOID)
            RETURN_WITH(1, val_tagged(VALUE_NULL));
        
        NEXT_CASE(PUSH_NULL)    STACK_PUSH(1, val_tagged(VALUE_NULL))
        
        NEXT_CASE(PUSH_DICT_EMPTY)
            Value v = val_tagged(VALUE_DICT);
            v.u.d = (Dict *)zalloc(sizeof(Dict));
            STACK_PUSH(1, v)
        
        NEXT_CASE(PUSH_NUM)
            STACK_PUSH(5, val_float(fi_mem_read_f64(code + frame->pc + 1)))
        
        NEXT_CASE(PUSH_GLOBAL)
        STACK_PUSH(2, global_frame->vars[PROG_IDX(1)])
            
        NEXT_CASE(INST_SET_GLOBAL)
            Value v2 = frame->stack[PROG_IDX(2)];
            value_store(&global_frame->vars[PROG_IDX(1)], v2);
            Value * v = &frame->vars[PROG_IDX(1)];
            if (v->tag == VALUE_STRING) { char ** ss = (char **)zalloc(sizeof(char *)); *ss = *v->u.s; v->u.s = ss; }
        
        NEXT_CASE(PUSH_CAP)    STACK_PUSH(2, *frame->caps[PROG_IDX(1)])
        NEXT_CASE(INST_SET_CAP)
            Value v2 = frame->stack[PROG_IDX(2)];
            value_store(frame->caps[PROG_IDX(1)], v2);
            Value * v = &frame->vars[PROG_IDX(1)];
            if (v->tag == VALUE_STRING) { char ** ss = (char **)zalloc(sizeof(char *)); *ss = *v->u.s; v->u.s = ss; }
        
        #define GLOBAL_MATH_SHARED(X)\
            Value v2 = frame->stack[PROG_IDX(2)];\
            uint16_t id = PROG_IDX(1);\
            Value v1 = global_frame->vars[id];\
            assert2(0, v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Operator " #X " only works on numbers");\
            value_store(&global_frame->vars[id], val_float(v1.u.f X v2.u.f));
        
        NEXT_CASE(INST_SET_GLOBAL_ADD)    GLOBAL_MATH_SHARED(+)
        NEXT_CASE(INST_SET_GLOBAL_SUB)    GLOBAL_MATH_SHARED(-)
        NEXT_CASE(INST_SET_GLOBAL_MUL)    GLOBAL_MATH_SHARED(*)
        NEXT_CASE(INST_SET_GLOBAL_DIV)    GLOBAL_MATH_SHARED(/)
        
        #define CAP_MATH_SHARED(X)\
            Value v2 = frame->stack[PROG_IDX(2)];\
            uint16_t id = PROG_IDX(1);\
            Value v1 = *frame->caps[id];\
            assert2(0, v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Operator " #X " only works on numbers");\
            value_store(frame->caps[id], val_float(v1.u.f X v2.u.f));
        
        #define BIN_STACKPOP(IDX)\
            Value v1 = frame->stack[PROG_IDX(IDX)];\
            Value v2 = frame->stack[PROG_IDX(IDX) + 1];
        
        NEXT_CASE(INST_SET_CAP_ADD)    CAP_MATH_SHARED(+)
        NEXT_CASE(INST_SET_CAP_SUB)    CAP_MATH_SHARED(-)
        NEXT_CASE(INST_SET_CAP_MUL)    CAP_MATH_SHARED(*)
        NEXT_CASE(INST_SET_CAP_DIV)    CAP_MATH_SHARED(/)
        
        #define MATH_SHARED(C, X) BIN_STACKPOP(1)\
            /*assert2(0, v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Operator " #X " only works on numbers");*/\
            if (v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT)\
                value_store(&frame->stack[PROG_IDX(1)], val_float(C v1.u.f X C v2.u.f));\
            else value_store(&frame->stack[PROG_IDX(1)], val_float(0.0));
        
        NEXT_CASE(INST_ADD)    MATH_SHARED(, +)
        NEXT_CASE(INST_SUB)    MATH_SHARED(, -)
        NEXT_CASE(INST_MUL)    MATH_SHARED(, *)
        NEXT_CASE(INST_DIV)    MATH_SHARED(, /)
        NEXT_CASE(INST_BITAND)    MATH_SHARED((unsigned int), &)
        NEXT_CASE(INST_BITOR)     MATH_SHARED((unsigned int), |)
        NEXT_CASE(INST_BITXOR)    MATH_SHARED((unsigned int), ^)
        NEXT_CASE(INST_INTMOD)    MATH_SHARED((long long int), %)
        
        #define MATH_SHARED_BOOL(X) BIN_STACKPOP(1)\
            assert2(0, v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Boolean comparison only works on numbers");\
            value_store(&frame->stack[PROG_IDX(1)], val_float(X));
        
        NEXT_CASE(INST_CMP_AND)    MATH_SHARED_BOOL(!!(v1.u.f) && !!(v2.u.f))
        NEXT_CASE(INST_CMP_OR)     MATH_SHARED_BOOL(!!(v1.u.f) || !!(v2.u.f))
        
        #define LOCAL_MATH_SHARED(X)\
            Value v2 = frame->stack[PROG_IDX(2)];\
            uint16_t id = PROG_IDX(1);\
            Value v1 = frame->vars[id];\
            assert2(0, v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Operator " #X " only works on numbers");\
            value_store(&frame->vars[id], val_float(v1.u.f X v2.u.f));
        
        NEXT_CASE(INST_SET_ADD)    LOCAL_MATH_SHARED(+)
        NEXT_CASE(INST_SET_SUB)    LOCAL_MATH_SHARED(-)
        NEXT_CASE(INST_SET_MUL)    LOCAL_MATH_SHARED(*)
        NEXT_CASE(INST_SET_DIV)    LOCAL_MATH_SHARED(/)
            
        #define ADDR_MATH_SHARED(X)\
            Value v2 = frame->stack[PROG_IDX(1)];\
            Value * v1p = frame->set_tgt_agg;\
            assert2(0, v1p && v2.tag == VALUE_FLOAT && v1p->tag == VALUE_FLOAT, "Operator " #X " only works on numbers");\
            frame->set_tgt_agg = 0;\
            value_store(v1p, val_float(v1p->u.f X v2.u.f));
        
        NEXT_CASE(INST_SET_LOC_ADD)    ADDR_MATH_SHARED(+)
        NEXT_CASE(INST_SET_LOC_SUB)    ADDR_MATH_SHARED(-)
        NEXT_CASE(INST_SET_LOC_MUL)    ADDR_MATH_SHARED(*)
        NEXT_CASE(INST_SET_LOC_DIV)    ADDR_MATH_SHARED(/)
        
        #define EQ_SHARED(X) BIN_STACKPOP(1)\
            int8_t equality = val_cmp(v1, v2);\
            value_store(&frame->stack[PROG_IDX(1)], val_float(X));
        
        NEXT_CASE(INST_CMP_EQ)    EQ_SHARED(equality == 0)
        NEXT_CASE(INST_CMP_NE)    EQ_SHARED(equality != 0)
        NEXT_CASE(INST_CMP_LE)    EQ_SHARED(equality == 0 || equality == -1)
        NEXT_CASE(INST_CMP_GE)    EQ_SHARED(equality == 0 || equality == 1)
        NEXT_CASE(INST_CMP_LT)    EQ_SHARED(equality == -1)
        NEXT_CASE(INST_CMP_GT)    EQ_SHARED(equality == 1)
        
        NEXT_CASE(INST_FORSTART)
            Value v = frame->stack[PROG_IDX(5)];
            assert2(0, v.tag == VALUE_FLOAT, "For loops can only operate on numbers");
            uint16_t id = PROG_IDX(1);
            uint16_t idx = PROG_IDX(2);
            frame->vars[id] = val_float(0.0);
            if ((uint64_t)v.u.f < 1) READ_AND_GOTO_TARGET(3)
            frame->forloops[idx].l = 0;
            frame->forloops[idx].r = v.u.f;
        NEXT_CASE(INST_FOREND)
            uint16_t id = PROG_IDX(1);
            uint16_t idx = PROG_IDX(2);
            frame->forloops[idx].l += 1;
            value_store(&frame->vars[id], val_float(frame->forloops[idx].l));
            if (frame->forloops[idx].l < frame->forloops[idx].r) READ_AND_GOTO_TARGET(3)
        
        NEXT_CASE(INST_JMP)    READ_AND_GOTO_TARGET(1)
        NEXT_CASE(INST_JMP_IF_FALSE)    if (!val_truthy(frame->stack[PROG_IDX(3)])) READ_AND_GOTO_TARGET(1)
        NEXT_CASE(INST_JMP_IF_TRUE)     if ( val_truthy(frame->stack[PROG_IDX(3)])) READ_AND_GOTO_TARGET(1)
        
        NEXT_CASE(PUSH_STRING)      STACK_PUSH(2, val_string(stringdup(cs->compiled_strings[PROG_IDX(1)])))
        
        NEXT_CASE(PUSH_LOCAL)       STACK_PUSH(2, frame->vars[PROG_IDX(1)])
        NEXT_CASE(PUSH_FUNCNAME)    STACK_PUSH(2, val_func(PROG_IDX(1)))
        
        NEXT_CASE(INST_SET)
            value_store(&frame->vars[PROG_IDX(1)], frame->stack[PROG_IDX(2)]);
            Value * v = &frame->vars[PROG_IDX(1)];
            if (v->tag == VALUE_STRING) { char ** ss = (char **)zalloc(sizeof(char *)); *ss = *v->u.s; v->u.s = ss; }
        
        NEXT_CASE(INST_SET_LOC)
            Value v2 = frame->stack[PROG_IDX(1)];
            if (frame->set_tgt_agg) { value_store(frame->set_tgt_agg, v2); frame->set_tgt_agg = 0; }
            else { assert2(0, frame->set_tgt_char && v2.tag == VALUE_STRING, "Invalid assignment.");
                *frame->set_tgt_char = **v2.u.s; frame->set_tgt_char = 0; }
        
        #define INDEX_SHARED(STR_VALID_OP) BIN_STACKPOP(1)\
            assert2(0, v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY || v1.tag == VALUE_DICT);\
            if (v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY) assert2(0, v2.tag == VALUE_FLOAT);\
            if (v1.tag == VALUE_DICT) assert2(0, v2.tag == VALUE_FLOAT || v2.tag == VALUE_STRING\
                                             || v2.tag == VALUE_FUNC || v2.tag == VALUE_NULL);\
            if (v1.tag == VALUE_STRING) assert2(0, ((size_t)v2.u.f) STR_VALID_OP strlen(*v1.u.s));
    
        NEXT_CASE(INST_INDEX)    INDEX_SHARED(<=)
            if (v1.tag == VALUE_STRING) { char ** ss = (char **)zalloc(sizeof(char *));
                *ss = stringdupn(*v1.u.s + (size_t)v2.u.f, 1); v1.u.s = ss; }
            else if (v1.tag == VALUE_ARRAY) { Value * vp = array_get(v1.u.a, v2.u.f); if (!vp) return 0; v1 = *vp; }
            else if (v1.tag == VALUE_DICT)   v1 = dict_get_or_insert(v1.u.d, v2)->r;
            frame->stack[PROG_IDX(1)] = v1;
        
        NEXT_CASE(INST_INDEX_LOC)    INDEX_SHARED(<)
            // Our strings are double-boxed so that we can COW them without the compiler needing to be aware of
            //  whether a string value is going to be used as a "place"/"lvalue" or not.
            if (v1.tag == VALUE_STRING) { assert2(0, (size_t)v2.u.f <= strlen(*v1.u.s), "Index past end of string");
                *v1.u.s = stringdupn(*v1.u.s, strlen(*v1.u.s) + 1); frame->set_tgt_char = *v1.u.s + (size_t)v2.u.f; }
            else if (v1.tag == VALUE_ARRAY)  frame->set_tgt_agg = array_get(v1.u.a, v2.u.f);
            else if (v1.tag == VALUE_DICT)   frame->set_tgt_agg = &(dict_get_or_insert(v1.u.d, v2)->r);
        
        NEXT_CASE(INST_LAMBDA)
            Value v = val_func(PROG_IDX(1));
            Funcdef * f = (Funcdef *)zalloc(sizeof(Funcdef));
            *f = *v.u.fn;
            //printf("%p\n", f->caps);
            if (f->cap_count) f->cap_data = (Value **)zalloc(sizeof(Value *) * f->cap_count);
            for (size_t j = 0; j < f->cap_count; j++)
                f->cap_data[j] = (f->caps[j] < 0) ? frame->caps[-f->caps[j]] : &frame->vars[f->caps[j]];
            v.u.fn = f;
            STACK_PUSH(5, v) READ_AND_GOTO_TARGET(3)
        
        END_CASE()
        DECAULT_CASE()
    CASES_END()
}

void register_intrinsic_func(const char * s)
{
    int16_t id = lex_ident_offset - insert_or_lookup_id(s, strlen(s));
    cs->funcs_reg[id] = FI_LIT(Funcdef) {1, 1, 0, 0, (uint16_t)id, 0, 0, prog.i, 0, 0};
}

#include "intrinsics.h"

#endif
