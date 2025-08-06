#ifndef FILLI_H_INCLUDED
#define FILLI_H_INCLUDED

// INTEGRATION:
// - include and link boehm GC and use #define to replace stdlib malloc/etc with boehm funcs
// - rewrite intrinsics.h, adding whatever functionality you need (e.g. trig, array insert/delete/splice)
// - skim microlib.h, consider replacing it with thin stdlib wrappers

#define IDENTIFIER_COUNT 32000
#define FRAME_VARCOUNT 1024 // increases memory usage of stack frames
#define FRAME_STACKSIZE 1024 // increases memory usage of stack frames
#define PROGRAM_MAXLEN 100000 // default max length of program
#define FORLOOP_COUNT_LIMIT 255 // increases memory usage of stack frames
#define ARGLIMIT 255 // affects risk of stack smashing during compilation
#define ELIFLIMIT 255 // affects risk of stack smashing during compilation
#define CAPTURELIMIT 255
#define LAMBDA_COUNT 4096

// OTHER LIMITS

// this library just does stuff that the stdlib does but with less stdlib involvement
// why? smaller statically linked (e.g. musl) binaries. yes, the difference is significant!
#include "microlib.h"

void * zalloc(size_t s) { char * r = (char *)malloc(s); memset(r, 0, s); return r; }

// actual program

typedef struct _IdEntry { const char * where; uint16_t len; } IdEntry;

int16_t insert_or_lookup_id(const char * text, uint16_t len)
{
    // TODO: make non-static
    static IdEntry ids[IDENTIFIER_COUNT] = {};
    for (int16_t j = 1; j <= IDENTIFIER_COUNT; j++)
    {
        if (ids[j].len == 0) ids[j] = (IdEntry) { stringdupn(text, len), len };
        if (ids[j].len == len && strncmp(ids[j].where, text, len) == 0) return -j;
    }
    panic("Out of IDs");
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
    insert_or_lookup_id("end", 3);       // 11
    insert_or_lookup_id("lambda", 3);    // 12
    lex_ident_offset = 12;
}
#define MIN_KEYWORD -12

Token * tokenize(const char * src, size_t * count)
{
    int newline_is_token = 1;
    
    const char * long_punctuation[] = { "==", "!=", ">=", "<=", "+=", "-=", "*=", "/=", "{}" };
    
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
            if (newline_is_token && t > 0 && token_is(src, ret, t, t-1, "\\"))
                t -= 1;
            else if (newline_is_token)
                ret[t++] = mk_token(i, 1, 3);
            i++;
        }
        // tokenize numbers
        else if ((src[i] >= '0' && src[i] <= '9') || (src[i] == '-' && src[i+1] >= '0' && src[i+1] <= '9'))
        {
            uint8_t dot_ok = 1;
            size_t start_i = i;
            if (src[i] == '-') i += 1;
            while ((src[i] >= '0' && src[i] <= '9') || (dot_ok && src[i] == '.'))
                dot_ok = (src[i++] == '.') ? 0 : dot_ok;
            ret[t++] = mk_token(start_i, i-start_i, 0);
        }
        // tokenize identifiers and keywords
        else if ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z') || src[i] == '_')
        {
            size_t start_i = i++;
            while ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z')
                   || src[i] == '_' || (src[i] >= '0' && src[i] <= '9'))
                i++;
            
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
            for (size_t j = 0; j < sizeof(long_punctuation) / sizeof(long_punctuation[0]); j++)
            {
                size_t len = strlen(long_punctuation[j]);
                if (strncmp(long_punctuation[j], src+i, len) == 0)
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
    }
    
    *count = t;
    return ret;
}

enum {
    INST_INVALID,
    // zero-op
    INST_DISCARD = 0x100, PUSH_NULL, PUSH_DICT_EMPTY, INST_RETURN_VAL, INST_RETURN_VOID,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV, INST_CMP_AND, INST_CMP_OR,
    INST_CMP_EQ, INST_CMP_NE, INST_CMP_GT, INST_CMP_LT, INST_CMP_GE, INST_CMP_LE,
    INST_INDEX, INST_INDEX_ADDR, INST_SET_ADDR,
    INST_SET_ADDR_ADD, INST_SET_ADDR_SUB, INST_SET_ADDR_MUL, INST_SET_ADDR_DIV,
    // 1-op
    PUSH_FUNCNAME = 0x220, INST_FUNCCALL_REF, PUSH_STRING, INST_ARRAY_LITERAL,
    PUSH_LOCAL, PUSH_GLOBAL, PUSH_CAP, INST_SET, INST_SET_GLOBAL, INST_SET_CAP,
    INST_SET_ADD, INST_SET_GLOBAL_ADD, INST_SET_CAP_ADD,
    INST_SET_SUB, INST_SET_GLOBAL_SUB, INST_SET_CAP_SUB,
    INST_SET_MUL, INST_SET_GLOBAL_MUL, INST_SET_CAP_MUL,
    INST_SET_DIV, INST_SET_GLOBAL_DIV, INST_SET_CAP_DIV,
    // 2-op
    INST_JMP = 0x340, INST_JMP_IF_FALSE, INST_JMP_IF_TRUE, INST_FUNCDEF, INST_FUNCCALL,
    // jumps: destination
    // INST_FUNCDEF: skip destination
    // INST_FUNCCALL: func id, arg count
    // 4-op
    PUSH_NUM = 0x560, INST_FOREND, INST_FORSTART, INST_LAMBDA, 
    // PUSH_NUM: f64 (8)
    // INST_FOREND: var id (2), for slot (2), destination (4)
    // INST_FORSTART: var id (2), for slot (2), destination(4) (needed if loop val is 0)
    // INST_LAMBDA: func id (4), destination(4)
};

// TODO: make non-global
uint16_t * program = 0;
uint32_t prog_capacity = PROGRAM_MAXLEN;
void init_program() { program = zalloc(sizeof(uint16_t) * prog_capacity); }
uint32_t prog_i = 0;

void prog_write(uint16_t a) { program[prog_i++] = a; }
void prog_add(size_t n) { for (size_t i = 0; i < n; i++) prog_write(0); }
void prog_write2(uint16_t a, uint16_t b) { prog_write(a); prog_write(b); }
void prog_write3(uint16_t a, uint16_t b, uint16_t c) { prog_write(a); prog_write(b); prog_write(c); }
void prog_write5(uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e)
    { prog_write(a); prog_write(b); prog_write(c); prog_write(d); prog_write(e); }

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

struct _Value;

typedef struct _Funcdef {
    uint8_t exists, intrinsic, argcount, id;
    uint32_t loc;
    uint16_t * args;
    uint16_t cap_count;
    int16_t * caps;
    struct _Value ** cap_data;
} Funcdef;

const char * compiled_strings[1<<16] = {};
uint16_t compiled_string_i = 0;

uint8_t func_depth = 0;
Funcdef funcs_registered[IDENTIFIER_COUNT + LAMBDA_COUNT] = {};
uint32_t lambda_id = IDENTIFIER_COUNT;
uint8_t globals_registered[IDENTIFIER_COUNT] = {};

uint8_t * locals_registered;
uint8_t * locals_reg_stack[1024] = {};
size_t locals_reg_i = 0;

uint16_t * caps_registered;
uint16_t * caps_reg_stack[1024] = {};
size_t caps_reg_i = 0;

uint8_t for_loop_index = 0;

// returns number of consumed tokens
size_t compile_value(const char * source, Token * tokens, size_t count, uint32_t i)
{
    if (i >= count) return 0;
    
    if (token_is(source, tokens, count, i, "{}")) return prog_write(PUSH_DICT_EMPTY), 1;
    
    if (tokens[i].kind > 1) return 0;
    if (tokens[i].kind < 0 && tokens[i].kind >= MIN_KEYWORD) return 0;
    
    if (tokens[i].kind < 0)
    {
        if (token_is(source, tokens, count, i, "true"))
            return prog_write5(PUSH_NUM, 0, 0, 0, 0x3FF0), 1;
        else if (token_is(source, tokens, count, i, "false"))
            return prog_write5(PUSH_NUM, 0, 0, 0, 0), 1;
        else if (token_is(source, tokens, count, i, "null"))
            return prog_write(PUSH_NULL), 1;
        else if (func_depth > 0 && locals_registered[lex_ident_offset-tokens[i].kind])
            prog_write(PUSH_LOCAL);
        else if (func_depth > 0 && caps_registered[lex_ident_offset-tokens[i].kind])
            prog_write(PUSH_CAP);
        else if (globals_registered[lex_ident_offset-tokens[i].kind])
            prog_write(PUSH_GLOBAL);
        else if (funcs_registered[lex_ident_offset-tokens[i].kind].exists)
            prog_write(PUSH_FUNCNAME);
        else
        {
            printsn(source + tokens[i].i, tokens[i].len);
            prints("\n");
            panic("Unknown identifier");
        }
        uint16_t id = lex_ident_offset - tokens[i].kind;
        prog_write((program[prog_i - 1] != PUSH_CAP) ? id : (caps_registered[id] - 1));
    }
    else if (tokens[i].kind == 1)
    {
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
        compiled_strings[compiled_string_i] = s;
        prog_write2(PUSH_STRING, compiled_string_i++);
    }
    else if (tokens[i].kind == 0)
    {
        char * s = stringdupn(source + tokens[i].i, tokens[i].len);
        double f = badstrtod(s);
        free(s);
        
        prog_write5(PUSH_NUM, 0, 0, 0, 0);
        memcpy(program + (prog_i - 4), &f, 8);
    }
    
    return 1;
}

#define PARSE_COMMALIST(END, BREAK, BREAK2, LIMITER, HANDLER)\
    uint32_t j = 0;\
    while (!token_is(source, tokens, count, i, END)) {\
        LIMITER; HANDLER; j += 1;\
        if (!(token_is(source, tokens, count, i, END) || token_is(source, tokens, count, i, ","))) BREAK;\
        if (token_is(source, tokens, count, i, ",")) i++;\
    }\
    if (!token_is(source, tokens, count, i++, END)) BREAK2;

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power);
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i);

void compile_func_start(void)
{
    func_depth += 1;
    locals_reg_stack[locals_reg_i++] = locals_registered;
    locals_registered = (uint8_t *)zalloc(IDENTIFIER_COUNT);
    caps_reg_stack[caps_reg_i++] = caps_registered;
    caps_registered = (uint16_t *)zalloc(sizeof(uint16_t) * IDENTIFIER_COUNT);
}
void compile_func_end(void)
{
    free(locals_registered);
    locals_registered = locals_reg_stack[--locals_reg_i];
    free(caps_registered);
    caps_registered = caps_reg_stack[--caps_reg_i];
    func_depth -= 1;
}
size_t compile_lambda(const char * source, Token * tokens, size_t count, size_t i, int16_t * caps, uint16_t caps_count);

uint16_t active_captures[CAPTURELIMIT];

size_t compile_innerexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    if (token_is(source, tokens, count, i, "lambda"))
    {
        size_t orig_i = i++;
        
        if (!token_is(source, tokens, count, i++, "[")) return 0;
        int16_t * caps = (int16_t *)zalloc(sizeof(int16_t) * CAPTURELIMIT);
        uint16_t * caps_registered_next = (uint16_t *)zalloc(sizeof(uint16_t) * IDENTIFIER_COUNT);
        PARSE_COMMALIST("]", return 0, return 0, assert(j < CAPTURELIMIT),
            if (tokens[i].kind >= MIN_KEYWORD) return 0;
            int16_t id = lex_ident_offset - tokens[i++].kind;
            int16_t accessor_id = 0;
            if      (func_depth > 0 && locals_registered[id])   accessor_id = id;
            else if (func_depth > 0 && caps_registered  [id])   accessor_id = -caps_registered[id];
            else
            {
                printsn(source + tokens[i - 1].i, tokens[i - 1].len);
                prints("\n");
                panic("Unable to capture identifier");
            }
            caps[j] = accessor_id;
            caps_registered_next[id] = j + 1;
        )
        
        compile_func_start();
        memcpy(caps_registered, caps_registered_next, sizeof(uint16_t) * IDENTIFIER_COUNT);
        size_t r = compile_lambda(source, tokens, count, i, caps, j);
        compile_func_end();
        
        if (r == 0) panic("Lambda body is invalid");
        
        return i + r - orig_i;
    }
    if (token_is(source, tokens, count, i, "(")) // wrapped expr
    {
        size_t ret = compile_expr(source, tokens, count, i+1, 0) + 1;
        assert(token_is(source, tokens, count, i + ret, ")"), "Unclosed parens");
        return ret + 1;
    }
    if (token_is(source, tokens, count, i, "[")) // array literal
    {
        size_t orig_i = i++; // skip [
        
        PARSE_COMMALIST("]", return 0, return 0, assert(j < 32000, "Too many values in array literal"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            i += r;
        )
        
        prog_write2(INST_ARRAY_LITERAL, j);
        return i - orig_i;
    }
    return compile_value(source, tokens, count, i++);
}

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power)
{
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
        size_t orig_i = i++; // skip (
        PARSE_COMMALIST(")",  return 0, return 0, assert(j < ARGLIMIT, "Too many arguments to function"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            i += r;
        )
        
        prog_write2(INST_FUNCCALL_REF, j);
        return i - orig_i;
    }
    
    size_t r = compile_expr(source, tokens, count, i + 1, binding_power < 500 ? binding_power : 0);
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
    else if (token_is(source, tokens, count, i, "and")) inst = INST_CMP_AND;
    else if (token_is(source, tokens, count, i, "or")) inst = INST_CMP_OR;
    else if (token_is(source, tokens, count, i, "["))
    {
        inst = INST_INDEX;
        i += ++r;
        assert(token_is(source, tokens, count, i++, "]"));
    }
    else { printsn(source + tokens[i].i, tokens[i].len); prints("\n"); panic("Unknown infix operator"); }
    prog_write(inst);
    return r + 1;
}


size_t compile_statementlist(const char * source, Token * tokens, size_t count, size_t i);

size_t loop_nesting = 0;
uint32_t loop_conts[10000] = {};
size_t loop_cont_i = 0;
uint32_t loop_breaks[10000] = {};
size_t loop_break_i = 0;

size_t compile_statement(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    size_t orig_i = i;
    if (tokens[i].kind == -1) // if
    {
        i += compile_expr(source, tokens, count, i + 1, 0) + 1;
        assert(token_is(source, tokens, count, i++, ":"));
        prog_write3(INST_JMP_IF_FALSE, 0, 0);
        size_t jump_at = prog_i - 2;
        
        i += compile_statementlist(source, tokens, count, i);
        
        uint32_t end = prog_i + ((tokens[i].kind == -3 || tokens[i].kind == -2) ? 3 : 0);
        memcpy(program + jump_at, &end, 4);
        
        uint32_t skips[ELIFLIMIT] = {};
        size_t skip_i = 0;
        
        while (tokens[i].kind == -3 || tokens[i].kind == -2) // elif, else
        {
            // add on to previous block: skip this and the rest of the blocks
            prog_write3(INST_JMP, 0, 0);
            skips[skip_i++] = prog_i - 2;
            assert(skip_i < ELIFLIMIT-1, "Too many elifs in if-else chain");
            
            if (tokens[i].kind == -3) // elif
            {
                i += compile_expr(source, tokens, count, i + 1, 0) + 1;
                assert(token_is(source, tokens, count, i++, ":"));
                prog_write3(INST_JMP_IF_FALSE, 0, 0);
                size_t jump_at = prog_i - 2;
                
                i += compile_statementlist(source, tokens, count, i);
                
                uint32_t end = prog_i + ((tokens[i].kind == -3 || tokens[i].kind == -2) ? 3 : 0);
                memcpy(program + jump_at, &end, 4);
            }
            else
            {
                i += 1;
                assert(token_is(source, tokens, count, i++, ":"));
                i += compile_statementlist(source, tokens, count, i);
            }
        }
        assert(tokens[i].kind == -11, "Missing end keyword");
        uint32_t real_end = prog_i;
        while (skip_i > 0) memcpy(program + skips[--skip_i], &real_end, 4);
        return i + 1 - orig_i;
    }
    if (tokens[i].kind == -5) // while
    {
        loop_nesting++;
        size_t loop_cont_base = loop_cont_i;
        size_t loop_break_base = loop_break_i;
        
        size_t expr_i = i + 1;
        i += compile_expr(source, tokens, count, expr_i, 0) + 1;
        assert(token_is(source, tokens, count, i++, ":"));
        prog_write3(INST_JMP_IF_FALSE, 0, 0);
        size_t skip_at = prog_i - 2;
        uint32_t loop_at = prog_i;
        
        i += compile_statementlist(source, tokens, count, i);
        assert(i < count);
        assert(tokens[i].kind == -11, "Missing end keyword"); // end
        
        uint32_t cont_to = prog_i;
        compile_expr(source, tokens, count, expr_i, 0); // recompile test expr
        prog_write3(INST_JMP_IF_TRUE, 0, 0);
        memcpy(program + (prog_i - 2), &loop_at, 4);
        
        uint32_t end = prog_i;
        memcpy(program + skip_at, &end, 4);
        
        uint32_t break_to = prog_i;
        while (loop_break_i > loop_break_base) memcpy(program + loop_breaks[--loop_break_i], &break_to, 4);
        while (loop_cont_i  > loop_cont_base ) memcpy(program + loop_conts [--loop_cont_i ], &cont_to , 4);
        loop_nesting--;
        
        return i + 1- orig_i;
    }
    else if (token_is(source, tokens, count, i, "let"))
    {
        if (++i >= count) return 0;
        int16_t id = lex_ident_offset - tokens[i++].kind;
        
        if (func_depth == 0) globals_registered[id] = 1;
        else                 locals_registered [id] = 1;
        
        if (token_is(source, tokens, count, i, "="))
        {
            size_t r = compile_expr(source, tokens, count, i + 1, 0);
            if (!r) return i - orig_i;
            i += r + 1;
            prog_write2(INST_SET + (func_depth == 0), id);
        }
        return i - orig_i;
    }
    else if (token_is(source, tokens, count, i, "for"))
    {
        if (++i >= count) return 0;
        
        loop_nesting++;
        size_t loop_cont_base = loop_cont_i;
        size_t loop_break_base = loop_break_i;
        
        int16_t id = lex_ident_offset - tokens[i++].kind;
        if (func_depth == 0) globals_registered[id] = 1;
        else                 locals_registered[id] = 1;
        assert(token_is(source, tokens, count, i++, "in"));
        uint16_t idx = for_loop_index++;
        assert(idx < FORLOOP_COUNT_LIMIT, "Too many for loops")
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert(ret > 0, "For loop requires valid expression")
        i += ret;
        
        prog_write5(INST_FORSTART, id, idx, 0, 0);
        
        uint32_t head = prog_i;
        
        assert(token_is(source, tokens, count, i++, ":"));
        
        i += compile_statementlist(source, tokens, count, i);
        assert(tokens[i++].kind == -11, "Missing end keyword");
        
        uint32_t cont_to = prog_i;
        prog_write5(INST_FOREND, id, idx, 0, 0);
        memcpy(program + (prog_i - 2), &head, 4);
        
        uint32_t end = prog_i;
        memcpy(program + (head - 2), &end, 4);
        
        uint32_t break_to = prog_i;
        while (loop_break_i > loop_break_base) memcpy(program + loop_breaks[--loop_break_i], &break_to, 4);
        while (loop_cont_i  > loop_cont_base ) memcpy(program + loop_conts [--loop_cont_i ], &cont_to , 4);
        loop_nesting--;
        
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
        && (token_is(source, tokens, count, i+1, "=")
            || token_is(source, tokens, count, i+1, "+=") || token_is(source, tokens, count, i+1, "-=")
            || token_is(source, tokens, count, i+1, "*=") || token_is(source, tokens, count, i+1, "/=")))
    {
        const char * opstr = stringdupn(source + tokens[i+1].i, tokens[i+1].len);
        size_t oplen = tokens[i+1].len;
        
        int16_t id = lex_ident_offset - tokens[i++].kind;
        i += 1; // =
        
        size_t ret = compile_expr(source, tokens, count, i, 0);
        assert(ret > 0, "Assignment requires valid expression")
        i += ret;
        
        uint8_t mode;
        if (func_depth > 0 && locals_registered[id]) mode = 0;
        else if (func_depth > 0 && caps_registered[id]) mode = 2;
        else if (globals_registered[id]) mode = 1;
        else panic("Unknown variable");
        
        if (strncmp(opstr, "=", oplen) == 0)       prog_write(INST_SET + mode);
        else if (strncmp(opstr, "+=", oplen) == 0) prog_write(INST_SET_ADD + mode);
        else if (strncmp(opstr, "-=", oplen) == 0) prog_write(INST_SET_SUB + mode);
        else if (strncmp(opstr, "*=", oplen) == 0) prog_write(INST_SET_MUL + mode);
        else if (strncmp(opstr, "/=", oplen) == 0) prog_write(INST_SET_DIV + mode);
        
        prog_write((mode != 2) ? id : (caps_registered[id] - 1));
        return i - orig_i;
    }
    else if (i + 2 < count && tokens[i].kind < -lex_ident_offset
             && token_is(source, tokens, count, i+1, "(")
             && funcs_registered[lex_ident_offset - tokens[i].kind].exists)
    {
        uint16_t id = lex_ident_offset - tokens[i++].kind;
        i += 1; // (
        
        PARSE_COMMALIST(")", return 0, return 0, assert(j < ARGLIMIT, "Too many arguments to function"),
            size_t r = compile_expr(source, tokens, count, i, 0);
            if (r == 0) return 0;
            i += r;
        )
        
        prog_write3(INST_FUNCCALL, id, j);
        
        prog_write(INST_DISCARD);
        return i - orig_i;
    }
    else if (tokens[i].kind == -11 || tokens[i].kind == -3 || tokens[i].kind == -2) // end, elif, else
        return i - orig_i;
    else if (token_is(source, tokens, count, i, "\n") || token_is(source, tokens, count, i, ";"))
        return 1;
    else if (token_is(source, tokens, count, i, "continue")
             || token_is(source, tokens, count, i, "break"))
    {
        assert(loop_nesting > 0);
        prog_write3(INST_JMP, 0, 0);
        if (token_is(source, tokens, count, i, "continue"))
            loop_conts[loop_cont_i++] = prog_i - 2;
        else
            loop_breaks[loop_break_i++] = prog_i - 2;
        return 1;
    }
    else if (token_is(source, tokens, count, i, "return"))
    {
        size_t r = compile_expr(source, tokens, count, ++i, 0);
        if (r == 0) prog_write(INST_RETURN_VOID);
        else        prog_write(INST_RETURN_VAL);
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
        i += r;
        
        if (program[prog_i - 1] == INST_INDEX && (token_is(source, tokens, count, i, "=")
             || token_is(source, tokens, count, i, "+=") || token_is(source, tokens, count, i, "-=")
             || token_is(source, tokens, count, i, "*=") || token_is(source, tokens, count, i, "/=")))
        {
            size_t old_i = i;
            uint32_t checkpoint = prog_i - 1;
            size_t r2 = compile_expr(source, tokens, count, i + 1, 0);
            if (!r2) { prog_write(INST_DISCARD); return r; }
            r += r2 + 1;
            program[checkpoint] = INST_INDEX_ADDR;
            if (token_is(source, tokens, count, old_i, "=" )) prog_write(INST_SET_ADDR);
            if (token_is(source, tokens, count, old_i, "+=")) prog_write(INST_SET_ADDR_ADD);
            if (token_is(source, tokens, count, old_i, "-=")) prog_write(INST_SET_ADDR_SUB);
            if (token_is(source, tokens, count, old_i, "*=")) prog_write(INST_SET_ADDR_MUL);
            if (token_is(source, tokens, count, old_i, "/=")) prog_write(INST_SET_ADDR_DIV);
        }
        else prog_write(INST_DISCARD);
        return r;
    }
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


size_t compile_register_func(const char * source, Token * tokens, size_t count, uint16_t id, uint32_t i)
{
    size_t orig_i = i;
    
    if (!token_is(source, tokens, count, i++, "(")) panic("Invalid funcdef")
    uint16_t args[ARGLIMIT];
    PARSE_COMMALIST(")", panic("Invalid funcdef"), panic("Invalid funcdef"), assert(j < ARGLIMIT),
        if (tokens[i].kind >= MIN_KEYWORD) panic("Invalid funcdef");
        args[j] = lex_ident_offset - tokens[i++].kind;
        locals_registered[args[j]] = 1;
    )
    if (!token_is(source, tokens, count, i++, ":")) panic("Invalid funcdef");
    
    funcs_registered[id] = (Funcdef) {1, 0, j, id, prog_i, 0, 0, 0, 0};
    if (j > 0)
    {
        funcs_registered[id].args = (uint16_t *)zalloc(sizeof(uint16_t)*j);
        memcpy(funcs_registered[id].args, args, j * sizeof(uint16_t));
    }
    
    i += compile_statementlist(source, tokens, count, i);
    prog_write(INST_RETURN_VOID);
    assert(tokens[i++].kind == -11, "Missing end keyword");
    return i - orig_i;
}

size_t compile_func(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    if (tokens[i].kind >= MIN_KEYWORD) return 0;
    int16_t id = lex_ident_offset - tokens[i++].kind;
    
    prog_write3(INST_FUNCDEF, 0, 0);
    size_t len_offs = prog_i - 2;
    
    i += compile_register_func(source, tokens, count, id, i);
    
    memcpy(program + len_offs, &prog_i, 4);
    
    return i - orig_i;
}
size_t compile_lambda(const char * source, Token * tokens, size_t count, size_t i, int16_t * caps, uint16_t caps_count)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    uint32_t id = lambda_id++;
    
    prog_write5(INST_LAMBDA, 0, 0, 0, 0);
    size_t id_offs = prog_i - 4;
    memcpy(program + id_offs, &id, 4);
    
    i += compile_register_func(source, tokens, count, id, i);
    
    funcs_registered[id].caps = caps;
    funcs_registered[id].cap_count = caps_count;
    
    memcpy(program + id_offs + 2, &prog_i, 4);
    
    return i - orig_i;
}
size_t compile(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t r, orig_i = i;
    while (i < count)
    {
        if (tokens[i].kind == -4) // func
        {
            compile_func_start();
            r = compile_func(source, tokens, count, i+1);
            compile_func_end();
            assert(r != 0, "Incomplete function");
            i += r + 1;
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

struct _BiValue;
typedef struct _Array { struct _Value * buf; size_t len; size_t cap; } Array;
typedef struct _Dict { struct _BiValue * buf; size_t len; size_t cap; } Dict;

// tag
enum { VALUE_NULL, VALUE_INVALID, VALUE_FLOAT, VALUE_ARRAY, VALUE_DICT, VALUE_STRING, VALUE_FUNC };

typedef struct _Value {
    union { double f; Array * a; Dict * d; char * s; Funcdef * fn; } u;
    uint8_t tag;
} Value;
typedef struct _BiValue { struct _Value l; struct _Value r; } BiValue;

Value val_tagged(uint8_t tag) { Value v; memset(&v, 0, sizeof(Value)); v.tag = tag; return v; }
Value val_float(double f) { Value v = val_tagged(VALUE_FLOAT); v.u.f = f; return v; }
Value val_string(char * s) { Value v = val_tagged(VALUE_STRING); v.u.s = s; return v; }
Value val_func(uint16_t id) { Value v = val_tagged(VALUE_FUNC); v.u.fn = &funcs_registered[id]; return v; }

Value * array_get(Array * a, size_t i) { assert(i < a->len); return a->buf + i; }

// used by hashmap, not comparisons
uint8_t val_eq(Value * a, Value * b)
{
    if (a->tag != b->tag) return 0;
    if (a->tag == VALUE_FLOAT) return a->u.f == b->u.f || (a->u.f != a->u.f && b->u.f != b->u.f);
    if (a->tag == VALUE_STRING) return strcmp(a->u.s, b->u.s) == 0;
    if (a->tag == VALUE_FUNC) return a->u.fn == b->u.fn;
    return 0;
}

uint64_t val_hash(Value * v)
{
    assert(v->tag == VALUE_STRING || v->tag == VALUE_FLOAT || v->tag == VALUE_FUNC || v->tag == VALUE_NULL,
           "Tried to use an unhashable type (dict or array) as a dict key");
    uint64_t hash = 0;
    uint64_t hv = 0xf6f1029eab913ac5;
    
    hash = (hash + v->tag) * hv;
    if (v->tag == VALUE_FLOAT)  hash = (hash + double_bits_safe(v->u.f)) * hv;
    else if (v->tag == VALUE_STRING) for (size_t i = 0; v->u.s[i] != 0; i++) hash = (hash + v->u.s[i]) * hv;
    else if (v->tag == VALUE_FUNC)   hash = (hash + v->u.fn->id) * hv;
    
    return hash ^ (hash >> 6);
}

// newcap must be a power of 2
void dict_reallocate(Dict * d, size_t newcap)
{
    BiValue * newbuf = zalloc(sizeof(BiValue) * newcap);
    for (size_t i = 0; i < newcap; i++)
        newbuf[i] = (BiValue) { val_tagged(VALUE_INVALID), val_tagged(VALUE_INVALID) };
    for (size_t i = 0; i < d->cap; i++)
    {
        uint64_t hash = val_hash(&d->buf[i].l) & (newcap - 1);
        while (newbuf[hash].l.tag == VALUE_INVALID) hash = (hash + 1) & (newcap - 1);
        newbuf[hash] = (BiValue) { d->buf[i].l, d->buf[i].r };
    }
    d->cap = newcap;
    d->buf = newbuf;
}
Value * dict_get_or_insert(Dict * d, Value * v)
{
    if (d->cap == 0) dict_reallocate(d, 64);
    // max 50% load factor
    if (d->len * 2 > d->cap) dict_reallocate(d, d->cap * 2);
    
    uint64_t hash = val_hash(v) & (d->cap - 1);
    while (val_eq(v, &d->buf[hash].l)) hash = (hash + 1) & (d->cap - 1);
    if (d->buf[hash].r.tag == VALUE_INVALID) 
    {
        d->len++;
        d->buf[hash].r = val_tagged(VALUE_NULL);
    }
    return &d->buf[hash].r;
}

uint8_t val_truthy(Value v)
{
    if (v.tag == VALUE_FLOAT)   return v.u.f != 0.0;
    if (v.tag == VALUE_STRING)  return v.u.s[0] != 0;
    if (v.tag == VALUE_ARRAY)   return v.u.a->len > 0;
    if (v.tag == VALUE_FUNC)    return 1;
    return 0;
}

typedef struct _Frame {
    size_t pc, stackpos;
    struct _Frame * return_to;
    Value * assign_target_agg;
    char * assign_target_char;
    Value vars[FRAME_VARCOUNT], stack[FRAME_STACKSIZE];
    double forloops[FORLOOP_COUNT_LIMIT];
    Value ** caps;
} Frame;

void print_op_and_panic(uint16_t op) { prints("---\n"); printu16hex(op); prints("\n---\n"); panic("TODO"); }

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame);

void interpret(void)
{
    Frame * frame = (Frame *)zalloc(sizeof(Frame));
    assert(frame, "Out of memory");
    
    Frame * global_frame = frame;
    
    #define CASES_START() \
    while (frame->pc < prog_i) {\
        uint16_t op = program[frame->pc];\
        switch (op) {
    #define CASES_END() } }
    
    #define PC_INC() frame->pc += op >> 8
    
    #define MARK_CASE(X) case X: {
    #define END_CASE() PC_INC(); continue; }
    #define DECAULT_CASE() default: print_op_and_panic(op);
    
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)
    
    CASES_START()
        
        #define READ_AND_GOTO_TARGET(X)\
            { uint32_t target; memcpy(&target, program + (frame->pc + X), 4); frame->pc = target; continue; }
        
        MARK_CASE(INST_INVALID)     return;
        NEXT_CASE(INST_DISCARD)     --frame->stackpos;
        NEXT_CASE(INST_FUNCDEF)     READ_AND_GOTO_TARGET(1)
        
        #define STACK_PUSH(X)\
            assert(frame->stackpos < FRAME_STACKSIZE);\
            frame->stack[frame->stackpos++] = X;
        
        NEXT_CASE(INST_ARRAY_LITERAL)
            uint16_t itemcount = program[frame->pc + 1];
            Value v = val_tagged(VALUE_ARRAY);
            v.u.a = (Array *)zalloc(sizeof(Array));
            *v.u.a = (Array) { (Value *)zalloc(sizeof(Value) * itemcount), itemcount, itemcount };
            while (itemcount > 0) v.u.a->buf[--itemcount] = frame->stack[--frame->stackpos];
            STACK_PUSH(v)
        
        #define ENTER_FUNC()\
            assert(fn->exists);\
            if (!fn->intrinsic)\
            {\
                Frame * prev = frame;\
                Frame * next = (Frame *)zalloc(sizeof(Frame));\
                assert(next, "Out of memory");\
                PC_INC();\
                next->return_to = frame;\
                frame = next;\
                assert(argcount == fn->argcount, "Function arg count doesn't match");\
                for (size_t i = fn->argcount; i > 0;)\
                    frame->vars[fn->args[--i]] = prev->stack[--prev->stackpos];\
                if (fn->cap_data) frame->caps = fn->cap_data; \
                prev->stack[--prev->stackpos];\
                frame->pc = fn->loc;\
                continue;\
            }\
            handle_intrinsic_func(fn->id, argcount, frame);\
            frame->stackpos -= argcount; // intrinsics
        
        NEXT_CASE(INST_FUNCCALL)
            uint16_t argcount = program[frame->pc + 2];
            Funcdef * fn = &funcs_registered[program[frame->pc + 1]];
            ENTER_FUNC()
        
        NEXT_CASE(INST_FUNCCALL_REF)
            uint16_t argcount = program[frame->pc + 1];
            Value v_func = frame->stack[frame->stackpos - argcount - 1];
            assert(v_func.tag == VALUE_FUNC);
            Funcdef * fn = v_func.u.fn;
            ENTER_FUNC()
        
        NEXT_CASE(INST_RETURN_VAL)
            Value v = frame->stack[--frame->stackpos];
            if (!frame->return_to) return;
            frame = frame->return_to;
            STACK_PUSH(v)
            continue;
        
        NEXT_CASE(INST_RETURN_VOID)
            if (!frame->return_to) return;
            frame = frame->return_to;
            STACK_PUSH(val_tagged(VALUE_NULL))
            continue;
        
        NEXT_CASE(PUSH_NULL)
            STACK_PUSH(val_tagged(VALUE_NULL))
        
        NEXT_CASE(PUSH_DICT_EMPTY)
            Value v = val_tagged(VALUE_DICT);
            v.u.d = (Dict *)zalloc(sizeof(Dict));
            STACK_PUSH(v)
        
        NEXT_CASE(PUSH_NUM)
            double f;
            memcpy(&f, program + frame->pc + 1, 8);
            STACK_PUSH(val_float(f))
        
        NEXT_CASE(PUSH_GLOBAL)
            STACK_PUSH(global_frame->vars[program[frame->pc + 1]])
        NEXT_CASE(INST_SET_GLOBAL)
            Value v = frame->stack[--frame->stackpos];
            global_frame->vars[program[frame->pc + 1]] = v;
        
        NEXT_CASE(PUSH_CAP)
            STACK_PUSH(*frame->caps[program[frame->pc + 1]])
        NEXT_CASE(INST_SET_CAP)
            Value v = frame->stack[--frame->stackpos];
            *frame->caps[program[frame->pc + 1]] = v;
        
        #define GLOBAL_MATH_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            uint16_t id = program[frame->pc + 1];\
            Value v1 = global_frame->vars[id];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");\
            global_frame->vars[id] = val_float(X);
        
        NEXT_CASE(INST_SET_GLOBAL_ADD)    GLOBAL_MATH_SHARED(v1.u.f + v2.u.f)
        NEXT_CASE(INST_SET_GLOBAL_SUB)    GLOBAL_MATH_SHARED(v1.u.f - v2.u.f)
        NEXT_CASE(INST_SET_GLOBAL_MUL)    GLOBAL_MATH_SHARED(v1.u.f * v2.u.f)
        NEXT_CASE(INST_SET_GLOBAL_DIV)    GLOBAL_MATH_SHARED(v1.u.f / v2.u.f)
        
        #define CAP_MATH_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            uint16_t id = program[frame->pc + 1];\
            Value v1 = *frame->caps[id];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");\
            *frame->caps[id] = val_float(X);
        
        NEXT_CASE(INST_SET_CAP_ADD)    CAP_MATH_SHARED(v1.u.f + v2.u.f)
        NEXT_CASE(INST_SET_CAP_SUB)
            Value v2 = frame->stack[--frame->stackpos];
            uint16_t id = program[frame->pc + 1];
            //printf("%p\n", frame->caps);
            //printf("%d\n", id);
            Value v1 = *frame->caps[id];
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");
            *frame->caps[id] = val_float(v1.u.f - v2.u.f);
            
        NEXT_CASE(INST_SET_CAP_MUL)    CAP_MATH_SHARED(v1.u.f * v2.u.f)
        NEXT_CASE(INST_SET_CAP_DIV)    CAP_MATH_SHARED(v1.u.f / v2.u.f)
        
        #define MATH_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");\
            frame->stack[frame->stackpos++] = val_float(X);
        
        NEXT_CASE(INST_ADD)    MATH_SHARED(v1.u.f + v2.u.f)
        NEXT_CASE(INST_SUB)    MATH_SHARED(v1.u.f - v2.u.f)
        NEXT_CASE(INST_MUL)    MATH_SHARED(v1.u.f * v2.u.f)
        NEXT_CASE(INST_DIV)    MATH_SHARED(v1.u.f / v2.u.f)
        NEXT_CASE(INST_CMP_AND)    MATH_SHARED(!!(v1.u.f) && !!(v2.u.f))
        NEXT_CASE(INST_CMP_OR)     MATH_SHARED(!!(v1.u.f) || !!(v2.u.f))
        
        #define EQ_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            int8_t equality = 0;\
            if (v2.tag != v1.tag) equality = 2;\
            else if (v1.tag == VALUE_FLOAT && (v1.u.f != v1.u.f || v2.u.f != v2.u.f)) equality = 2;\
            else if (v1.tag == VALUE_FLOAT && v1.u.f < v2.u.f) equality = -1;\
            else if (v1.tag == VALUE_FLOAT && v1.u.f > v2.u.f) equality = 1;\
            else if (v1.tag == VALUE_STRING) equality = strcmp(v1.u.s, v2.u.s);\
            else if (v1.tag == VALUE_ARRAY && v1.u.a != v2.u.a) equality = 2;\
            frame->stack[frame->stackpos++] = val_float(X);
            // 0: equal, 2: neq (unordered). -1: lt. 1: gt.
        
        NEXT_CASE(INST_CMP_EQ)    EQ_SHARED(equality == 0)
        NEXT_CASE(INST_CMP_NE)    EQ_SHARED(equality != 0)
        NEXT_CASE(INST_CMP_LE)    EQ_SHARED(equality == 0 || equality == 1)
        NEXT_CASE(INST_CMP_GE)    EQ_SHARED(equality == 0 || equality == -1)
        NEXT_CASE(INST_CMP_LT)    EQ_SHARED(equality == 1)
        NEXT_CASE(INST_CMP_GT)    EQ_SHARED(equality == -1)
        
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
            STACK_PUSH(val_string(stringdup(compiled_strings[program[frame->pc + 1]])))
        NEXT_CASE(PUSH_LOCAL)
            STACK_PUSH(frame->vars[program[frame->pc + 1]])
        NEXT_CASE(PUSH_FUNCNAME)
            STACK_PUSH(val_func(program[frame->pc + 1]))
        
        NEXT_CASE(INST_SET)
            frame->vars[program[frame->pc + 1]] = frame->stack[--frame->stackpos];
        
        #define LOCAL_MATH_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            uint16_t id = program[frame->pc + 1];\
            Value v1 = frame->vars[id];\
            assert(v2.tag == VALUE_FLOAT && v1.tag == VALUE_FLOAT, "Math only works on numbers");\
            frame->vars[id] = val_float(X);
        
        NEXT_CASE(INST_SET_ADD)    LOCAL_MATH_SHARED(v1.u.f + v2.u.f)
        NEXT_CASE(INST_SET_SUB)    LOCAL_MATH_SHARED(v1.u.f - v2.u.f)
        NEXT_CASE(INST_SET_MUL)    LOCAL_MATH_SHARED(v1.u.f * v2.u.f)
        NEXT_CASE(INST_SET_DIV)    LOCAL_MATH_SHARED(v1.u.f / v2.u.f)
            
        NEXT_CASE(INST_SET_ADDR)
            Value v2 = frame->stack[--frame->stackpos];
            if (frame->assign_target_agg)   *frame->assign_target_agg = v2;
            else assert(frame->assign_target_char && v2.tag == VALUE_STRING && *v2.u.s != '\0');
            if (frame->assign_target_char)  *frame->assign_target_char = *v2.u.s;
            frame->assign_target_agg = 0;
            frame->assign_target_char = 0;
        
        #define ADDR_MATH_SHARED(X)\
            Value v2 = frame->stack[--frame->stackpos];\
            Value * v1p = frame->assign_target_agg;\
            assert(v1p && v2.tag == VALUE_FLOAT && v1p->tag == VALUE_FLOAT, "Math only works on numbers");\
            frame->assign_target_agg = 0;\
            *v1p = val_float(X);
        
        NEXT_CASE(INST_SET_ADDR_ADD)    ADDR_MATH_SHARED(v1p->u.f + v2.u.f)
        NEXT_CASE(INST_SET_ADDR_SUB)    ADDR_MATH_SHARED(v1p->u.f - v2.u.f)
        NEXT_CASE(INST_SET_ADDR_MUL)    ADDR_MATH_SHARED(v1p->u.f * v2.u.f)
        NEXT_CASE(INST_SET_ADDR_DIV)    ADDR_MATH_SHARED(v1p->u.f / v2.u.f)
        
        #define INDEX_SHARED(STR_VALID_OP)\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            assert(v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY || v1.tag == VALUE_DICT);\
            if (v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY) assert(v2.tag == VALUE_FLOAT);\
            if (v1.tag == VALUE_DICT) assert(v2.tag == VALUE_FLOAT || v2.tag == VALUE_STRING\
                                             || v2.tag == VALUE_FUNC || v2.tag == VALUE_NULL);\
            if (v1.tag == VALUE_STRING) assert(((size_t)v2.u.f) STR_VALID_OP strlen(v1.u.s));
    
        NEXT_CASE(INST_INDEX)    INDEX_SHARED(<=)
            if (v1.tag == VALUE_STRING) v1.u.s = stringdupn(v1.u.s + (size_t)v2.u.f, 1);
            if (v1.tag == VALUE_ARRAY)  v1 = *array_get(v1.u.a, v2.u.f);
            if (v1.tag == VALUE_DICT)   v1 = *dict_get_or_insert(v1.u.d, &v2);
            frame->stack[frame->stackpos++] = v1;
        
        NEXT_CASE(INST_INDEX_ADDR)    INDEX_SHARED(<)
            if (v1.tag == VALUE_STRING) frame->assign_target_char = v1.u.s + (size_t)v2.u.f;
            if (v1.tag == VALUE_ARRAY)  frame->assign_target_agg = array_get(v1.u.a, v2.u.f);
            if (v1.tag == VALUE_DICT)   frame->assign_target_agg = dict_get_or_insert(v1.u.d, &v2);
        
        NEXT_CASE(INST_LAMBDA)
            Value v = val_func(program[frame->pc + 1]);
            Funcdef * f = (Funcdef *)zalloc(sizeof(Funcdef));
            *f = *v.u.fn;
            //printf("%p\n", f->caps);
            if (f->cap_count) f->cap_data = (Value **)zalloc(sizeof(Value *) * f->cap_count);
            for (size_t j = 0; j < f->cap_count; j++)
                f->cap_data[j] = (f->caps[j] < 0) ? frame->caps[-f->caps[j]] : &frame->vars[f->caps[j]];
            v.u.fn = f;
            STACK_PUSH(v)
            READ_AND_GOTO_TARGET(3)
        
        END_CASE()
        DECAULT_CASE()
    CASES_END()
}

void register_intrinsic_func(const char * s)
{
    int16_t id = lex_ident_offset - insert_or_lookup_id(s, strlen(s));
    funcs_registered[id] = (Funcdef) {1, 1, 0, id, prog_i, 0, 0, 0, 0};
}

#include "intrinsics.h"

#endif
