#ifndef FILLI_H_INCLUDED
#define FILLI_H_INCLUDED

#define IDENTIFIER_COUNT 32000
#define FRAME_VARCOUNT 1024 // increases memory usage of stack frames
#define FRAME_STACKSIZE 1024 // increases memory usage of stack frames
#define PROGRAM_MAXLEN 100000 // default max length of program
#define FORLOOP_COUNT_LIMIT 255 // increases memory usage of stack frames
#define ARGLIMIT 255 // affects risk of stack smashing during compilation
#define ELIFLIMIT 255 // affects risk of stack smashing during compilation

// OTHER LIMITS

// micro stdlib replacement stuff to reduce binary size (yes, this has a big effect)

#include "microlib.h"

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
//      return a malloc-allocated copy of s, stopping at len
//      null terminated. stops at any null byte.
// char * stringdup(const char * s);
//      return a malloc-allocated copy of s
//      null terminated

// void prints(const char * s);
//      dump every character in s to stdout
// void eprints(const char * s);
//      dump every character in s to stderr
// void printu16hex(uint16_t x);
//      stdout print the given short as if with "%04X", no trailing newline
// void printsn(const char * s, size_t len);
//      stdout print the first n characters from s, stopping at any 0 bytes, no trailing newline
// double badstrtod(const char * s);
//      parse the given string as a 64-bit float, silently stopping wherever it stops looking like a float
//      does not need to be accurate
// const char * baddtostr(double f);
//      return a malloc-allocated string containing something similar to sprintf %f
//      does not need to be accurate

// actual program

typedef struct _IdEntry { const char * where; uint16_t len; } IdEntry;

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
    lex_ident_offset = highest_ident_id;
}
#define MIN_KEYWORD -13

Token * tokenize(const char * src, size_t * count)
{
    int newline_is_token = 1;
    
    const char * long_punctuation[] = { "==", "!=", ">=", "<=", "+=", "-=", "*=", "/=", "{}" };
    
    size_t len = strlen(src);
    
    Token * ret = (Token *)malloc(sizeof(Token) * len);
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
            
            ret[t++] = mk_token(start_i, i-start_i, insert_or_lookup_id(src + start_i, i - start_i));
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
    INST_DISCARD = 0x100,
    PUSH_NULL, PUSH_DICT_EMPTY,
    INST_RETURN_VAL, INST_RETURN_VOID,
    INST_ADD, INST_SUB, INST_MUL, INST_DIV,
    INST_CMP_EQ, INST_CMP_NE, INST_CMP_GT, INST_CMP_LT, INST_CMP_GE, INST_CMP_LE,
    INST_INDEX,
    INST_INDEX_ADDR, INST_ASSIGN_ADDR,
    INST_ASSIGN_ADDR_ADD, INST_ASSIGN_ADDR_SUB, INST_ASSIGN_ADDR_MUL, INST_ASSIGN_ADDR_DIV,
    // 1-op
    PUSH_FUNCNAME = 0x220,
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
    INST_JMP = 0x340, // destination
    INST_JMP_IF_FALSE, // destination
    INST_JMP_IF_TRUE, // destination
    INST_FUNCDEF, // skip destination
    INST_FUNCCALL, // func id, arg count
    // 4-op
    INST_FOREND = 0x560, // var id (2), for slot (2), destination (4)
    INST_FORSTART, // var id (2), for slot (2), end of loop (4) (needed if loop val is 0)
    PUSH_NUM, // f64
};

// FIXME: make non-global
uint16_t * program = 0;
uint32_t prog_capacity = PROGRAM_MAXLEN;
void init_program() { program = malloc(sizeof(uint16_t) * prog_capacity); }
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

typedef struct _Funcdef {
    uint8_t exists; uint8_t intrinsic; uint8_t argcount; uint8_t id;
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
        else if (!in_global && locals_registered[lex_ident_offset-tokens[i].kind])
            prog_write(PUSH_LOCAL);
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
        prog_write(lex_ident_offset - tokens[i].kind);
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

size_t compile_expr(const char * source, Token * tokens, size_t count, size_t i, int right_bind_power);
size_t compile_binexpr(const char * source, Token * tokens, size_t count, size_t i);

size_t compile_innerexpr(const char * source, Token * tokens, size_t count, size_t i)
{
    if (i >= count) return 0;
    if (token_is(source, tokens, count, i, "(")) // wrapped expr
    {
        size_t ret = compile_expr(source, tokens, count, i+1, 0) + 1;
        assert(token_is(source, tokens, count, i + ret, ")"), "Unclosed parens");
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
            assert(j < 32000, "Too many values in array literal (limit is 32000)");
            j += 1;
            i += r;
            
            if (!(token_is(source, tokens, count, i, "]") || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, "]")) return 0;
        
        prog_write2(INST_ARRAY_LITERAL, j);
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
            assert(j++ < ARGLIMIT, "Too many arguments to function");
            i += r;
            
            if (!(token_is(source, tokens, count, i, ")") || token_is(source, tokens, count, i, ",")))
                return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, ")")) return 0;
        
        prog_write2(INST_FUNCCALL_EXPR, j);
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
            
            if (tokens[i].kind == -3)
            {
                i += compile_expr(source, tokens, count, i + 1, 0) + 1;
                assert(token_is(source, tokens, count, i++, ":"));
                prog_write3(INST_JMP_IF_FALSE, 0, 0);
                size_t jump_at = prog_i - 2;
                
                i += compile_statementlist(source, tokens, count, i);
                
                uint32_t end = prog_i + ((tokens[i].kind == -3 || tokens[i].kind == -2) ? 3 : 0);
                memcpy(program + jump_at, &end, 4);
            }
            else if (++i)
            {
                assert(token_is(source, tokens, count, i++, ":"));
                i += compile_statementlist(source, tokens, count, i);
            }
        }
        assert(tokens[i].kind == -12, "Missing end keyword");
        uint32_t real_end = prog_i;
        while (skip_i > 0) memcpy(program + skips[--skip_i], &real_end, 4);
        i += 1;
        
        return i - orig_i;
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
        assert(tokens[i].kind == -12, "Missing end keyword"); // end
        
        uint32_t cont_to = prog_i;
        compile_expr(source, tokens, count, expr_i, 0); // recompile test expr
        prog_write3(INST_JMP_IF_TRUE, 0, 0);
        memcpy(program + (prog_i - 2), &loop_at, 4);
        
        uint32_t end = prog_i;
        memcpy(program + skip_at, &end, 4);
        i += 1;
        
        uint32_t break_to = prog_i;
        while (loop_break_i > loop_break_base) memcpy(program + loop_breaks[--loop_break_i], &break_to, 4);
        while (loop_cont_i  > loop_cont_base ) memcpy(program + loop_conts [--loop_cont_i ], &cont_to , 4);
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
            if (!r) return i - orig_i;
            i += r + 1;
            prog_write2(INST_ASSIGN + in_global, id);
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
        if (in_global) globals_registered[id] = 1;
        else           locals_registered[id] = 1;
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
        assert(tokens[i++].kind == -12, "Missing end keyword");
        
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
        
        uint8_t is_global;
        if (!in_global && locals_registered[id]) is_global = 0;
        else if (globals_registered[id]) is_global = 1;
        else panic("Unknown variable");
        
        if (strncmp(opstr, "=", oplen) == 0)       prog_write(INST_ASSIGN + is_global);
        else if (strncmp(opstr, "+=", oplen) == 0) prog_write(INST_ASSIGN_ADD + is_global);
        else if (strncmp(opstr, "-=", oplen) == 0) prog_write(INST_ASSIGN_SUB + is_global);
        else if (strncmp(opstr, "*=", oplen) == 0) prog_write(INST_ASSIGN_MUL + is_global);
        else if (strncmp(opstr, "/=", oplen) == 0) prog_write(INST_ASSIGN_DIV + is_global);
        
        prog_write(id);
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
            assert(j++ < ARGLIMIT, "Too many arguments to function");
            i += r;
            
            if (!(token_is(source, tokens, count, i, ")")
                || token_is(source, tokens, count, i, ","))) return 0;
            if (token_is(source, tokens, count, i, ",")) i++;
        }
        if (!token_is(source, tokens, count, i++, ")")) return 0;
        
        prog_write3(INST_FUNCCALL, id, j);
        
        prog_write(INST_DISCARD);
        return i - orig_i;
    }
    else if (tokens[i].kind == -12 || tokens[i].kind == -3 || tokens[i].kind == -2) // end, elif, else
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
        
        if ((token_is(source, tokens, count, i, "=")
             || token_is(source, tokens, count, i, "+=") || token_is(source, tokens, count, i, "-=")
             || token_is(source, tokens, count, i, "*=") || token_is(source, tokens, count, i, "/="))
            && program[prog_i - 1] == INST_INDEX)
        {
            size_t old_i = i;
            uint32_t checkpoint = prog_i - 1;
            size_t r2 = compile_expr(source, tokens, count, i + 1, 0);
            if (!r2) { prog_write(INST_DISCARD); return r; }
            r += r2 + 1;
            program[checkpoint] = INST_INDEX_ADDR;
            if (token_is(source, tokens, count, old_i, "=" )) prog_write(INST_ASSIGN_ADDR);
            if (token_is(source, tokens, count, old_i, "+=")) prog_write(INST_ASSIGN_ADDR_ADD);
            if (token_is(source, tokens, count, old_i, "-=")) prog_write(INST_ASSIGN_ADDR_SUB);
            if (token_is(source, tokens, count, old_i, "*=")) prog_write(INST_ASSIGN_ADDR_MUL);
            if (token_is(source, tokens, count, old_i, "/=")) prog_write(INST_ASSIGN_ADDR_DIV);
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
size_t compile_func(const char * source, Token * tokens, size_t count, size_t i)
{
    size_t orig_i = i;
    if (i >= count) return 0;
    if (tokens[i].kind >= MIN_KEYWORD) return 0;
    int16_t id = lex_ident_offset - tokens[i++].kind;
    if (!token_is(source, tokens, count, i++, "(")) return 0;
    uint16_t args[ARGLIMIT];
    uint32_t j = 0;
    while (1)
    {
        if (token_is(source, tokens, count, i, ")")) { i += 1; break; }
        if (tokens[i].kind >= MIN_KEYWORD) return 0;
        assert(j < ARGLIMIT);
        args[j++] = lex_ident_offset - tokens[i++].kind;
        locals_registered[args[j - 1]] = 1;
        if (!(token_is(source, tokens, count, i, ")")
              || token_is(source, tokens, count, i, ","))) return 0;
        if (token_is(source, tokens, count, i, ",")) i++;
    }
    if (!token_is(source, tokens, count, i++, ":")) return 0;
    
    prog_write3(INST_FUNCDEF, 0, 0);
    size_t len_offs = prog_i - 2;
    
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
            assert(r != 0, "Incomplete function");
            i += r + 1;
            
            assert(tokens[i++].kind == -12, "Missing end keyword");
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
struct _BiValue;
typedef struct _Array { struct _Value * buf; size_t len; size_t cap; } Array;
typedef struct _Dict { struct _BiValue * buf; size_t len; size_t cap; } Dict;

// tag
enum { VALUE_INVALID, VALUE_FLOAT, VALUE_ARRAY, VALUE_DICT, VALUE_STRING, VALUE_FUNC, VALUE_NULL };

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
    uint64_t hv = 0xf1357aea2e62a9c5;
    
    hash = (hash + v->tag) * hv;
    if (v->tag == VALUE_FLOAT)
    {
        uint64_t n = 0;
        memcpy(&n, &v->u.f, 8);
        hash = (hash + n) * hv;
    }
    else if (v->tag == VALUE_STRING)
        for (size_t i = 0; v->u.s[i] != 0; i++) hash = (hash + v->u.s[i]) * hv;
    else if (v->tag == VALUE_FUNC)
        hash = (hash + v->u.fn->id) * hv;
    
    return hash ^ (hash >> 6);
}

// newcap must be a power of 2
void dict_reallocate(Dict * d, size_t newcap)
{
    size_t mask = newcap - 1;
    BiValue * newbuf = malloc(sizeof(BiValue) * newcap);
    memset(newbuf, 0, sizeof(BiValue) * newcap);
    for (size_t i = 0; i < d->len; i++)
    {
        Value * l = &d->buf[i].l;
        Value * r = &d->buf[i].r;
        uint64_t hash = val_hash(l) & mask;
        while (newbuf[hash].l.tag == VALUE_INVALID) hash = (hash + 1) & mask;
        newbuf[hash].l = *l;
        newbuf[hash].r = *r;
    }
    d->cap = newcap;
    d->buf = newbuf;
}
Value * dict_get_or_insert(Dict * d, Value * v)
{
    if (d->cap == 0) dict_reallocate(d, 64);
    // max 50% load factor
    if (d->len * 2 > d->cap) dict_reallocate(d, d->cap * 2);
    
    size_t mask = d->cap - 1;
    
    uint64_t hash = val_hash(v) & mask;
    while (val_eq(v, &d->buf[hash].l)) hash = (hash + 1) & mask;
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
    size_t pc;
    struct _Frame * return_to;
    size_t stackpos;
    Value * assign_target_agg;
    char * assign_target_char;
    Value vars[FRAME_VARCOUNT];
    Value stack[FRAME_STACKSIZE];
    double forloops[FORLOOP_COUNT_LIMIT];
} Frame;

void print_op_and_panic(uint16_t op)
{
    prints("---\n");
    printu16hex(op);
    prints("\n---\n");
    panic("TODO");
}

void handle_intrinsic_func(uint16_t id, size_t argcount, Frame * frame);

void interpret(void)
{
    Frame * frame = (Frame *)malloc(sizeof(Frame));
    assert(frame, "Out of memory");
    
    Frame * global_frame = frame;

    #define CASES_START() \
    while (1) {\
        uint16_t op = program[frame->pc];\
        switch (op) {
    #define CASES_END() } }
    
    #define PC_INC() frame->pc += op >> 8
    
    #define MARK_CASE(X) case X: {
    #define END_CASE() PC_INC(); continue; }
    #define DECAULT_CASE() default: print_op_and_panic(op);
    
    #define NEXT_CASE(X) END_CASE() MARK_CASE(X)

    memset(frame, 0, sizeof(Frame));
    
    CASES_START()
        
        #define READ_AND_GOTO_TARGET(X)\
            { uint32_t target; memcpy(&target, program + (frame->pc + X), 4); frame->pc = target; continue; }
        
        MARK_CASE(INST_INVALID)     return;
        NEXT_CASE(INST_DISCARD)     --frame->stackpos;
        NEXT_CASE(INST_FUNCDEF)     READ_AND_GOTO_TARGET(1)
        
        NEXT_CASE(INST_ARRAY_LITERAL)
            uint16_t itemcount = program[frame->pc + 1];
            Value v = val_tagged(VALUE_ARRAY);
            v.u.a = (Array *)malloc(sizeof(Array));
            v.u.a->buf = (Value *)malloc(sizeof(Value) * itemcount);
            v.u.a->len = itemcount;
            v.u.a->cap = itemcount;
            while (itemcount > 0) v.u.a->buf[--itemcount] = frame->stack[--frame->stackpos];
            frame->stack[frame->stackpos++] = v;
            assert(frame->stackpos < FRAME_STACKSIZE);
        
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
                assert(next, "Out of memory");\
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
            assert(frame->stackpos < FRAME_STACKSIZE);
            continue;
        
        NEXT_CASE(INST_RETURN_VOID)
            if (!frame->return_to) return;
            frame = frame->return_to;
            frame->stack[frame->stackpos++] = val_float(0.0);
            assert(frame->stackpos < FRAME_STACKSIZE);
            continue;
        
        NEXT_CASE(PUSH_NULL)
            frame->stack[frame->stackpos++] = val_tagged(VALUE_NULL);
        
        NEXT_CASE(PUSH_DICT_EMPTY)
            memset(&frame->stack[frame->stackpos], 0, sizeof(Value));
            frame->stack[frame->stackpos].tag = VALUE_DICT;
            frame->stack[frame->stackpos++].u.d = (Dict *)malloc(sizeof(Dict));
        
        NEXT_CASE(PUSH_NUM)
            double f;
            memcpy(&f, program + frame->pc + 1, 8);
            frame->stack[frame->stackpos++] = val_float(f);
            assert(frame->stackpos < FRAME_STACKSIZE);
        NEXT_CASE(PUSH_GLOBAL)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = global_frame->vars[id];
            assert(frame->stackpos < FRAME_STACKSIZE);
        
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
            // 0: equal, 2: neq (unordered). -1: lt. 1: gt.
        
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
            assert(frame->stackpos < FRAME_STACKSIZE);
        NEXT_CASE(PUSH_LOCAL)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = frame->vars[id];
            assert(frame->stackpos < FRAME_STACKSIZE);
        NEXT_CASE(PUSH_FUNCNAME)
            uint16_t id = program[frame->pc + 1];
            frame->stack[frame->stackpos++] = val_func(id);
            assert(frame->stackpos < FRAME_STACKSIZE);
        
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
            frame->vars[id] = val_float(v1.u.f / v2.u.f);
            
        NEXT_CASE(INST_ASSIGN_ADDR)
            Value v2 = frame->stack[--frame->stackpos];
            if (frame->assign_target_agg)
                *frame->assign_target_agg = v2;
            else
                assert(frame->assign_target_char && v2.tag == VALUE_STRING && *v2.u.s != '\0');
            if (frame->assign_target_char)
                *frame->assign_target_char = *v2.u.s;
            frame->assign_target_agg = 0;
            frame->assign_target_char = 0;
        
        #define ADDR_MATH_SHARED()\
            Value v2 = frame->stack[--frame->stackpos];\
            Value * v1p = frame->assign_target_agg;\
            assert(v1p && v2.tag == VALUE_FLOAT && v1p->tag == VALUE_FLOAT, "Math only works on numbers");\
            frame->assign_target_agg = 0;
        
        NEXT_CASE(INST_ASSIGN_ADDR_ADD)    ADDR_MATH_SHARED()
            *v1p = val_float(v1p->u.f + v2.u.f);
        NEXT_CASE(INST_ASSIGN_ADDR_SUB)    ADDR_MATH_SHARED()
            *v1p = val_float(v1p->u.f - v2.u.f);
        NEXT_CASE(INST_ASSIGN_ADDR_MUL)    ADDR_MATH_SHARED()
            *v1p = val_float(v1p->u.f * v2.u.f);
        NEXT_CASE(INST_ASSIGN_ADDR_DIV)    ADDR_MATH_SHARED()
            *v1p = val_float(v1p->u.f / v2.u.f);
        
        #define INDEX_SHARED(STR_VALID_OP)\
            Value v2 = frame->stack[--frame->stackpos];\
            Value v1 = frame->stack[--frame->stackpos];\
            assert(v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY || v1.tag == VALUE_DICT);\
            if (v1.tag == VALUE_STRING || v1.tag == VALUE_ARRAY)\
                assert(v2.tag == VALUE_FLOAT);\
            if (v1.tag == VALUE_DICT)\
                assert(v2.tag == VALUE_FLOAT || v2.tag == VALUE_STRING\
                       || v2.tag == VALUE_FUNC || v2.tag == VALUE_NULL);\
            if (v1.tag == VALUE_STRING)\
                assert(((size_t)v2.u.f) STR_VALID_OP strlen(v1.u.s));
    
        NEXT_CASE(INST_INDEX)    INDEX_SHARED(<=)
            if (v1.tag == VALUE_STRING) v1.u.s = stringdupn(v1.u.s + (size_t)v2.u.f, 1);
            if (v1.tag == VALUE_ARRAY)  v1 = *array_get(v1.u.a, v2.u.f);
            if (v1.tag == VALUE_DICT)   v1 = *dict_get_or_insert(v1.u.d, &v2);
            frame->stack[frame->stackpos++] = v1;
        
        NEXT_CASE(INST_INDEX_ADDR)    INDEX_SHARED(<)
            if (v1.tag == VALUE_STRING) frame->assign_target_char = v1.u.s + (size_t)v2.u.f;
            if (v1.tag == VALUE_ARRAY)  frame->assign_target_agg = array_get(v1.u.a, v2.u.f);
            if (v1.tag == VALUE_DICT)   frame->assign_target_agg = dict_get_or_insert(v1.u.d, &v2);
        
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

#include "intrinsics.h"

#endif
