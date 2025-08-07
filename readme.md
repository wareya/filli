# Filli

Filli is an ultra small (language code under 1000 cloc) dynamic programming language written in pure C (C23) with no dependencies.

Embeddable, header-only, not horribly slow, and configurable. The reference `.fil` file runner compiles down to ~30KB with `clang -Os -flto` etc. (Hello World compiles down to ~14KB with the same setup, so Filli only is only "costing" 20KB out of that 30KB.)

Depending on compiler flags, the microbenchmarks I've tested vary from 35% to 50% the runtime of the Lua equivalent -- Lua is a very fast interpreter, so this means that Filli isn't horribly inefficient.

Filli is meant to be used with BDWGC (aka Boehm GC) or some similar interior-pointer-aware conservative GC. If your Filli threads are only ever going to be short lived, you can #define NO_GC before including it to disable all the GC stuff.

## Features

- VERY small implementation
- - Language code is less than 1000 cloc
- - Reference application compiles down to ~30KB
- Easy to embed
- Familiar lua-like syntax
- - Not indentation-sensitive
- - Comments are `#`, not `;`, so hashbangs work
- - Newlines separate statements unless preceded by \
- In-place math assignment, unlike Lua
- Dynamically typed, imperative and functional
- Function-scoped variables with downwards visibility
- Support for closure lambdas
- Arrays (shared references)
- Dictionaries (shared references)
- Strings (shared references)
- Double-precision floats
- Function references
- Control flow: `if`, `for`-range, and `while` loops
- - Loops support `break` and `continue`
- - No `goto`
- No type coersion of any kind
- - (equality checks accept unalike arguments and return as unordered-unequal)
- Limited "stdlib", print() only; not automatically exposed to your C environment
- Root-level code runs normally, ergonomic for scripting

## Examples

Functions, math, in-place math assignment:

```python
# the "Too Simple" pi calculation benchmark, slightly modified
func calc(n):
    let sum = 0
    let flip = 1
    print(n)
    print(sum)
    print(flip)
    for i in n:
        sum += flip / (2 * i + 1)
        flip *= -1
    end
    return sum
end

let sum = calc(100000)
```

Closure lambdas:

```python
func fwrap():
    let z = 5 + 1
    let f = lambda[z](): z -= 0.93 print(z) end
    f()
    f()
    return f
end

let f = fwrap()
f()
f()

# prints:
# 5.070000000
# 4.140000000
# 3.210000000
# 2.280000000
```

Strings, arrays, and dicts:

```python
let array = [3,1,4,5];
print(array[2]);
array[2] += 3;
print(array[2]);
array[2] = 1.414;
print(array[2]);

let string = "Hello, world!"
print(string)
string[0] = "h"
print(string)
string[6] = "_"
print(string)

let dict = {}
print(dict)
print(dict["a"])
dict["a"] = 429.351293;
print(dict["a"])
```

## Integration

Include `filli.h` in your project, as well as `intrinsics.h` and `microlib.h`. Add `#include "filli.h"` or similar to a SINGLE translation unit in your project and then re-expose it from there.

**Filli intentionally leaks memory!** You should include libgc / BDWGC before including `filli.h`, like so:

```c
#include <gc.h>
#define malloc(X) GC_MALLOC(X)
#define calloc(X, Y) GC_MALLOC(X*Y)
#define realloc(X, Y) GC_REALLOC(X, Y)
#define free(X) GC_FREE(X)
```

Read `microlib.h` and consider replacing it with wrappers around stdlib functions. In particular, the float-vs-string-related functions aren't particularly accurate and you should consider replacing them with more accurate ones.

If you need to add more predefined functions, add them in `intrinsics.h`.

Filli uses assertions to validate that it's not about to do something invalid or memory-unsafe, so if you accept user-defined scripts, run it on a separate thread and check for premature termination.

## License

Apache 2.0 and/or MIT, at your choice. Coypright 2025 "wareya" and any contributors.

