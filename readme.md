# Filli

Filli is an ultra small (language code under 1000 cloc) dynamic programming language written in pure C (C23) with no dependencies.

Embeddable, header-only, not horribly slow, and configurable. The reference `.fil` file runner compiles down to 34 KB with `clang -Os -flto` etc. Depending on compiler flags, the microbenchmarks I've tested vary from 35% to 50% the runtime of the Lua equivalent -- Lua is a very fast interpreter, so this means that Filli isn't horribly inefficient.

Meant to be used while linking to BDW GC ("Boehm" GC) or some similar interior-pointer-aware conservative GC. If your Filli threads are only ever going to be short lived, you can #define NO_GC before including it to disable all the GC stuff. 

## Features

- VERY small implementation
- - Language code is less than 1000 cloc
- - Reference application compiles down to ~34KB
- Familiar lua-like syntax
- - Not indentation-sensitive
- - Newlines separate statements unless preceded by \
- - Comments are `#`, not `;`, so hashbangs work
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