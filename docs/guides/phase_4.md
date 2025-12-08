

## Phase 4: Operations Implementation

### Prompt 4.1: Arithmetic Operations

```
TASK: Implement all arithmetic operations with exact Scala semantics

CONTEXT (From Ergo Core Developers):
"Arithmetic in ErgoTree follows Scala/Java semantics:
- Signed integers only (no unsigned types in user-facing API)
- Overflow throws exception (not silent wrap)
- Division truncates toward zero
- Modulo follows truncating division

BigInt arithmetic is arbitrary precision but capped at 256 bits.
Operations on different types are NOT allowed - type must match exactly."

PREREQUISITE KNOWLEDGE:
- Byte, Short, Int, Long are signed
- Overflow detection is required
- Division by zero throws exception
- BigInt needs arbitrary precision library
- All operations are binary (left op right)

CREATE FILE: src/interpreter/ops/arithmetic.zig

OPERATIONS TO IMPLEMENT:
```zig
// For each operation, implement for all numeric types:
// Byte (i8), Short (i16), Int (i32), Long (i64), BigInt (256-bit)

/// Addition with overflow check
pub fn add(comptime T: type, a: T, b: T) !T {
    const result = @addWithOverflow(a, b);
    if (result[1] != 0) return error.ArithmeticOverflow;
    return result[0];
}

/// Subtraction with overflow check
pub fn sub(comptime T: type, a: T, b: T) !T {
    const result = @subWithOverflow(a, b);
    if (result[1] != 0) return error.ArithmeticOverflow;
    return result[0];
}

/// Multiplication with overflow check
pub fn mul(comptime T: type, a: T, b: T) !T {
    const result = @mulWithOverflow(a, b);
    if (result[1] != 0) return error.ArithmeticOverflow;
    return result[0];
}

/// Division (truncating toward zero)
pub fn div(comptime T: type, a: T, b: T) !T {
    if (b == 0) return error.DivisionByZero;
    // Special case: MIN / -1 overflows
    if (T == i8 and a == -128 and b == -1) return error.ArithmeticOverflow;
    if (T == i16 and a == -32768 and b == -1) return error.ArithmeticOverflow;
    if (T == i32 and a == -2147483648 and b == -1) return error.ArithmeticOverflow;
    if (T == i64 and a == -9223372036854775808 and b == -1) return error.ArithmeticOverflow;
    return @divTrunc(a, b);
}

/// Modulo (following truncating division)
pub fn mod(comptime T: type, a: T, b: T) !T {
    if (b == 0) return error.DivisionByZero;
    return @rem(a, b);
}

/// Negation with overflow check
pub fn negate(comptime T: type, a: T) !T {
    // MIN cannot be negated
    if (a == std.math.minInt(T)) return error.ArithmeticOverflow;
    return -a;
}

/// Minimum
pub fn min(comptime T: type, a: T, b: T) T {
    return @min(a, b);
}

/// Maximum
pub fn max(comptime T: type, a: T, b: T) T {
    return @max(a, b);
}
```

BIGINT OPERATIONS:
```zig
/// 256-bit integer operations
pub const BigInt = struct {
    /// Internal representation: 32 bytes, little-endian, two's complement
    bytes: [32]u8,
    
    pub fn add(a: BigInt, b: BigInt) !BigInt {
        // Implement 256-bit addition with carry
        // Check for overflow (result > 2^255-1 or < -2^255)
    }
    
    pub fn multiply(a: BigInt, b: BigInt) !BigInt {
        // Implement 256-bit multiplication
        // Result must fit in 256 bits
    }
    
    // Note: Division and modulo for BigInt are complex
    // May want to use external library or careful implementation
};
```

TESTS:
[ ] Addition: 1 + 2 = 3
[ ] Addition: MAX + 1 overflows
[ ] Subtraction: 5 - 3 = 2
[ ] Subtraction: MIN - 1 overflows
[ ] Multiplication: 6 * 7 = 42
[ ] Multiplication: MAX * 2 overflows
[ ] Division: 7 / 3 = 2 (truncates toward zero)
[ ] Division: -7 / 3 = -2 (not -3)
[ ] Division: 1 / 0 error
[ ] Modulo: 7 % 3 = 1
[ ] Modulo: -7 % 3 = -1 (follows division)
[ ] Negation: -MIN overflows
[ ] BigInt: basic operations
[ ] Type mismatch rejected
```

### Prompt 4.2: Comparison Operations

```
TASK: Implement comparison operations for all comparable types

CONTEXT (From Zig Experts):
"Comparison in ErgoTree works on ordered types (numerics) and
any type for equality. GroupElement comparison is defined
(lexicographic on encoded bytes). SigmaProp comparison is structural."

PREREQUISITE KNOWLEDGE:
- < <= > >= work on numeric types
- == != work on all types
- Collections compared element-wise
- Tuples compared component-wise
- Options: None < Some, then compare inner

CREATE FILE: src/interpreter/ops/comparison.zig

IMPLEMENTATION:
```zig
/// Compare ordered values
pub fn compareOrdered(
    state: *const InterpreterState,
    a: ValueRef,
    b: ValueRef,
) !std.math.Order {
    if (a.type_code != b.type_code) return error.TypeMismatch;
    
    switch (a.type_code) {
        @intFromEnum(PrimType.byte),
        @intFromEnum(PrimType.short),
        @intFromEnum(PrimType.int),
        @intFromEnum(PrimType.long) => {
            const a_val = state.stack.getInt(a.slot);
            const b_val = state.stack.getInt(b.slot);
            return std.math.order(a_val, b_val);
        },
        @intFromEnum(PrimType.big_int) => {
            return compareBigInt(state, a, b);
        },
        else => return error.TypeNotOrdered,
    }
}

/// Compare for equality (works on all types)
pub fn equals(
    state: *const InterpreterState,
    a: ValueRef,
    b: ValueRef,
) !bool {
    if (a.type_code != b.type_code) return false;
    
    switch (a.type_code) {
        @intFromEnum(PrimType.boolean) => {
            return state.stack.getBool(a.slot) == state.stack.getBool(b.slot);
        },
        @intFromEnum(PrimType.byte),
        @intFromEnum(PrimType.short),
        @intFromEnum(PrimType.int),
        @intFromEnum(PrimType.long) => {
            return state.stack.getInt(a.slot) == state.stack.getInt(b.slot);
        },
        @intFromEnum(PrimType.big_int) => {
            return compareBigInt(state, a, b) == .eq;
        },
        @intFromEnum(PrimType.group_element) => {
            return compareGroupElement(state, a, b);
        },
        @intFromEnum(PrimType.sigma_prop) => {
            return compareSigmaProp(state, a, b);
        },
        else => {
            // For complex types, need recursive comparison
            return compareComplex(state, a, b);
        },
    }
}

fn compareComplex(
    state: *const InterpreterState,
    a: ValueRef,
    b: ValueRef,
) !bool {
    const type_idx = state.getTypeFromRef(a);
    const stype = state.types.get(type_idx);
    
    switch (stype) {
        .coll => {
            const coll_a = state.collections.get(state.stack.getRef(a.slot));
            const coll_b = state.collections.get(state.stack.getRef(b.slot));
            
            if (coll_a.len != coll_b.len) return false;
            
            const elems_a = state.collections.getElements(coll_a);
            const elems_b = state.collections.getElements(coll_b);
            
            for (elems_a, elems_b) |ea, eb| {
                if (!try equals(state, ea, eb)) return false;
            }
            return true;
        },
        .tuple => |t| {
            const elems_a = state.getTupleElements(a);
            const elems_b = state.getTupleElements(b);
            
            for (0..t.len) |i| {
                if (!try equals(state, elems_a[i], elems_b[i])) return false;
            }
            return true;
        },
        .option => {
            // Compare None/Some and inner values
            return compareOption(state, a, b);
        },
        else => return error.TypeNotComparable,
    }
}

/// Comparison operations
pub fn lt(state: *const InterpreterState, a: ValueRef, b: ValueRef) !bool {
    return (try compareOrdered(state, a, b)) == .lt;
}

pub fn le(state: *const InterpreterState, a: ValueRef, b: ValueRef) !bool {
    const order = try compareOrdered(state, a, b);
    return order == .lt or order == .eq;
}

pub fn gt(state: *const InterpreterState, a: ValueRef, b: ValueRef) !bool {
    return (try compareOrdered(state, a, b)) == .gt;
}

pub fn ge(state: *const InterpreterState, a: ValueRef, b: ValueRef) !bool {
    const order = try compareOrdered(state, a, b);
    return order == .gt or order == .eq;
}
```

TESTS:
[ ] Numeric comparisons: 1 < 2, 2 <= 2, 3 > 2, etc.
[ ] BigInt comparisons
[ ] Boolean equality
[ ] Collection equality (same elements)
[ ] Collection inequality (different length)
[ ] Tuple equality
[ ] Option equality (None == None, Some(1) == Some(1))
[ ] GroupElement equality
[ ] Type mismatch handling
```

### Prompt 4.3-4.7: Remaining Operations

I'll provide a condensed prompt template for the remaining operation categories:

```
TASK: Implement [CATEGORY] operations

CATEGORIES REMAINING:
- 4.3: Logical operations (and_op, or_op, at_least, logical_not, bin_and, bin_or, bin_xor)
- 4.4: Collection operations (size_of, by_index, slice, append, map, fold, filter, exists, forall, flatMap)
- 4.5: Box operations (extract_amount, extract_script_bytes, extract_bytes, extract_id, extract_register, tokens)
- 4.6: Context operations (height, inputs, outputs, self_box, get_var, data_inputs, headers, pre_header)
- 4.7: Higher-order operations (func_value, apply, map_collection, fold, filter)

FOR EACH CATEGORY:
1. Extract exact semantics from Scala implementation
2. Implement with proper error handling
3. Add cost accounting
4. Test against reference implementation

COMMAND TO FIND SCALA IMPLEMENTATION:
```bash
grep -rn "def [operationName]\|case.*[OperationName]" \
  --include="*.scala" -A 20 | head -100
```

KEY FILES:
- sigmastate/src/main/scala/sigmastate/eval/ErgoTreeEvaluator.scala
- sigmastate/src/main/scala/sigmastate/interpreter/Interpreter.scala
- core/src/main/scala/sigma/ast/operations.scala
```

---
