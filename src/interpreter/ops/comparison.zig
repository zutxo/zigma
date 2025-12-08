//! Comparison Operations for ErgoTree Interpreter
//!
//! Implements comparison operations for ordered types (numerics)
//! and equality for all types.
//!
//! Reference: sigmastate/src/main/scala/sigmastate/eval/ErgoTreeEvaluator.scala

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Ordering Results
// ============================================================================

/// Comparison result (mirrors std.math.Order)
pub const Order = enum {
    less_than,
    equal,
    greater_than,
};

// ============================================================================
// Generic Comparison Operations
// ============================================================================

/// Compare two ordered values
pub fn compare(comptime T: type, a: T, b: T) Order {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    if (a < b) return .less_than;
    if (a > b) return .greater_than;
    return .equal;
}

/// Less than
pub fn lt(comptime T: type, a: T, b: T) bool {
    return compare(T, a, b) == .less_than;
}

/// Less than or equal
pub fn le(comptime T: type, a: T, b: T) bool {
    const ord = compare(T, a, b);
    return ord == .less_than or ord == .equal;
}

/// Greater than
pub fn gt(comptime T: type, a: T, b: T) bool {
    return compare(T, a, b) == .greater_than;
}

/// Greater than or equal
pub fn ge(comptime T: type, a: T, b: T) bool {
    const ord = compare(T, a, b);
    return ord == .greater_than or ord == .equal;
}

/// Equal
pub fn eq(comptime T: type, a: T, b: T) bool {
    return a == b;
}

/// Not equal
pub fn neq(comptime T: type, a: T, b: T) bool {
    return a != b;
}

// ============================================================================
// i64-based Comparisons (for evaluator Value compatibility)
// ============================================================================

/// Compare two i64 values, returns -1, 0, or 1
pub fn compareI64(a: i64, b: i64) i2 {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

/// Less than for i64
pub fn ltI64(a: i64, b: i64) bool {
    return a < b;
}

/// Less than or equal for i64
pub fn leI64(a: i64, b: i64) bool {
    return a <= b;
}

/// Greater than for i64
pub fn gtI64(a: i64, b: i64) bool {
    return a > b;
}

/// Greater than or equal for i64
pub fn geI64(a: i64, b: i64) bool {
    return a >= b;
}

/// Equal for i64
pub fn eqI64(a: i64, b: i64) bool {
    return a == b;
}

/// Not equal for i64
pub fn neqI64(a: i64, b: i64) bool {
    return a != b;
}

// ============================================================================
// Boolean Equality
// ============================================================================

/// Equal for bool
pub fn eqBool(a: bool, b: bool) bool {
    return a == b;
}

/// Not equal for bool
pub fn neqBool(a: bool, b: bool) bool {
    return a != b;
}

// ============================================================================
// Byte Array Comparison
// ============================================================================

/// Compare two byte arrays lexicographically
pub fn compareBytes(a: []const u8, b: []const u8) Order {
    assert(a.len <= std.math.maxInt(usize));
    assert(b.len <= std.math.maxInt(usize));

    const min_len = @min(a.len, b.len);
    for (0..min_len) |i| {
        if (a[i] < b[i]) return .less_than;
        if (a[i] > b[i]) return .greater_than;
    }
    // Prefix matches, shorter is less
    if (a.len < b.len) return .less_than;
    if (a.len > b.len) return .greater_than;
    return .equal;
}

/// Byte array equality
pub fn eqBytes(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ============================================================================
// Tests
// ============================================================================

test "comparison: compare i32" {
    try std.testing.expectEqual(Order.less_than, compare(i32, 1, 2));
    try std.testing.expectEqual(Order.equal, compare(i32, 5, 5));
    try std.testing.expectEqual(Order.greater_than, compare(i32, 10, 3));
}

test "comparison: lt le gt ge" {
    try std.testing.expect(lt(i32, 1, 2));
    try std.testing.expect(!lt(i32, 2, 2));
    try std.testing.expect(!lt(i32, 3, 2));

    try std.testing.expect(le(i32, 1, 2));
    try std.testing.expect(le(i32, 2, 2));
    try std.testing.expect(!le(i32, 3, 2));

    try std.testing.expect(!gt(i32, 1, 2));
    try std.testing.expect(!gt(i32, 2, 2));
    try std.testing.expect(gt(i32, 3, 2));

    try std.testing.expect(!ge(i32, 1, 2));
    try std.testing.expect(ge(i32, 2, 2));
    try std.testing.expect(ge(i32, 3, 2));
}

test "comparison: eq neq" {
    try std.testing.expect(eq(i32, 5, 5));
    try std.testing.expect(!eq(i32, 5, 6));
    try std.testing.expect(neq(i32, 5, 6));
    try std.testing.expect(!neq(i32, 5, 5));
}

test "comparison: i64 operations" {
    try std.testing.expectEqual(@as(i2, -1), compareI64(1, 2));
    try std.testing.expectEqual(@as(i2, 0), compareI64(5, 5));
    try std.testing.expectEqual(@as(i2, 1), compareI64(10, 3));

    try std.testing.expect(ltI64(1, 2));
    try std.testing.expect(leI64(2, 2));
    try std.testing.expect(gtI64(3, 2));
    try std.testing.expect(geI64(2, 2));
    try std.testing.expect(eqI64(5, 5));
    try std.testing.expect(neqI64(5, 6));
}

test "comparison: bool equality" {
    try std.testing.expect(eqBool(true, true));
    try std.testing.expect(eqBool(false, false));
    try std.testing.expect(!eqBool(true, false));
    try std.testing.expect(neqBool(true, false));
}

test "comparison: byte array" {
    try std.testing.expectEqual(Order.equal, compareBytes("abc", "abc"));
    try std.testing.expectEqual(Order.less_than, compareBytes("abc", "abd"));
    try std.testing.expectEqual(Order.greater_than, compareBytes("abd", "abc"));
    try std.testing.expectEqual(Order.less_than, compareBytes("ab", "abc"));
    try std.testing.expectEqual(Order.greater_than, compareBytes("abc", "ab"));

    try std.testing.expect(eqBytes("hello", "hello"));
    try std.testing.expect(!eqBytes("hello", "world"));
}

test "comparison: negative numbers" {
    try std.testing.expect(lt(i32, -5, -3));
    try std.testing.expect(gt(i32, -3, -5));
    try std.testing.expect(lt(i32, -1, 0));
    try std.testing.expect(gt(i32, 0, -1));
}

test "comparison: boundary values" {
    const min_i32 = std.math.minInt(i32);
    const max_i32 = std.math.maxInt(i32);

    try std.testing.expect(lt(i32, min_i32, max_i32));
    try std.testing.expect(gt(i32, max_i32, min_i32));
    try std.testing.expect(eq(i32, min_i32, min_i32));
    try std.testing.expect(eq(i32, max_i32, max_i32));
}
