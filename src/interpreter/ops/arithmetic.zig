//! Arithmetic Operations for ErgoTree Interpreter
//!
//! Implements all arithmetic operations with exact Scala/Java semantics:
//! - Signed integers only (no unsigned in user API)
//! - Overflow throws exception (not silent wrap)
//! - Division truncates toward zero
//! - Modulo follows truncating division
//!
//! Reference: sigmastate/src/main/scala/sigmastate/eval/ErgoTreeEvaluator.scala

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Error Types
// ============================================================================

pub const ArithmeticError = error{
    /// Result would overflow the type's range
    Overflow,
    /// Division or modulo by zero
    DivisionByZero,
};

// ============================================================================
// Generic Arithmetic Operations
// ============================================================================

/// Addition with overflow check
/// Matches Scala semantics: throws on overflow
pub fn add(comptime T: type, a: T, b: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    const result = @addWithOverflow(a, b);
    if (result[1] != 0) return error.Overflow;
    return result[0];
}

/// Subtraction with overflow check
pub fn sub(comptime T: type, a: T, b: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    const result = @subWithOverflow(a, b);
    if (result[1] != 0) return error.Overflow;
    return result[0];
}

/// Multiplication with overflow check
pub fn mul(comptime T: type, a: T, b: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    const result = @mulWithOverflow(a, b);
    if (result[1] != 0) return error.Overflow;
    return result[0];
}

/// Division (truncating toward zero)
/// Special case: MIN / -1 overflows (result would be -MIN which doesn't fit)
pub fn div(comptime T: type, a: T, b: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    if (b == 0) return error.DivisionByZero;

    // Special case: MIN / -1 overflows
    // In Scala/Java: Integer.MIN_VALUE / -1 throws ArithmeticException
    if (a == std.math.minInt(T) and b == -1) {
        return error.Overflow;
    }

    return @divTrunc(a, b);
}

/// Modulo (following truncating division)
/// Sign of result matches sign of dividend (a)
pub fn mod(comptime T: type, a: T, b: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    if (b == 0) return error.DivisionByZero;

    // Note: @rem follows truncated division semantics (sign matches dividend)
    // This matches Scala/Java behavior
    return @rem(a, b);
}

/// Negation with overflow check
/// Special case: -MIN overflows (result would be -MIN which doesn't fit)
pub fn negate(comptime T: type, a: T) ArithmeticError!T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    assert(@typeInfo(T).int.signedness == .signed);

    // MIN cannot be negated: -(-128) = 128 which doesn't fit in i8
    if (a == std.math.minInt(T)) {
        return error.Overflow;
    }

    return -a;
}

/// Minimum (no overflow possible)
pub fn min(comptime T: type, a: T, b: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    return @min(a, b);
}

/// Maximum (no overflow possible)
pub fn max(comptime T: type, a: T, b: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    return @max(a, b);
}

// ============================================================================
// i64-based Operations (for evaluator Value compatibility)
// ============================================================================

/// Add two i64 values, returning result and detecting overflow
pub fn addI64(a: i64, b: i64) ArithmeticError!i64 {
    return add(i64, a, b);
}

/// Subtract two i64 values
pub fn subI64(a: i64, b: i64) ArithmeticError!i64 {
    return sub(i64, a, b);
}

/// Multiply two i64 values
pub fn mulI64(a: i64, b: i64) ArithmeticError!i64 {
    return mul(i64, a, b);
}

/// Divide two i64 values (truncating)
pub fn divI64(a: i64, b: i64) ArithmeticError!i64 {
    return div(i64, a, b);
}

/// Modulo two i64 values
pub fn modI64(a: i64, b: i64) ArithmeticError!i64 {
    return mod(i64, a, b);
}

// ============================================================================
// Tests
// ============================================================================

test "arithmetic: add basic" {
    try std.testing.expectEqual(@as(i32, 3), try add(i32, 1, 2));
    try std.testing.expectEqual(@as(i64, 100), try add(i64, 50, 50));
    try std.testing.expectEqual(@as(i8, -10), try add(i8, -5, -5));
}

test "arithmetic: add overflow" {
    // i32 max overflow
    try std.testing.expectError(error.Overflow, add(i32, std.math.maxInt(i32), 1));

    // i8 overflow: 127 + 1
    try std.testing.expectError(error.Overflow, add(i8, 127, 1));

    // i64 overflow
    try std.testing.expectError(error.Overflow, add(i64, std.math.maxInt(i64), 1));

    // Negative overflow: MIN - 1 via add
    try std.testing.expectError(error.Overflow, add(i32, std.math.minInt(i32), -1));
}

test "arithmetic: sub basic" {
    try std.testing.expectEqual(@as(i32, 2), try sub(i32, 5, 3));
    try std.testing.expectEqual(@as(i32, -2), try sub(i32, 3, 5));
}

test "arithmetic: sub overflow" {
    // MIN - 1 overflows
    try std.testing.expectError(error.Overflow, sub(i32, std.math.minInt(i32), 1));

    // MAX - (-1) = MAX + 1 overflows
    try std.testing.expectError(error.Overflow, sub(i32, std.math.maxInt(i32), -1));
}

test "arithmetic: mul basic" {
    try std.testing.expectEqual(@as(i32, 42), try mul(i32, 6, 7));
    try std.testing.expectEqual(@as(i32, -42), try mul(i32, -6, 7));
    try std.testing.expectEqual(@as(i32, 42), try mul(i32, -6, -7));
}

test "arithmetic: mul overflow" {
    // Large multiplication overflow
    try std.testing.expectError(error.Overflow, mul(i32, std.math.maxInt(i32), 2));

    // Negative overflow
    try std.testing.expectError(error.Overflow, mul(i32, std.math.minInt(i32), 2));
}

test "arithmetic: div basic" {
    // Truncates toward zero
    try std.testing.expectEqual(@as(i32, 2), try div(i32, 7, 3));
    try std.testing.expectEqual(@as(i32, -2), try div(i32, -7, 3)); // Not -3!
    try std.testing.expectEqual(@as(i32, -2), try div(i32, 7, -3));
    try std.testing.expectEqual(@as(i32, 2), try div(i32, -7, -3));
}

test "arithmetic: div by zero" {
    try std.testing.expectError(error.DivisionByZero, div(i32, 10, 0));
    try std.testing.expectError(error.DivisionByZero, div(i64, 0, 0));
}

test "arithmetic: div MIN by -1 overflow" {
    // This is a critical edge case: MIN / -1 would produce -MIN which doesn't fit
    // Scala/Java throw ArithmeticException for this
    try std.testing.expectError(error.Overflow, div(i32, std.math.minInt(i32), -1));
    try std.testing.expectError(error.Overflow, div(i64, std.math.minInt(i64), -1));
    try std.testing.expectError(error.Overflow, div(i8, std.math.minInt(i8), -1));
    try std.testing.expectError(error.Overflow, div(i16, std.math.minInt(i16), -1));
}

test "arithmetic: mod basic" {
    try std.testing.expectEqual(@as(i32, 1), try mod(i32, 7, 3));
    try std.testing.expectEqual(@as(i32, -1), try mod(i32, -7, 3)); // Sign matches dividend
    try std.testing.expectEqual(@as(i32, 1), try mod(i32, 7, -3));
    try std.testing.expectEqual(@as(i32, -1), try mod(i32, -7, -3));
}

test "arithmetic: mod by zero" {
    try std.testing.expectError(error.DivisionByZero, mod(i32, 10, 0));
}

test "arithmetic: negate basic" {
    try std.testing.expectEqual(@as(i32, -42), try negate(i32, 42));
    try std.testing.expectEqual(@as(i32, 42), try negate(i32, -42));
    try std.testing.expectEqual(@as(i32, 0), try negate(i32, 0));
}

test "arithmetic: negate MIN overflow" {
    // -MIN doesn't fit in the same type
    try std.testing.expectError(error.Overflow, negate(i32, std.math.minInt(i32)));
    try std.testing.expectError(error.Overflow, negate(i64, std.math.minInt(i64)));
    try std.testing.expectError(error.Overflow, negate(i8, std.math.minInt(i8)));
}

test "arithmetic: min max" {
    try std.testing.expectEqual(@as(i32, 3), min(i32, 3, 5));
    try std.testing.expectEqual(@as(i32, 5), max(i32, 3, 5));
    try std.testing.expectEqual(@as(i32, -5), min(i32, -3, -5));
    try std.testing.expectEqual(@as(i32, -3), max(i32, -3, -5));
}

test "arithmetic: i64 operations" {
    try std.testing.expectEqual(@as(i64, 3), try addI64(1, 2));
    try std.testing.expectEqual(@as(i64, -1), try subI64(1, 2));
    try std.testing.expectEqual(@as(i64, 6), try mulI64(2, 3));
    try std.testing.expectEqual(@as(i64, 2), try divI64(7, 3));
    try std.testing.expectEqual(@as(i64, 1), try modI64(7, 3));
}
