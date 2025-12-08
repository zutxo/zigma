//! Logical Operations for ErgoTree Interpreter
//!
//! Implements logical and bitwise operations.
//!
//! Logical: and, or, xor, not (for booleans)
//! Bitwise: bitAnd, bitOr, bitXor, bitNot, shifts (for integers)
//!
//! Reference: sigmastate/src/main/scala/sigmastate/eval/ErgoTreeEvaluator.scala

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Boolean Logical Operations
// ============================================================================

/// Logical AND
pub fn logicalAnd(a: bool, b: bool) bool {
    return a and b;
}

/// Logical OR
pub fn logicalOr(a: bool, b: bool) bool {
    return a or b;
}

/// Logical XOR (exclusive or)
pub fn logicalXor(a: bool, b: bool) bool {
    return a != b;
}

/// Logical NOT
pub fn logicalNot(a: bool) bool {
    return !a;
}

// ============================================================================
// Bitwise Operations (for integers)
// ============================================================================

/// Bitwise AND
pub fn bitAnd(comptime T: type, a: T, b: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    // Cast to unsigned, perform AND, cast back
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(T).int.bits } });
    return @bitCast(@as(U, @bitCast(a)) & @as(U, @bitCast(b)));
}

/// Bitwise OR
pub fn bitOr(comptime T: type, a: T, b: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(T).int.bits } });
    return @bitCast(@as(U, @bitCast(a)) | @as(U, @bitCast(b)));
}

/// Bitwise XOR
pub fn bitXor(comptime T: type, a: T, b: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(T).int.bits } });
    return @bitCast(@as(U, @bitCast(a)) ^ @as(U, @bitCast(b)));
}

/// Bitwise NOT (one's complement)
pub fn bitNot(comptime T: type, a: T) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = @typeInfo(T).int.bits } });
    return @bitCast(~@as(U, @bitCast(a)));
}

/// Left shift
/// Note: Shift amount is masked to valid range per Scala semantics
pub fn shiftLeft(comptime T: type, a: T, shift: u6) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const bits = @typeInfo(T).int.bits;
    const masked_shift = shift & (bits - 1);
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = bits } });
    return @bitCast(@as(U, @bitCast(a)) << @intCast(masked_shift));
}

/// Arithmetic right shift (sign-extending)
/// Note: Shift amount is masked to valid range per Scala semantics
pub fn shiftRight(comptime T: type, a: T, shift: u6) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const bits = @typeInfo(T).int.bits;
    const masked_shift = shift & (bits - 1);
    // Arithmetic shift (sign extends)
    return a >> @intCast(masked_shift);
}

/// Logical right shift (zero-extending)
/// Note: Shift amount is masked to valid range per Scala semantics
pub fn shiftRightZeroed(comptime T: type, a: T, shift: u6) T {
    comptime assert(T == i8 or T == i16 or T == i32 or T == i64);
    const bits = @typeInfo(T).int.bits;
    const masked_shift = shift & (bits - 1);
    const U = @Type(.{ .int = .{ .signedness = .unsigned, .bits = bits } });
    const result = @as(U, @bitCast(a)) >> @intCast(masked_shift);
    return @bitCast(result);
}

// ============================================================================
// i64-based Operations (for evaluator compatibility)
// ============================================================================

pub fn bitAndI64(a: i64, b: i64) i64 {
    return bitAnd(i64, a, b);
}

pub fn bitOrI64(a: i64, b: i64) i64 {
    return bitOr(i64, a, b);
}

pub fn bitXorI64(a: i64, b: i64) i64 {
    return bitXor(i64, a, b);
}

pub fn bitNotI64(a: i64) i64 {
    return bitNot(i64, a);
}

// ============================================================================
// Tests
// ============================================================================

test "logical: and or xor not" {
    try std.testing.expect(logicalAnd(true, true) == true);
    try std.testing.expect(logicalAnd(true, false) == false);
    try std.testing.expect(logicalAnd(false, false) == false);

    try std.testing.expect(logicalOr(true, true) == true);
    try std.testing.expect(logicalOr(true, false) == true);
    try std.testing.expect(logicalOr(false, false) == false);

    try std.testing.expect(logicalXor(true, true) == false);
    try std.testing.expect(logicalXor(true, false) == true);
    try std.testing.expect(logicalXor(false, false) == false);

    try std.testing.expect(logicalNot(true) == false);
    try std.testing.expect(logicalNot(false) == true);
}

test "logical: bitwise and or xor" {
    // 0b1100 & 0b1010 = 0b1000
    try std.testing.expectEqual(@as(i32, 0b1000), bitAnd(i32, 0b1100, 0b1010));
    // 0b1100 | 0b1010 = 0b1110
    try std.testing.expectEqual(@as(i32, 0b1110), bitOr(i32, 0b1100, 0b1010));
    // 0b1100 ^ 0b1010 = 0b0110
    try std.testing.expectEqual(@as(i32, 0b0110), bitXor(i32, 0b1100, 0b1010));
}

test "logical: bitwise not" {
    // ~0 = -1 (all bits set)
    try std.testing.expectEqual(@as(i32, -1), bitNot(i32, 0));
    // ~(-1) = 0
    try std.testing.expectEqual(@as(i32, 0), bitNot(i32, -1));
}

test "logical: shift left" {
    try std.testing.expectEqual(@as(i32, 8), shiftLeft(i32, 1, 3)); // 1 << 3 = 8
    try std.testing.expectEqual(@as(i32, 1), shiftLeft(i32, 1, 32)); // 32 & 31 = 0, so 1 << 0 = 1
    try std.testing.expectEqual(@as(i8, -128), shiftLeft(i8, 1, 7)); // Becomes negative (MSB set)
}

test "logical: shift right arithmetic" {
    try std.testing.expectEqual(@as(i32, 2), shiftRight(i32, 8, 2)); // 8 >> 2 = 2
    try std.testing.expectEqual(@as(i32, -1), shiftRight(i32, -1, 5)); // Sign extends: -1 >> 5 = -1
    try std.testing.expectEqual(@as(i32, -2), shiftRight(i32, -8, 2)); // -8 >> 2 = -2
}

test "logical: shift right zeroed" {
    try std.testing.expectEqual(@as(i32, 2), shiftRightZeroed(i32, 8, 2)); // Same as arithmetic for positive
    // For -1 (all bits set), zero-filled shift produces a large positive number
    const result = shiftRightZeroed(i32, -1, 1);
    try std.testing.expect(result > 0); // Zero-fill makes it positive
    try std.testing.expectEqual(@as(i32, 0x7FFFFFFF), result); // 2^31 - 1
}

test "logical: i64 bitwise" {
    try std.testing.expectEqual(@as(i64, 0), bitAndI64(0xFF, 0x00));
    try std.testing.expectEqual(@as(i64, 0xFF), bitOrI64(0xFF, 0x00));
    try std.testing.expectEqual(@as(i64, 0xFF), bitXorI64(0xFF, 0x00));
    try std.testing.expectEqual(@as(i64, -1), bitNotI64(0));
}

test "logical: negative number bitwise" {
    // Test bitwise operations with negative numbers
    // -1 has all bits set
    try std.testing.expectEqual(@as(i32, 0b1010), bitAnd(i32, -1, 0b1010));
    try std.testing.expectEqual(@as(i32, -1), bitOr(i32, -1, 0b1010));
}
