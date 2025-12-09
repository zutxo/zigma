//! Collection Operations for ErgoTree Interpreter
//!
//! Implements basic collection operations:
//! - size_of: Get collection length
//! - by_index: Access element by index
//! - slice: Extract sub-collection
//! - append: Concatenate collections
//! - indices: Get indices as Coll[Int]
//!
//! Higher-order operations (map, fold, filter) are in higher_order.zig
//! as they require function evaluation integration.
//!
//! Reference: sigmastate/src/main/scala/sigmastate/utxo/CollOps.scala

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Error Types
// ============================================================================

pub const CollectionError = error{
    /// Index out of bounds
    IndexOutOfBounds,
    /// Slice range invalid (start > end or end > len)
    InvalidSliceRange,
    /// Collection size limit exceeded
    SizeLimitExceeded,
};

// ============================================================================
// Configuration
// ============================================================================

/// Maximum collection size (matches Ergo protocol limits)
pub const max_collection_size: usize = 10000;

// ============================================================================
// Basic Collection Operations
// ============================================================================

/// Get size of collection
/// OpCode: SizeOf (0x6C)
pub fn sizeOf(comptime T: type, coll: []const T) i32 {
    assert(coll.len <= max_collection_size);
    return @intCast(coll.len);
}

/// Access element by index
/// OpCode: ByIndex (0x6A)
/// Returns error if index out of bounds
pub fn byIndex(comptime T: type, coll: []const T, index: i32) CollectionError!T {
    if (index < 0 or index >= sizeOf(T, coll)) {
        return error.IndexOutOfBounds;
    }
    return coll[@intCast(index)];
}

/// Access element by index with default for out-of-bounds
/// OpCode: ByIndex with default value
pub fn byIndexOrDefault(comptime T: type, coll: []const T, index: i32, default: T) T {
    if (index < 0 or index >= sizeOf(T, coll)) {
        return default;
    }
    return coll[@intCast(index)];
}

/// Extract slice [start, end)
/// OpCode: Slice (0x6B)
/// Returns error if range is invalid
pub fn slice(comptime T: type, coll: []const T, start: i32, end: i32) CollectionError![]const T {
    const len = sizeOf(T, coll);

    if (start < 0 or end < 0) {
        return error.InvalidSliceRange;
    }
    if (start > end or end > len) {
        return error.InvalidSliceRange;
    }

    const start_idx: usize = @intCast(start);
    const end_idx: usize = @intCast(end);
    return coll[start_idx..end_idx];
}

/// Get first element
/// Returns error if collection is empty
pub fn first(comptime T: type, coll: []const T) CollectionError!T {
    return byIndex(T, coll, 0);
}

/// Get last element
/// Returns error if collection is empty
pub fn last(comptime T: type, coll: []const T) CollectionError!T {
    if (coll.len == 0) return error.IndexOutOfBounds;
    return coll[coll.len - 1];
}

/// Check if collection is empty
pub fn isEmpty(comptime T: type, coll: []const T) bool {
    return coll.len == 0;
}

/// Check if collection is not empty
pub fn nonEmpty(comptime T: type, coll: []const T) bool {
    return coll.len > 0;
}

// ============================================================================
// Collection Creation (into provided buffer)
// ============================================================================

/// Concatenate two collections into a buffer
/// OpCode: Append (0x6D)
/// Caller must provide buffer with sufficient capacity
pub fn append(
    comptime T: type,
    a: []const T,
    b: []const T,
    buffer: []T,
) CollectionError![]T {
    const total_len = a.len + b.len;
    if (total_len > max_collection_size) return error.SizeLimitExceeded;
    if (buffer.len < total_len) return error.SizeLimitExceeded;

    @memcpy(buffer[0..a.len], a);
    @memcpy(buffer[a.len..total_len], b);

    return buffer[0..total_len];
}

/// Create indices collection [0, 1, ..., len-1]
/// Caller must provide buffer
pub fn indices(len: usize, buffer: []i32) CollectionError![]i32 {
    if (len > max_collection_size) return error.SizeLimitExceeded;
    if (buffer.len < len) return error.SizeLimitExceeded;

    for (0..len) |i| {
        buffer[i] = @intCast(i);
    }

    return buffer[0..len];
}

/// Take first n elements
pub fn take(comptime T: type, coll: []const T, n: i32) []const T {
    if (n <= 0) return coll[0..0];
    const count: usize = @intCast(@min(n, sizeOf(T, coll)));
    return coll[0..count];
}

/// Drop first n elements
pub fn drop(comptime T: type, coll: []const T, n: i32) []const T {
    if (n <= 0) return coll;
    const start: usize = @intCast(@min(n, sizeOf(T, coll)));
    return coll[start..];
}

/// Reverse collection into buffer
pub fn reverse(comptime T: type, coll: []const T, buffer: []T) CollectionError![]T {
    if (buffer.len < coll.len) return error.SizeLimitExceeded;

    const len = coll.len;
    for (0..len) |i| {
        buffer[i] = coll[len - 1 - i];
    }

    return buffer[0..len];
}

// ============================================================================
// Search Operations
// ============================================================================

/// Find index of first matching element
/// Returns -1 if not found
pub fn indexOf(comptime T: type, coll: []const T, elem: T) i32 {
    for (coll, 0..) |item, i| {
        if (std.meta.eql(item, elem)) {
            return @intCast(i);
        }
    }
    return -1;
}

/// Check if collection contains element
pub fn contains(comptime T: type, coll: []const T, elem: T) bool {
    return indexOf(T, coll, elem) >= 0;
}

// ============================================================================
// Byte Collection Operations (Coll[Byte] specific)
// ============================================================================

/// Compare two byte collections lexicographically
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
pub fn compareBytes(a: []const u8, b: []const u8) i32 {
    const min_len = @min(a.len, b.len);

    for (0..min_len) |i| {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }

    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// XOR two byte arrays of same length into buffer
pub fn xorBytes(a: []const u8, b: []const u8, buffer: []u8) CollectionError![]u8 {
    if (a.len != b.len) return error.InvalidSliceRange;
    if (buffer.len < a.len) return error.SizeLimitExceeded;

    for (0..a.len) |i| {
        buffer[i] = a[i] ^ b[i];
    }

    return buffer[0..a.len];
}

// ============================================================================
// Tests
// ============================================================================

test "collection: sizeOf" {
    const arr = [_]i32{ 1, 2, 3, 4, 5 };
    try std.testing.expectEqual(@as(i32, 5), sizeOf(i32, &arr));
    try std.testing.expectEqual(@as(i32, 0), sizeOf(i32, &[_]i32{}));
}

test "collection: byIndex" {
    const arr = [_]i32{ 10, 20, 30 };
    try std.testing.expectEqual(@as(i32, 10), try byIndex(i32, &arr, 0));
    try std.testing.expectEqual(@as(i32, 30), try byIndex(i32, &arr, 2));
    try std.testing.expectError(error.IndexOutOfBounds, byIndex(i32, &arr, 3));
    try std.testing.expectError(error.IndexOutOfBounds, byIndex(i32, &arr, -1));
}

test "collection: byIndexOrDefault" {
    const arr = [_]i32{ 10, 20 };
    try std.testing.expectEqual(@as(i32, 10), byIndexOrDefault(i32, &arr, 0, -1));
    try std.testing.expectEqual(@as(i32, -1), byIndexOrDefault(i32, &arr, 99, -1));
}

test "collection: slice" {
    const arr = [_]i32{ 1, 2, 3, 4, 5 };

    const sl = try slice(i32, &arr, 1, 4);
    try std.testing.expectEqual(@as(usize, 3), sl.len);
    try std.testing.expectEqual(@as(i32, 2), sl[0]);
    try std.testing.expectEqual(@as(i32, 4), sl[2]);

    try std.testing.expectError(error.InvalidSliceRange, slice(i32, &arr, 3, 2));
    try std.testing.expectError(error.InvalidSliceRange, slice(i32, &arr, 0, 10));
}

test "collection: first and last" {
    const arr = [_]i32{ 10, 20, 30 };
    try std.testing.expectEqual(@as(i32, 10), try first(i32, &arr));
    try std.testing.expectEqual(@as(i32, 30), try last(i32, &arr));

    const empty = [_]i32{};
    try std.testing.expectError(error.IndexOutOfBounds, first(i32, &empty));
    try std.testing.expectError(error.IndexOutOfBounds, last(i32, &empty));
}

test "collection: isEmpty and nonEmpty" {
    const arr = [_]i32{1};
    const empty = [_]i32{};

    try std.testing.expect(!isEmpty(i32, &arr));
    try std.testing.expect(isEmpty(i32, &empty));
    try std.testing.expect(nonEmpty(i32, &arr));
    try std.testing.expect(!nonEmpty(i32, &empty));
}

test "collection: append" {
    const a = [_]i32{ 1, 2 };
    const b = [_]i32{ 3, 4, 5 };
    var buffer: [10]i32 = undefined;

    const result = try append(i32, &a, &b, &buffer);
    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqual(@as(i32, 1), result[0]);
    try std.testing.expectEqual(@as(i32, 5), result[4]);
}

test "collection: indices" {
    var buffer: [10]i32 = undefined;
    const result = try indices(5, &buffer);

    try std.testing.expectEqual(@as(usize, 5), result.len);
    try std.testing.expectEqual(@as(i32, 0), result[0]);
    try std.testing.expectEqual(@as(i32, 4), result[4]);
}

test "collection: take and drop" {
    const arr = [_]i32{ 1, 2, 3, 4, 5 };

    const t = take(i32, &arr, 3);
    try std.testing.expectEqual(@as(usize, 3), t.len);
    try std.testing.expectEqual(@as(i32, 1), t[0]);

    const d = drop(i32, &arr, 2);
    try std.testing.expectEqual(@as(usize, 3), d.len);
    try std.testing.expectEqual(@as(i32, 3), d[0]);
}

test "collection: reverse" {
    const arr = [_]i32{ 1, 2, 3 };
    var buffer: [10]i32 = undefined;

    const result = try reverse(i32, &arr, &buffer);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 3, 2, 1 }, result);
}

test "collection: indexOf and contains" {
    const arr = [_]i32{ 10, 20, 30, 20 };

    try std.testing.expectEqual(@as(i32, 1), indexOf(i32, &arr, 20));
    try std.testing.expectEqual(@as(i32, -1), indexOf(i32, &arr, 99));
    try std.testing.expect(contains(i32, &arr, 20));
    try std.testing.expect(!contains(i32, &arr, 99));
}

test "collection: compareBytes" {
    try std.testing.expectEqual(@as(i32, 0), compareBytes("abc", "abc"));
    try std.testing.expectEqual(@as(i32, -1), compareBytes("abc", "abd"));
    try std.testing.expectEqual(@as(i32, 1), compareBytes("abd", "abc"));
    try std.testing.expectEqual(@as(i32, -1), compareBytes("ab", "abc"));
    try std.testing.expectEqual(@as(i32, 1), compareBytes("abc", "ab"));
}

test "collection: xorBytes" {
    const a = [_]u8{ 0xFF, 0x00, 0xAA };
    const b = [_]u8{ 0x0F, 0xF0, 0x55 };
    var buffer: [10]u8 = undefined;

    const result = try xorBytes(&a, &b, &buffer);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0xF0, 0xFF }, result);
}
