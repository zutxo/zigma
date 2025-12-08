//! VLQ (Variable Length Quantity) and ZigZag encoding for ErgoTree serialization.
//!
//! VLQ uses 7 bits per byte with MSB as continuation flag.
//! ZigZag maps signed integers to unsigned for efficient VLQ encoding of negative values.
//!
//! Reference: https://en.wikipedia.org/wiki/Variable-length_quantity

const std = @import("std");
const assert = std.debug.assert;

/// Maximum bytes needed for VLQ-encoded u64 (ceil(64/7) = 10)
pub const max_vlq_bytes: usize = 10;

// Compile-time sanity checks
comptime {
    // VLQ for u64 needs at most ceil(64/7) = 10 bytes
    assert(max_vlq_bytes == 10);
    // 9 bytes can encode 63 bits, 10 bytes needed for full u64
    assert((max_vlq_bytes - 1) * 7 < 64);
    assert(max_vlq_bytes * 7 >= 64);
}

/// Errors that can occur during VLQ decoding
pub const DecodeError = error{
    /// Input buffer is empty or truncated (missing continuation bytes)
    UnexpectedEndOfInput,
    /// VLQ sequence exceeds maximum length for target type
    Overflow,
};

// ============================================================================
// ZigZag Encoding
// ============================================================================

/// Encode signed i64 to unsigned u64 using ZigZag encoding.
/// Maps: 0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, 2 -> 4, ...
pub fn zigzagEncode(n: i64) u64 {
    // Arithmetic right shift preserves sign, giving all 1s for negative
    const shifted: u64 = @bitCast(n << 1);
    const sign_mask: u64 = @bitCast(n >> 63);
    const result = shifted ^ sign_mask;

    // POSTCONDITIONS:
    // 1. Non-negative inputs produce even outputs
    assert((n >= 0) == (result & 1 == 0));
    // 2. Zero maps to zero
    assert(n != 0 or result == 0);
    // 3. Result encodes magnitude in upper bits
    assert(if (n >= 0) result >> 1 == @as(u64, @intCast(n)) else result >> 1 == @as(u64, @intCast(-(n + 1))));

    return result;
}

/// Decode unsigned u64 to signed i64 using ZigZag decoding.
/// Maps: 0 -> 0, 1 -> -1, 2 -> 1, 3 -> -2, 4 -> 2, ...
pub fn zigzagDecode(n: u64) i64 {
    const half: u64 = n >> 1;
    const sign_bit: u64 = n & 1;
    // If sign_bit is 1, negate by XOR with all 1s and subtract (two's complement)
    const mask: u64 = 0 -% sign_bit; // 0 or 0xFFFFFFFFFFFFFFFF
    const result: i64 = @bitCast(half ^ mask);

    // POSTCONDITIONS:
    // 1. Even inputs produce non-negative outputs
    assert((n & 1 == 0) == (result >= 0));
    // 2. Zero maps to zero
    assert(n != 0 or result == 0);
    // 3. Magnitude relationship holds
    assert(if (result >= 0) n >> 1 == @as(u64, @intCast(result)) else n >> 1 == @as(u64, @intCast(-(result + 1))));

    return result;
}

// ============================================================================
// VLQ Encoding (Unsigned)
// ============================================================================

/// Encode unsigned u64 to VLQ format, writing to buffer.
/// Returns number of bytes written.
/// Buffer must be at least max_vlq_bytes (10) long.
pub fn encodeU64(value: u64, buf: []u8) usize {
    // PRECONDITION: Buffer large enough for worst case
    assert(buf.len >= max_vlq_bytes);

    var v = value;
    var i: usize = 0;

    while (true) {
        const byte: u8 = @truncate(v & 0x7F);
        v >>= 7;

        if (v == 0) {
            buf[i] = byte; // No continuation bit

            // POSTCONDITIONS:
            const bytes_written = i + 1;
            // 1. At least one byte written
            assert(bytes_written >= 1);
            // 2. At most max_vlq_bytes written
            assert(bytes_written <= max_vlq_bytes);
            // 3. Last byte has no continuation bit
            assert(buf[i] & 0x80 == 0);

            return bytes_written;
        } else {
            buf[i] = byte | 0x80; // Set continuation bit
            i += 1;

            // INVARIANT: Haven't exceeded max bytes
            assert(i < max_vlq_bytes);
        }
    }
}

/// Decode VLQ-encoded unsigned u64 from buffer.
/// Returns decoded value and number of bytes consumed.
pub fn decodeU64(buf: []const u8) DecodeError!struct { value: u64, bytes_read: usize } {
    // PRECONDITION: Non-empty buffer (checked via error return)
    if (buf.len == 0) return error.UnexpectedEndOfInput;

    var result: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;

    while (i < buf.len) {
        const byte = buf[i];
        i += 1;

        // Check for overflow before shifting
        if (shift >= 64) return error.Overflow;

        const payload: u64 = byte & 0x7F;

        // Check if this would overflow
        if (shift == 63 and payload > 1) return error.Overflow;

        result |= payload << shift;

        if (byte & 0x80 == 0) {
            // No continuation bit - done

            // POSTCONDITIONS:
            // 1. At least one byte consumed
            assert(i >= 1);
            // 2. At most max_vlq_bytes consumed
            assert(i <= max_vlq_bytes);
            // 3. Last byte had no continuation bit
            assert(buf[i - 1] & 0x80 == 0);

            return .{ .value = result, .bytes_read = i };
        }

        shift += 7;

        // INVARIANT: Haven't exceeded max bytes
        if (i >= max_vlq_bytes) {
            return error.Overflow;
        }
    }

    return error.UnexpectedEndOfInput;
}

// ============================================================================
// VLQ Encoding (Signed via ZigZag)
// ============================================================================

/// Encode signed i64 to VLQ format using ZigZag encoding.
/// Returns number of bytes written.
pub fn encodeI64(value: i64, buf: []u8) usize {
    return encodeU64(zigzagEncode(value), buf);
}

/// Decode VLQ-encoded signed i64 (ZigZag encoded) from buffer.
/// Returns decoded value and number of bytes consumed.
pub fn decodeI64(buf: []const u8) DecodeError!struct { value: i64, bytes_read: usize } {
    const result = try decodeU64(buf);
    return .{ .value = zigzagDecode(result.value), .bytes_read = result.bytes_read };
}

// ============================================================================
// Convenience Types
// ============================================================================

/// Reader wrapper for sequential VLQ decoding
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn readU64(self: *Reader) DecodeError!u64 {
        const result = try decodeU64(self.data[self.pos..]);
        self.pos += result.bytes_read;
        return result.value;
    }

    pub fn readI64(self: *Reader) DecodeError!i64 {
        const result = try decodeI64(self.data[self.pos..]);
        self.pos += result.bytes_read;
        return result.value;
    }

    pub fn readU32(self: *Reader) DecodeError!u32 {
        const v = try self.readU64();
        if (v > std.math.maxInt(u32)) return error.Overflow;
        return @truncate(v);
    }

    pub fn readI32(self: *Reader) DecodeError!i32 {
        const v = try self.readI64();
        if (v > std.math.maxInt(i32) or v < std.math.minInt(i32)) return error.Overflow;
        return @truncate(v);
    }

    pub fn remaining(self: Reader) []const u8 {
        return self.data[self.pos..];
    }

    pub fn isEmpty(self: Reader) bool {
        return self.pos >= self.data.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "zigzag: encode/decode roundtrip" {
    const cases = [_]i64{ 0, 1, -1, 2, -2, 63, -64, 64, -65, 127, -128, 8191, -8192, std.math.maxInt(i64), std.math.minInt(i64) };

    for (cases) |v| {
        const encoded = zigzagEncode(v);
        const decoded = zigzagDecode(encoded);
        try std.testing.expectEqual(v, decoded);
    }
}

test "zigzag: known vectors from spec" {
    // From vectors.json signed_zigzag section
    try std.testing.expectEqual(@as(u64, 0), zigzagEncode(0));
    try std.testing.expectEqual(@as(u64, 1), zigzagEncode(-1));
    try std.testing.expectEqual(@as(u64, 2), zigzagEncode(1));
    try std.testing.expectEqual(@as(u64, 3), zigzagEncode(-2));
    try std.testing.expectEqual(@as(u64, 0x7f), zigzagEncode(-64));
    try std.testing.expectEqual(@as(u64, 0x7e), zigzagEncode(63));
}

test "vlq: encode unsigned vectors" {
    var buf: [max_vlq_bytes]u8 = undefined;

    // Test value encoding and verify bytes
    inline for (.{
        .{ 0, &[_]u8{0x00} },
        .{ 1, &[_]u8{0x01} },
        .{ 127, &[_]u8{0x7f} },
        .{ 128, &[_]u8{ 0x80, 0x01 } },
        .{ 129, &[_]u8{ 0x81, 0x01 } },
        .{ 16383, &[_]u8{ 0xff, 0x7f } },
        .{ 16384, &[_]u8{ 0x80, 0x80, 0x01 } },
        .{ 16385, &[_]u8{ 0x81, 0x80, 0x01 } },
        .{ 2097151, &[_]u8{ 0xff, 0xff, 0x7f } },
        .{ 2097152, &[_]u8{ 0x80, 0x80, 0x80, 0x01 } },
        .{ 268435455, &[_]u8{ 0xff, 0xff, 0xff, 0x7f } },
        .{ 268435456, &[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x01 } },
        .{ 34359738367, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0x7f } },
        .{ 34359738368, &[_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 } },
        .{ 9223372036854775807, &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f } },
    }) |tc| {
        const value: u64 = tc[0];
        const expected: []const u8 = tc[1];
        const len = encodeU64(value, &buf);
        try std.testing.expectEqualSlices(u8, expected, buf[0..len]);
    }
}

test "vlq: decode unsigned vectors" {
    inline for (.{
        .{ &[_]u8{0x00}, 0 },
        .{ &[_]u8{0x01}, 1 },
        .{ &[_]u8{0x7f}, 127 },
        .{ &[_]u8{ 0x80, 0x01 }, 128 },
        .{ &[_]u8{ 0xff, 0x7f }, 16383 },
        .{ &[_]u8{ 0x80, 0x80, 0x01 }, 16384 },
        .{ &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 9223372036854775807 },
    }) |tc| {
        const bytes: []const u8 = tc[0];
        const expected: u64 = tc[1];
        const result = try decodeU64(bytes);
        try std.testing.expectEqual(expected, result.value);
        try std.testing.expectEqual(bytes.len, result.bytes_read);
    }
}

test "vlq: signed vectors via zigzag" {
    var buf: [max_vlq_bytes]u8 = undefined;

    // From vectors.json signed_zigzag section
    inline for (.{
        .{ @as(i64, 0), &[_]u8{0x00} },
        .{ @as(i64, -1), &[_]u8{0x01} },
        .{ @as(i64, 1), &[_]u8{0x02} },
        .{ @as(i64, -2), &[_]u8{0x03} },
        .{ @as(i64, -64), &[_]u8{0x7f} },
        .{ @as(i64, 63), &[_]u8{0x7e} },
        .{ @as(i64, -65), &[_]u8{ 0x81, 0x01 } },
        .{ @as(i64, 64), &[_]u8{ 0x80, 0x01 } },
        .{ @as(i64, -8192), &[_]u8{ 0xff, 0x7f } },
        .{ @as(i64, 8191), &[_]u8{ 0xfe, 0x7f } },
        .{ @as(i64, -8193), &[_]u8{ 0x81, 0x80, 0x01 } },
        .{ @as(i64, 8192), &[_]u8{ 0x80, 0x80, 0x01 } },
    }) |tc| {
        const value: i64 = tc[0];
        const expected: []const u8 = tc[1];

        const len = encodeI64(value, &buf);
        try std.testing.expectEqualSlices(u8, expected, buf[0..len]);

        // Verify decode roundtrip
        const result = try decodeI64(expected);
        try std.testing.expectEqual(value, result.value);
    }
}

test "vlq: i64 min/max" {
    var buf: [max_vlq_bytes]u8 = undefined;

    // i64::MIN requires 10 bytes due to zigzag
    const len_min = encodeI64(std.math.minInt(i64), &buf);
    try std.testing.expectEqual(@as(usize, 10), len_min);
    const expected_min = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    try std.testing.expectEqualSlices(u8, &expected_min, buf[0..len_min]);

    // i64::MAX also requires 10 bytes
    const len_max = encodeI64(std.math.maxInt(i64), &buf);
    try std.testing.expectEqual(@as(usize, 10), len_max);
    const expected_max = [_]u8{ 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    try std.testing.expectEqualSlices(u8, &expected_max, buf[0..len_max]);
}

test "vlq: decode error on truncated input" {
    // Byte with continuation bit but no following byte
    const truncated = [_]u8{0x80};
    try std.testing.expectError(error.UnexpectedEndOfInput, decodeU64(&truncated));
}

test "vlq: decode error on empty input" {
    const empty: []const u8 = &.{};
    try std.testing.expectError(error.UnexpectedEndOfInput, decodeU64(empty));
}

test "vlq: roundtrip preserves all u64 boundary values" {
    var buf: [max_vlq_bytes]u8 = undefined;
    const values = [_]u64{
        0,
        1,
        0x7F,
        0x80,
        0x3FFF,
        0x4000,
        0x1FFFFF,
        0x200000,
        0xFFFFFFF,
        0x10000000,
        0xFFFFFFFF,
        0x100000000,
        std.math.maxInt(u64),
    };

    for (values) |v| {
        const len = encodeU64(v, &buf);
        const result = try decodeU64(buf[0..len]);
        try std.testing.expectEqual(v, result.value);
    }
}

test "vlq: Reader sequential decoding" {
    // 0x00 (0), 0x80 0x01 (128), 0xff 0x7f (16383)
    const data = [_]u8{ 0x00, 0x80, 0x01, 0xff, 0x7f };
    var reader = Reader.init(&data);

    try std.testing.expectEqual(@as(u64, 0), try reader.readU64());
    try std.testing.expectEqual(@as(u64, 128), try reader.readU64());
    try std.testing.expectEqual(@as(u64, 16383), try reader.readU64());
    try std.testing.expect(reader.isEmpty());
}
