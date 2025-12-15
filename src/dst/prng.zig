//! Deterministic Pseudo-Random Number Generator for DST
//!
//! TigerBeetle-style PRNG wrapper providing seed-based reproducibility.
//! All randomness in DST flows through this module, ensuring any failure
//! can be reproduced exactly from the seed alone.
//!
//! Key features:
//!   - Git commit hash as seed (CI integration)
//!   - Ratio-based probability checks
//!   - Exponential distributions for realistic modeling
//!   - Enum weights for swarm testing

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum seed string length (40 for git SHA, 20 for u64 decimal)
const max_seed_len: usize = 40;

// ============================================================================
// Types
// ============================================================================

/// Ratio for probability checks (e.g., 30/100 = 30% chance)
pub const Ratio = struct {
    numerator: u64,
    denominator: u64,

    /// Zero probability - never happens
    pub fn zero() Ratio {
        return .{ .numerator = 0, .denominator = 1 };
    }

    /// Full probability - always happens
    pub fn one() Ratio {
        return .{ .numerator = 1, .denominator = 1 };
    }

    /// Create ratio from percentage (0-100)
    pub fn percent(p: u8) Ratio {
        assert(p <= 100);
        return .{ .numerator = p, .denominator = 100 };
    }

    /// Check if ratio is valid
    pub fn isValid(self: Ratio) bool {
        return self.denominator > 0 and self.numerator <= self.denominator;
    }
};

/// Deterministic PRNG wrapper
pub const PRNG = struct {
    state: std.Random.DefaultPrng,

    /// Initialize from 64-bit seed
    pub fn from_seed(seed: u64) PRNG {
        return .{ .state = std.Random.DefaultPrng.init(seed) };
    }

    /// Get the underlying Random interface
    pub fn random(self: *PRNG) std.Random {
        return self.state.random();
    }

    // ========================================================================
    // Integer Generation
    // ========================================================================

    /// Generate random integer of type T
    pub fn int(self: *PRNG, comptime T: type) T {
        return self.random().int(T);
    }

    /// Generate random integer in inclusive range [min, max]
    pub fn range_inclusive(self: *PRNG, comptime T: type, min: T, max: T) T {
        assert(min <= max);
        return self.random().intRangeAtMost(T, min, max);
    }

    /// Generate random integer in exclusive range [min, max)
    pub fn range(self: *PRNG, comptime T: type, min: T, max: T) T {
        assert(min < max);
        return self.random().intRangeLessThan(T, min, max);
    }

    /// Generate integer with exponential distribution
    /// Returns values clustered around `avg` with long tail
    pub fn int_exponential(self: *PRNG, comptime T: type, avg: T) T {
        comptime {
            const info = @typeInfo(T);
            assert(info == .int);
            assert(info.int.signedness == .unsigned);
        }
        // Use float for exponential, then cast to integer
        const r = self.random();
        const exp = r.floatExp(f64) * @as(f64, @floatFromInt(avg));
        return std.math.lossyCast(T, exp);
    }

    // ========================================================================
    // Boolean & Probability
    // ========================================================================

    /// Generate random boolean
    pub fn boolean(self: *PRNG) bool {
        return self.random().boolean();
    }

    /// Return true with given probability (ratio)
    pub fn chance(self: *PRNG, ratio: Ratio) bool {
        assert(ratio.isValid());
        if (ratio.numerator == 0) return false;
        if (ratio.numerator == ratio.denominator) return true;
        return self.random().uintLessThan(u64, ratio.denominator) < ratio.numerator;
    }

    // ========================================================================
    // Enum & Array Operations
    // ========================================================================

    /// Generate random enum value
    pub fn enum_value(self: *PRNG, comptime E: type) E {
        return self.random().enumValue(E);
    }

    /// Generate random enum value with weights
    /// Weights array must have same length as enum fields
    pub fn enum_weighted(self: *PRNG, comptime E: type, weights: EnumWeightsType(E)) E {
        const fields = std.meta.fields(E);

        // Calculate total weight
        var total: u64 = 0;
        inline for (fields) |field| {
            total += @field(weights, field.name);
        }

        if (total == 0) {
            // All weights zero - fall back to uniform
            return self.enum_value(E);
        }

        // Pick random value in [0, total)
        const pick = self.range(u64, 0, total);

        // Find which field this maps to
        var acc: u64 = 0;
        inline for (fields) |field| {
            acc += @field(weights, field.name);
            if (pick < acc) {
                return @enumFromInt(field.value);
            }
        }

        // Should never reach here if weights sum correctly
        unreachable;
    }

    /// Shuffle slice in place (Fisher-Yates)
    pub fn shuffle(self: *PRNG, comptime T: type, slice: []T) void {
        self.random().shuffle(T, slice);
    }

    /// Select random element from slice
    pub fn select(self: *PRNG, comptime T: type, slice: []const T) T {
        assert(slice.len > 0);
        const idx = self.range(usize, 0, slice.len);
        return slice[idx];
    }

    /// Fill slice with random bytes
    pub fn fill(self: *PRNG, buf: []u8) void {
        self.random().bytes(buf);
    }

    // ========================================================================
    // Utility Types
    // ========================================================================

    /// Generate struct type for enum weights
    pub fn EnumWeightsType(comptime E: type) type {
        const fields = std.meta.fields(E);
        var struct_fields: [fields.len]std.builtin.Type.StructField = undefined;

        inline for (fields, 0..) |field, i| {
            struct_fields[i] = .{
                .name = field.name,
                .type = u64,
                .default_value_ptr = null,
                .is_comptime = false,
                .alignment = @alignOf(u64),
            };
        }

        return @Type(.{ .@"struct" = .{
            .layout = .auto,
            .fields = &struct_fields,
            .decls = &.{},
            .is_tuple = false,
        } });
    }
};

// ============================================================================
// Seed Parsing
// ============================================================================

/// Parse seed from string, supporting:
/// - 64-bit decimal integer
/// - 40-character git commit hash (truncated to u64)
///
/// Returns null on parse error
pub fn parse_seed(bytes: []const u8) ?u64 {
    if (bytes.len == 0) return null;
    if (bytes.len > max_seed_len) return null;

    if (bytes.len == 40) {
        // Git commit hash (40 hex characters) - truncate to u64
        const commit_hash = std.fmt.parseUnsigned(u160, bytes, 16) catch return null;
        return @truncate(commit_hash);
    }

    // Regular decimal integer
    return std.fmt.parseUnsigned(u64, bytes, 10) catch null;
}

/// Parse seed from string, panicking on error (for CLI use)
pub fn parse_seed_or_panic(bytes: []const u8) u64 {
    if (bytes.len == 40) {
        // Git commit hash
        const commit_hash = std.fmt.parseUnsigned(u160, bytes, 16) catch |err| switch (err) {
            error.Overflow => unreachable,
            error.InvalidCharacter => @panic("seed: git hash contains invalid character"),
        };
        return @truncate(commit_hash);
    }

    return std.fmt.parseUnsigned(u64, bytes, 10) catch |err| switch (err) {
        error.Overflow => @panic("seed: exceeds 64-bit unsigned integer"),
        error.InvalidCharacter => @panic("seed: contains invalid character"),
    };
}

// ============================================================================
// Swarm Testing Utilities
// ============================================================================

/// Generate random weights for swarm testing
/// Some enum variants get disabled (weight=0), others get random weights
pub fn random_enum_weights(
    prng: *PRNG,
    comptime E: type,
) PRNG.EnumWeightsType(E) {
    const fields = std.meta.fields(E);
    var weights: PRNG.EnumWeightsType(E) = undefined;

    // Randomly enable/disable each variant
    inline for (fields) |field| {
        // 70% chance to enable each variant
        @field(weights, field.name) = if (prng.chance(.{ .numerator = 70, .denominator = 100 }))
            prng.range_inclusive(u64, 1, 100)
        else
            0;
    }

    return weights;
}

// ============================================================================
// Tests
// ============================================================================

test "prng: seed reproducibility" {
    const seed: u64 = 0xDEADBEEF_CAFEBABE;

    var prng1 = PRNG.from_seed(seed);
    var prng2 = PRNG.from_seed(seed);

    // Same seed must produce same sequence
    for (0..100) |_| {
        try std.testing.expectEqual(prng1.int(u64), prng2.int(u64));
    }
}

test "prng: different seeds produce different sequences" {
    var prng1 = PRNG.from_seed(1);
    var prng2 = PRNG.from_seed(2);

    // Different seeds should (almost certainly) produce different values
    var different = false;
    for (0..10) |_| {
        if (prng1.int(u64) != prng2.int(u64)) {
            different = true;
            break;
        }
    }
    try std.testing.expect(different);
}

test "prng: range_inclusive bounds" {
    var prng = PRNG.from_seed(42);

    for (0..1000) |_| {
        const val = prng.range_inclusive(u8, 10, 20);
        try std.testing.expect(val >= 10);
        try std.testing.expect(val <= 20);
    }
}

test "prng: chance probability" {
    var prng = PRNG.from_seed(12345);

    // 0% should never happen
    for (0..100) |_| {
        try std.testing.expect(!prng.chance(Ratio.zero()));
    }

    // 100% should always happen
    for (0..100) |_| {
        try std.testing.expect(prng.chance(Ratio.one()));
    }

    // 50% should be roughly balanced (with tolerance)
    var true_count: usize = 0;
    const trials = 10000;
    for (0..trials) |_| {
        if (prng.chance(Ratio.percent(50))) {
            true_count += 1;
        }
    }
    // Allow 10% deviation from expected 50%
    try std.testing.expect(true_count > trials * 40 / 100);
    try std.testing.expect(true_count < trials * 60 / 100);
}

test "prng: int_exponential distribution" {
    var prng = PRNG.from_seed(99999);

    const avg: u32 = 100;
    var sum: u64 = 0;
    const samples = 10000;

    for (0..samples) |_| {
        sum += prng.int_exponential(u32, avg);
    }

    // Mean should be close to avg (within 20%)
    const mean = sum / samples;
    try std.testing.expect(mean > avg * 80 / 100);
    try std.testing.expect(mean < avg * 120 / 100);
}

test "prng: enum_value coverage" {
    const TestEnum = enum { a, b, c };
    var prng = PRNG.from_seed(777);

    var counts = [_]usize{ 0, 0, 0 };
    for (0..300) |_| {
        const val = prng.enum_value(TestEnum);
        counts[@intFromEnum(val)] += 1;
    }

    // All variants should be hit at least once
    for (counts) |c| {
        try std.testing.expect(c > 0);
    }
}

test "parse_seed: decimal integer" {
    try std.testing.expectEqual(@as(?u64, 12345), parse_seed("12345"));
    try std.testing.expectEqual(@as(?u64, 0), parse_seed("0"));
    try std.testing.expectEqual(@as(?u64, 18446744073709551615), parse_seed("18446744073709551615"));
}

test "parse_seed: git commit hash" {
    // 40-character hex string (git SHA)
    const sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const seed = parse_seed(sha);
    try std.testing.expect(seed != null);
    // Same SHA should produce same seed
    try std.testing.expectEqual(seed, parse_seed(sha));
}

test "parse_seed: invalid inputs" {
    try std.testing.expectEqual(@as(?u64, null), parse_seed(""));
    try std.testing.expectEqual(@as(?u64, null), parse_seed("not_a_number"));
    try std.testing.expectEqual(@as(?u64, null), parse_seed("-1")); // Negative not allowed
    // 41 characters (too long for git hash)
    try std.testing.expectEqual(@as(?u64, null), parse_seed("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2X"));
}

test "ratio: validity checks" {
    try std.testing.expect(Ratio.zero().isValid());
    try std.testing.expect(Ratio.one().isValid());
    try std.testing.expect(Ratio.percent(50).isValid());
    try std.testing.expect((Ratio{ .numerator = 30, .denominator = 100 }).isValid());
    try std.testing.expect(!(Ratio{ .numerator = 0, .denominator = 0 }).isValid());
    try std.testing.expect(!(Ratio{ .numerator = 2, .denominator = 1 }).isValid());
}
