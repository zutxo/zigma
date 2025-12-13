//! Value Pool for Nested Value Storage
//!
//! Enables arbitrary nesting of ErgoTree values (Option[Option[T]], Tuple of Tuples,
//! Coll[Box], etc.) while maintaining static allocation as per ZIGMA_STYLE.md.
//!
//! Design: Complex values store u16 indices into this pool rather than inline data.
//! This allows Options to contain Boxes, Tuples to have arbitrary element types, and
//! Collection HOF to work with any element type.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../core/types.zig");

const TypeIndex = types.TypeIndex;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of pooled values (sufficient for deeply nested structures)
pub const max_pooled_values: u16 = 4096;

/// Sentinel value indicating no value / None
pub const null_value_idx: u16 = std.math.maxInt(u16);

// Compile-time sanity checks (ZIGMA_STYLE requirement: 3+ assertions)
comptime {
    // Pool size must be reasonable for stack allocation
    assert(max_pooled_values <= 8192);
    assert(max_pooled_values >= 256);

    // Sentinel must be outside valid range
    assert(null_value_idx >= max_pooled_values);

    // PooledValue must be cache-friendly
    assert(@sizeOf(PooledValue) <= 64);
}

// ============================================================================
// Pooled Value
// ============================================================================

/// A value stored in the pool with its type tag.
/// Supports all ErgoTree value types for arbitrary nesting.
pub const PooledValue = struct {
    /// Type of this value (index into TypePool)
    type_idx: TypeIndex,

    /// Value data (discriminated by type_idx at runtime)
    data: ValueData,

    pub const ValueData = union {
        /// Primitives: boolean, byte, short, int, long stored as i64
        primitive: i64,

        /// 256-bit BigInt (big-endian two's complement)
        big_int: BigIntData,

        /// Group element (33 bytes compressed SEC1)
        group_element: [33]u8,

        /// Byte slice reference (pointer + length into arena)
        byte_slice: ByteSliceRef,

        /// Option reference (inner type + optional value index)
        option: OptionData,

        /// Tuple reference (start index + count)
        tuple: TupleData,

        /// Collection reference (element type + start index + count)
        collection: CollectionData,

        /// Box reference (source + index into context)
        box: BoxData,

        /// SigmaProp reference (data pointer into arena)
        sigma_prop: ByteSliceRef,

        /// Header (index into context headers array)
        header: u16,

        /// 32-byte hash result (Blake2b256 or SHA256), stored inline
        hash32: [32]u8,
    };

    /// BigInt storage (32 bytes max)
    pub const BigIntData = struct {
        bytes: [32]u8,
        len: u8,

        // Compile-time check
        comptime {
            assert(@sizeOf(BigIntData) == 33);
        }
    };

    /// Reference to byte slice in arena
    pub const ByteSliceRef = struct {
        ptr: [*]const u8,
        len: u32,

        pub fn slice(self: ByteSliceRef) []const u8 {
            return self.ptr[0..self.len];
        }
    };

    /// Option value storage
    pub const OptionData = struct {
        /// Type of inner value
        inner_type: TypeIndex,
        /// Index into ValuePool (null_value_idx if None)
        value_idx: u16,

        pub fn isSome(self: OptionData) bool {
            return self.value_idx != null_value_idx;
        }

        pub fn isNone(self: OptionData) bool {
            return self.value_idx == null_value_idx;
        }
    };

    /// Tuple value storage
    pub const TupleData = struct {
        /// Start index in ValuePool for elements
        start_idx: u16,
        /// Number of elements (2-255)
        len: u8,
        /// Start index in TypePool for element types
        types_start: TypeIndex,
    };

    /// Collection value storage
    pub const CollectionData = struct {
        /// Element type
        elem_type: TypeIndex,
        /// Start index in ValuePool for elements
        start_idx: u16,
        /// Number of elements
        len: u16,
    };

    /// Box reference storage
    pub const BoxData = struct {
        source: BoxSource,
        index: u16,

        pub const BoxSource = enum(u2) {
            inputs = 0,
            outputs = 1,
            data_inputs = 2,
        };
    };
};

// ============================================================================
// Value Pool
// ============================================================================

/// Pre-allocated pool for storing complex/nested values.
/// Supports O(1) allocation, O(1) access, O(1) reset.
pub const ValuePool = struct {
    const Self = @This();

    /// Pre-allocated storage array
    values: [max_pooled_values]PooledValue,

    /// Current allocation count
    count: u16,

    // Compile-time assertions (ZIGMA_STYLE: pool must fit in reasonable memory)
    comptime {
        // Total pool size check
        const total_size = @sizeOf([max_pooled_values]PooledValue);
        assert(total_size <= 512 * 1024); // Max 512KB

        // Individual value size check
        assert(@sizeOf(PooledValue) <= 64);
    }

    /// Initialize empty pool
    pub fn init() Self {
        return .{
            .values = undefined,
            .count = 0,
        };
    }

    /// Allocate a slot and return its index.
    /// Returns error if pool exhausted.
    pub fn alloc(self: *Self) error{PoolExhausted}!u16 {
        // PRECONDITION: count is within bounds
        assert(self.count <= max_pooled_values);

        if (self.count >= max_pooled_values) {
            return error.PoolExhausted;
        }

        const idx = self.count;
        self.count += 1;

        // POSTCONDITION: returned index is valid
        assert(idx < max_pooled_values);
        return idx;
    }

    /// Allocate N contiguous slots, return start index.
    /// Used for tuples and collections.
    pub fn allocN(self: *Self, n: u16) error{PoolExhausted}!u16 {
        // PRECONDITION: n is reasonable
        assert(n > 0);
        assert(n <= 255); // Max tuple/collection size per protocol

        if (self.count > max_pooled_values - n) {
            return error.PoolExhausted;
        }

        const start = self.count;
        self.count += n;

        // POSTCONDITION: all indices valid
        assert(start + n <= max_pooled_values);
        return start;
    }

    /// Get value at index (bounds checked)
    pub fn get(self: *const Self, idx: u16) ?*const PooledValue {
        if (idx >= self.count) return null;
        return &self.values[idx];
    }

    /// Get mutable value at index (bounds checked)
    pub fn getMut(self: *Self, idx: u16) ?*PooledValue {
        if (idx >= self.count) return null;
        return &self.values[idx];
    }

    /// Set value at index (must be allocated)
    pub fn set(self: *Self, idx: u16, value: PooledValue) void {
        // PRECONDITION: index was allocated
        assert(idx < self.count);
        self.values[idx] = value;
    }

    /// Store primitive value, return index
    pub fn storePrimitive(self: *Self, type_idx: TypeIndex, value: i64) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .primitive = value },
        };
        return idx;
    }

    /// Store BigInt value, return index
    pub fn storeBigInt(self: *Self, type_idx: TypeIndex, bytes: []const u8) error{PoolExhausted}!u16 {
        // PRECONDITION: BigInt fits in 32 bytes
        assert(bytes.len <= 32);

        const idx = try self.alloc();
        var big_int_data: PooledValue.BigIntData = .{
            .bytes = [_]u8{0} ** 32,
            .len = @intCast(bytes.len),
        };
        @memcpy(big_int_data.bytes[0..bytes.len], bytes);

        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .big_int = big_int_data },
        };
        return idx;
    }

    /// Store GroupElement value, return index
    pub fn storeGroupElement(self: *Self, type_idx: TypeIndex, bytes: [33]u8) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .group_element = bytes },
        };
        return idx;
    }

    /// Store byte slice reference, return index
    pub fn storeByteSlice(self: *Self, type_idx: TypeIndex, ptr: [*]const u8, slice_len: u32) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .byte_slice = .{ .ptr = ptr, .len = slice_len } },
        };
        return idx;
    }

    /// Store Option value, return index
    pub fn storeOption(self: *Self, type_idx: TypeIndex, inner_type: TypeIndex, value_idx: u16) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .option = .{ .inner_type = inner_type, .value_idx = value_idx } },
        };
        return idx;
    }

    /// Store Tuple header (elements must be stored separately at start_idx)
    pub fn storeTuple(self: *Self, type_idx: TypeIndex, start_idx: u16, elem_count: u8, types_start: TypeIndex) error{PoolExhausted}!u16 {
        // PRECONDITION: tuple has valid length
        assert(elem_count >= 2);

        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .tuple = .{ .start_idx = start_idx, .len = elem_count, .types_start = types_start } },
        };
        return idx;
    }

    /// Store Collection header (elements must be stored separately at start_idx)
    pub fn storeCollection(self: *Self, type_idx: TypeIndex, elem_type: TypeIndex, start_idx: u16, elem_count: u16) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .collection = .{ .elem_type = elem_type, .start_idx = start_idx, .len = elem_count } },
        };
        return idx;
    }

    /// Store Box reference
    pub fn storeBox(self: *Self, type_idx: TypeIndex, source: PooledValue.BoxData.BoxSource, index: u16) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .box = .{ .source = source, .index = index } },
        };
        return idx;
    }

    /// Store 32-byte hash result (inline, no arena needed)
    pub fn storeHash32(self: *Self, type_idx: TypeIndex, hash: [32]u8) error{PoolExhausted}!u16 {
        const idx = try self.alloc();
        self.values[idx] = .{
            .type_idx = type_idx,
            .data = .{ .hash32 = hash },
        };
        return idx;
    }

    /// Reset pool for reuse (O(1) - just resets counter)
    pub fn reset(self: *Self) void {
        self.count = 0;
    }

    /// Current number of allocated values
    pub fn len(self: *const Self) u16 {
        return self.count;
    }

    /// Remaining capacity
    pub fn remaining(self: *const Self) u16 {
        return max_pooled_values - self.count;
    }

    /// Check if pool is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.count == 0;
    }

    /// Check if pool is full
    pub fn isFull(self: *const Self) bool {
        return self.count >= max_pooled_values;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "value_pool: allocation up to capacity" {
    var pool = ValuePool.init();

    // Allocate several values
    const idx1 = try pool.alloc();
    const idx2 = try pool.alloc();
    const idx3 = try pool.alloc();

    try std.testing.expectEqual(@as(u16, 0), idx1);
    try std.testing.expectEqual(@as(u16, 1), idx2);
    try std.testing.expectEqual(@as(u16, 2), idx3);
    try std.testing.expectEqual(@as(u16, 3), pool.len());
}

test "value_pool: allocN contiguous slots" {
    var pool = ValuePool.init();

    _ = try pool.alloc(); // idx 0
    const start = try pool.allocN(5); // idx 1-5

    try std.testing.expectEqual(@as(u16, 1), start);
    try std.testing.expectEqual(@as(u16, 6), pool.len());

    // Can access all allocated slots
    for (0..5) |i| {
        const ptr = pool.getMut(start + @as(u16, @intCast(i)));
        try std.testing.expect(ptr != null);
    }
}

test "value_pool: pool exhaustion" {
    var pool = ValuePool.init();

    // Fill the pool
    for (0..max_pooled_values) |_| {
        _ = try pool.alloc();
    }

    try std.testing.expect(pool.isFull());
    try std.testing.expectError(error.PoolExhausted, pool.alloc());
}

test "value_pool: reset clears count" {
    var pool = ValuePool.init();

    _ = try pool.alloc();
    _ = try pool.alloc();
    _ = try pool.alloc();

    try std.testing.expectEqual(@as(u16, 3), pool.len());

    pool.reset();

    try std.testing.expectEqual(@as(u16, 0), pool.len());
    try std.testing.expect(pool.isEmpty());
}

test "value_pool: store and retrieve primitive" {
    var pool = ValuePool.init();

    const type_idx: TypeIndex = 5; // SLong
    const value: i64 = 42;

    const idx = try pool.storePrimitive(type_idx, value);

    const stored = pool.get(idx).?;
    try std.testing.expectEqual(type_idx, stored.type_idx);
    try std.testing.expectEqual(value, stored.data.primitive);
}

test "value_pool: store and retrieve BigInt" {
    var pool = ValuePool.init();

    const type_idx: TypeIndex = 6; // SBigInt
    const bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const idx = try pool.storeBigInt(type_idx, &bytes);

    const stored = pool.get(idx).?;
    try std.testing.expectEqual(type_idx, stored.type_idx);
    try std.testing.expectEqual(@as(u8, 4), stored.data.big_int.len);
    try std.testing.expectEqualSlices(u8, &bytes, stored.data.big_int.bytes[0..4]);
}

test "value_pool: store and retrieve GroupElement" {
    var pool = ValuePool.init();

    const type_idx: TypeIndex = 7; // SGroupElement
    var ge_bytes: [33]u8 = undefined;
    @memset(&ge_bytes, 0xAB);

    const idx = try pool.storeGroupElement(type_idx, ge_bytes);

    const stored = pool.get(idx).?;
    try std.testing.expectEqual(type_idx, stored.type_idx);
    try std.testing.expectEqualSlices(u8, &ge_bytes, &stored.data.group_element);
}

test "value_pool: store and retrieve Option (Some)" {
    var pool = ValuePool.init();

    // First store the inner value
    const inner_idx = try pool.storePrimitive(5, 100);

    // Then store the Option
    const option_type: TypeIndex = 20; // Some Option type
    const inner_type: TypeIndex = 5; // SLong
    const opt_idx = try pool.storeOption(option_type, inner_type, inner_idx);

    const stored = pool.get(opt_idx).?;
    try std.testing.expectEqual(option_type, stored.type_idx);
    try std.testing.expect(stored.data.option.isSome());
    try std.testing.expectEqual(inner_idx, stored.data.option.value_idx);
}

test "value_pool: store and retrieve Option (None)" {
    var pool = ValuePool.init();

    const option_type: TypeIndex = 20;
    const inner_type: TypeIndex = 5;
    const opt_idx = try pool.storeOption(option_type, inner_type, null_value_idx);

    const stored = pool.get(opt_idx).?;
    try std.testing.expect(stored.data.option.isNone());
}

test "value_pool: store and retrieve Tuple" {
    var pool = ValuePool.init();

    // Store tuple elements first
    const elem_start = try pool.allocN(3);
    pool.set(elem_start, .{ .type_idx = 3, .data = .{ .primitive = 10 } });
    pool.set(elem_start + 1, .{ .type_idx = 5, .data = .{ .primitive = 20 } });
    pool.set(elem_start + 2, .{ .type_idx = 7, .data = .{ .group_element = [_]u8{0} ** 33 } });

    // Store tuple header
    const tuple_type: TypeIndex = 30;
    const types_start: TypeIndex = 100;
    const tuple_idx = try pool.storeTuple(tuple_type, elem_start, 3, types_start);

    const stored = pool.get(tuple_idx).?;
    try std.testing.expectEqual(tuple_type, stored.type_idx);
    try std.testing.expectEqual(elem_start, stored.data.tuple.start_idx);
    try std.testing.expectEqual(@as(u8, 3), stored.data.tuple.len);
    try std.testing.expectEqual(types_start, stored.data.tuple.types_start);

    // Verify we can access tuple elements
    const elem0 = pool.get(stored.data.tuple.start_idx).?;
    try std.testing.expectEqual(@as(i64, 10), elem0.data.primitive);
}

test "value_pool: store and retrieve Collection" {
    var pool = ValuePool.init();

    // Store collection elements
    const elem_start = try pool.allocN(4);
    for (0..4) |i| {
        pool.set(elem_start + @as(u16, @intCast(i)), .{
            .type_idx = 5,
            .data = .{ .primitive = @as(i64, @intCast(i)) * 10 },
        });
    }

    // Store collection header
    const coll_type: TypeIndex = 40;
    const elem_type: TypeIndex = 5; // SLong
    const coll_idx = try pool.storeCollection(coll_type, elem_type, elem_start, 4);

    const stored = pool.get(coll_idx).?;
    try std.testing.expectEqual(coll_type, stored.type_idx);
    try std.testing.expectEqual(elem_type, stored.data.collection.elem_type);
    try std.testing.expectEqual(@as(u16, 4), stored.data.collection.len);

    // Verify element access
    const elem2 = pool.get(stored.data.collection.start_idx + 2).?;
    try std.testing.expectEqual(@as(i64, 20), elem2.data.primitive);
}

test "value_pool: nested Option[Option[Int]]" {
    var pool = ValuePool.init();

    // Store innermost value: Int = 42
    const inner_val_idx = try pool.storePrimitive(4, 42); // SInt

    // Store inner Option: Some(42)
    const inner_opt_idx = try pool.storeOption(20, 4, inner_val_idx);

    // Store outer Option: Some(Some(42))
    const outer_opt_idx = try pool.storeOption(21, 20, inner_opt_idx);

    // Verify nested access
    const outer = pool.get(outer_opt_idx).?;
    try std.testing.expect(outer.data.option.isSome());

    const inner = pool.get(outer.data.option.value_idx).?;
    try std.testing.expect(inner.data.option.isSome());

    const innermost = pool.get(inner.data.option.value_idx).?;
    try std.testing.expectEqual(@as(i64, 42), innermost.data.primitive);
}

test "value_pool: get out of bounds returns null" {
    var pool = ValuePool.init();

    _ = try pool.alloc();
    _ = try pool.alloc();

    try std.testing.expect(pool.get(0) != null);
    try std.testing.expect(pool.get(1) != null);
    try std.testing.expect(pool.get(2) == null); // Not allocated
    try std.testing.expect(pool.get(1000) == null); // Way out of bounds
}
