//! Memory Pools for ErgoTree Interpreter
//!
//! Pre-allocated memory pools for zero-allocation evaluation.
//! Follows TigerBeetle-style data-oriented design principles.
//!
//! Key design decisions:
//! - All pools have fixed maximum sizes known at compile time
//! - No dynamic allocation during evaluation
//! - Stack-based allocation for evaluation frames
//! - Pools can be reset for reuse between transactions

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../core/types.zig");

// ============================================================================
// Configuration
// ============================================================================

/// Maximum depth of evaluation stack (prevents runaway recursion)
pub const max_eval_depth: usize = 256;

/// Maximum number of values on the value stack
pub const max_value_stack: usize = 1024;

/// Maximum number of let-bindings in scope
pub const max_bindings: usize = 256;

/// Maximum number of expressions in a single ErgoTree
pub const max_expressions: usize = 4096;

/// Maximum cost budget per evaluation (in cost units)
pub const default_cost_limit: u64 = 1_000_000;

// Compile-time sanity checks for pool configuration
comptime {
    // All limits must be reasonable for stack allocation
    assert(max_eval_depth <= 1024);
    assert(max_value_stack <= 8192);
    assert(max_bindings <= 1024);
    assert(max_expressions <= 16384);

    // Cost limit must be positive
    assert(default_cost_limit > 0);

    // ValueIndex must fit max_value_stack
    assert(max_value_stack <= std.math.maxInt(ValueIndex));
}

// ============================================================================
// Value Index
// ============================================================================

/// Index into value pool (u16 sufficient for max_value_stack)
pub const ValueIndex = u16;

/// Sentinel value indicating no value
pub const null_value: ValueIndex = std.math.maxInt(ValueIndex);

// ============================================================================
// Stack Allocator
// ============================================================================

/// Fixed-size stack allocator for temporary data.
/// Supports push/pop semantics with watermark reset.
pub fn StackAllocator(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();

        items: [capacity]T = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn push(self: *Self, item: T) error{StackOverflow}!void {
            if (self.len >= capacity) return error.StackOverflow;
            self.items[self.len] = item;
            self.len += 1;
        }

        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            self.len -= 1;
            return self.items[self.len];
        }

        pub fn peek(self: *const Self) ?T {
            if (self.len == 0) return null;
            return self.items[self.len - 1];
        }

        pub fn peekPtr(self: *Self) ?*T {
            if (self.len == 0) return null;
            return &self.items[self.len - 1];
        }

        pub fn get(self: *const Self, idx: usize) ?T {
            if (idx >= self.len) return null;
            return self.items[idx];
        }

        pub fn getPtr(self: *Self, idx: usize) ?*T {
            if (idx >= self.len) return null;
            return &self.items[idx];
        }

        pub fn slice(self: *const Self) []const T {
            return self.items[0..self.len];
        }

        pub fn sliceMut(self: *Self) []T {
            return self.items[0..self.len];
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len >= capacity;
        }

        pub fn remaining(self: *const Self) usize {
            return capacity - self.len;
        }

        /// Reset to empty state
        pub fn reset(self: *Self) void {
            self.len = 0;
        }

        /// Reset to a specific watermark (for frame cleanup)
        pub fn resetTo(self: *Self, mark: usize) void {
            assert(mark <= self.len);
            self.len = mark;
        }

        /// Get current position as watermark
        pub fn watermark(self: *const Self) usize {
            return self.len;
        }
    };
}

// ============================================================================
// Binding Map
// ============================================================================

/// Stack-allocated binding map for variable lookup.
/// Uses linear search (fast for small N typical in ErgoTree).
pub fn BindingMap(comptime V: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            id: u32,
            value: V,
        };

        entries: [capacity]Entry = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn put(self: *Self, id: u32, value: V) error{MapFull}!void {
            // Check for existing entry (update in place)
            for (self.entries[0..self.len]) |*e| {
                if (e.id == id) {
                    e.value = value;
                    return;
                }
            }
            // Add new entry
            if (self.len >= capacity) return error.MapFull;
            self.entries[self.len] = .{ .id = id, .value = value };
            self.len += 1;
        }

        pub fn get(self: *const Self, id: u32) ?V {
            for (self.entries[0..self.len]) |e| {
                if (e.id == id) return e.value;
            }
            return null;
        }

        pub fn contains(self: *const Self, id: u32) bool {
            return self.get(id) != null;
        }

        pub fn reset(self: *Self) void {
            self.len = 0;
        }

        pub fn resetTo(self: *Self, mark: usize) void {
            assert(mark <= self.len);
            self.len = mark;
        }

        pub fn watermark(self: *const Self) usize {
            return self.len;
        }
    };
}

// ============================================================================
// Arena Allocator (Bump Allocator)
// ============================================================================

/// Fixed-capacity bump allocator for variable-sized data.
/// Supports only allocation, not deallocation (reset clears all).
pub fn BumpAllocator(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        buffer: [capacity]u8 = undefined,
        offset: usize = 0,

        pub fn init() Self {
            return .{};
        }

        /// Allocate aligned memory for type T
        pub fn alloc(self: *Self, comptime T: type, n: usize) error{OutOfMemory}![*]T {
            const alignment = @alignOf(T);
            const aligned_offset = std.mem.alignForward(usize, self.offset, alignment);
            const size = @sizeOf(T) * n;
            const end = aligned_offset + size;

            if (end > capacity) return error.OutOfMemory;

            const ptr: [*]T = @ptrCast(@alignCast(self.buffer[aligned_offset..].ptr));
            self.offset = end;
            return ptr;
        }

        /// Allocate and zero-initialize
        pub fn allocZeroed(self: *Self, comptime T: type, n: usize) error{OutOfMemory}![*]T {
            const ptr = try self.alloc(T, n);
            @memset(ptr[0..n], std.mem.zeroes(T));
            return ptr;
        }

        /// Allocate slice
        pub fn allocSlice(self: *Self, comptime T: type, n: usize) error{OutOfMemory}![]T {
            const ptr = try self.alloc(T, n);
            return ptr[0..n];
        }

        /// Remaining capacity in bytes
        pub fn remaining(self: *const Self) usize {
            return capacity - self.offset;
        }

        /// Used bytes
        pub fn used(self: *const Self) usize {
            return self.offset;
        }

        /// Reset to empty (invalidates all previous allocations)
        pub fn reset(self: *Self) void {
            self.offset = 0;
        }
    };
}

// ============================================================================
// Evaluation Frame
// ============================================================================

/// Frame marker for stack cleanup
pub const FrameMarker = struct {
    value_watermark: usize,
    binding_watermark: usize,
};

// ============================================================================
// Evaluation Pools
// ============================================================================

/// Combined pools for a single evaluation.
/// Designed for reuse across multiple transactions.
pub const EvalPools = struct {
    /// Type pool (shared, rarely changes)
    type_pool: types.TypePool,

    /// Value stack for computation
    value_stack: StackAllocator(ValueIndex, max_value_stack),

    /// Binding map for variable lookup
    bindings: BindingMap(ValueIndex, max_bindings),

    /// Frame markers for scope management
    frames: StackAllocator(FrameMarker, max_eval_depth),

    /// Bump allocator for variable-sized data (byte arrays, etc.)
    arena: BumpAllocator(64 * 1024), // 64KB arena

    /// Cost accounting
    cost_used: u64,
    cost_limit: u64,

    pub fn init() EvalPools {
        return .{
            .type_pool = types.TypePool.init(),
            .value_stack = StackAllocator(ValueIndex, max_value_stack).init(),
            .bindings = BindingMap(ValueIndex, max_bindings).init(),
            .frames = StackAllocator(FrameMarker, max_eval_depth).init(),
            .arena = BumpAllocator(64 * 1024).init(),
            .cost_used = 0,
            .cost_limit = default_cost_limit,
        };
    }

    /// Reset all pools for new evaluation
    pub fn reset(self: *EvalPools) void {
        self.value_stack.reset();
        self.bindings.reset();
        self.frames.reset();
        self.arena.reset();
        self.type_pool.reset();
        self.cost_used = 0;
    }

    /// Set cost limit for evaluation
    pub fn setCostLimit(self: *EvalPools, limit: u64) void {
        self.cost_limit = limit;
    }

    /// Add cost, returns error if budget exceeded
    pub fn addCost(self: *EvalPools, cost: u64) error{CostLimitExceeded}!void {
        self.cost_used +|= cost; // Saturating add
        if (self.cost_used > self.cost_limit) {
            return error.CostLimitExceeded;
        }
    }

    /// Push a new evaluation frame
    pub fn pushFrame(self: *EvalPools) error{StackOverflow}!void {
        try self.frames.push(.{
            .value_watermark = self.value_stack.watermark(),
            .binding_watermark = self.bindings.watermark(),
        });
    }

    /// Pop evaluation frame and clean up
    pub fn popFrame(self: *EvalPools) void {
        if (self.frames.pop()) |frame| {
            self.value_stack.resetTo(frame.value_watermark);
            self.bindings.resetTo(frame.binding_watermark);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "memory: StackAllocator push/pop" {
    var stack = StackAllocator(u32, 4).init();

    try std.testing.expect(stack.isEmpty());
    try stack.push(10);
    try stack.push(20);
    try stack.push(30);

    try std.testing.expectEqual(@as(usize, 3), stack.len);
    try std.testing.expectEqual(@as(?u32, 30), stack.peek());
    try std.testing.expectEqual(@as(?u32, 30), stack.pop());
    try std.testing.expectEqual(@as(?u32, 20), stack.pop());
    try std.testing.expectEqual(@as(usize, 1), stack.len);
}

test "memory: StackAllocator overflow" {
    var stack = StackAllocator(u32, 2).init();

    try stack.push(1);
    try stack.push(2);
    try std.testing.expectError(error.StackOverflow, stack.push(3));
}

test "memory: StackAllocator watermark reset" {
    var stack = StackAllocator(u32, 8).init();

    try stack.push(1);
    try stack.push(2);
    const mark = stack.watermark();
    try stack.push(3);
    try stack.push(4);

    try std.testing.expectEqual(@as(usize, 4), stack.len);
    stack.resetTo(mark);
    try std.testing.expectEqual(@as(usize, 2), stack.len);
    try std.testing.expectEqual(@as(?u32, 2), stack.peek());
}

test "memory: BindingMap put/get" {
    var map = BindingMap(u64, 8).init();

    try map.put(1, 100);
    try map.put(2, 200);
    try map.put(3, 300);

    try std.testing.expectEqual(@as(?u64, 100), map.get(1));
    try std.testing.expectEqual(@as(?u64, 200), map.get(2));
    try std.testing.expectEqual(@as(?u64, 300), map.get(3));
    try std.testing.expectEqual(@as(?u64, null), map.get(4));
}

test "memory: BindingMap update existing" {
    var map = BindingMap(u64, 4).init();

    try map.put(1, 100);
    try map.put(1, 999); // Update
    try std.testing.expectEqual(@as(?u64, 999), map.get(1));
    try std.testing.expectEqual(@as(usize, 1), map.len);
}

test "memory: BindingMap watermark" {
    var map = BindingMap(u64, 8).init();

    try map.put(1, 100);
    const mark = map.watermark();
    try map.put(2, 200);
    try map.put(3, 300);

    try std.testing.expect(map.contains(2));
    map.resetTo(mark);
    try std.testing.expect(!map.contains(2));
    try std.testing.expect(map.contains(1));
}

test "memory: BumpAllocator alloc" {
    var arena = BumpAllocator(256).init();

    const a = try arena.allocSlice(u32, 4);
    try std.testing.expectEqual(@as(usize, 4), a.len);

    const b = try arena.allocSlice(u8, 10);
    try std.testing.expectEqual(@as(usize, 10), b.len);

    // Check we can write to allocated memory
    a[0] = 42;
    b[0] = 255;
    try std.testing.expectEqual(@as(u32, 42), a[0]);
    try std.testing.expectEqual(@as(u8, 255), b[0]);
}

test "memory: BumpAllocator out of memory" {
    var arena = BumpAllocator(16).init();

    _ = try arena.allocSlice(u8, 8);
    _ = try arena.allocSlice(u8, 8);
    try std.testing.expectError(error.OutOfMemory, arena.allocSlice(u8, 1));
}

test "memory: BumpAllocator reset" {
    var arena = BumpAllocator(64).init();

    _ = try arena.allocSlice(u8, 32);
    try std.testing.expectEqual(@as(usize, 32), arena.used());

    arena.reset();
    try std.testing.expectEqual(@as(usize, 0), arena.used());
    try std.testing.expectEqual(@as(usize, 64), arena.remaining());
}

test "memory: EvalPools initialization" {
    var pools = EvalPools.init();

    try std.testing.expect(pools.value_stack.isEmpty());
    try std.testing.expect(pools.bindings.len == 0);
    try std.testing.expect(pools.frames.isEmpty());
    try std.testing.expectEqual(@as(u64, 0), pools.cost_used);
    try std.testing.expectEqual(default_cost_limit, pools.cost_limit);
}

test "memory: EvalPools cost accounting" {
    var pools = EvalPools.init();
    pools.setCostLimit(100);

    try pools.addCost(50);
    try std.testing.expectEqual(@as(u64, 50), pools.cost_used);

    try pools.addCost(40);
    try std.testing.expectEqual(@as(u64, 90), pools.cost_used);

    try std.testing.expectError(error.CostLimitExceeded, pools.addCost(20));
}

test "memory: EvalPools frame management" {
    var pools = EvalPools.init();

    // Push some values and bindings
    try pools.value_stack.push(1);
    try pools.value_stack.push(2);
    try pools.bindings.put(10, 100);

    // Push frame
    try pools.pushFrame();

    // Add more in new frame
    try pools.value_stack.push(3);
    try pools.value_stack.push(4);
    try pools.bindings.put(20, 200);

    try std.testing.expectEqual(@as(usize, 4), pools.value_stack.len);
    try std.testing.expect(pools.bindings.contains(20));

    // Pop frame - should restore to before
    pools.popFrame();

    try std.testing.expectEqual(@as(usize, 2), pools.value_stack.len);
    try std.testing.expect(!pools.bindings.contains(20));
    try std.testing.expect(pools.bindings.contains(10));
}

test "memory: EvalPools reset" {
    var pools = EvalPools.init();

    try pools.value_stack.push(1);
    try pools.bindings.put(1, 1);
    try pools.addCost(100);

    pools.reset();

    try std.testing.expect(pools.value_stack.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), pools.bindings.len);
    try std.testing.expectEqual(@as(u64, 0), pools.cost_used);
}
