//! Register Cache for Lazy Loading
//!
//! Provides per-evaluation caching of deserialized box registers R4-R9.
//! Registers are stored as raw bytes in BoxView and deserialized on first
//! access via ExtractRegisterAs. Cached results are reused on subsequent access.
//!
//! Design:
//!   - Fixed-size array for O(1) lookup (no HashMap for determinism)
//!   - Three-state entries: not_loaded | loaded | absent | invalid
//!   - O(1) reset between evaluations
//!   - Memory: ~14KB for worst case (256 boxes * 3 sources * 6 registers)
//!
//! Reference: Rust ergotree-ir/src/chain/ergo_box/register.rs

const std = @import("std");
const assert = std.debug.assert;
const context = @import("context.zig");
const value_pool = @import("value_pool.zig");

const Register = context.Register;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum boxes per source (inputs/outputs/data_inputs)
const max_boxes_per_source: u16 = 256;

/// Number of cacheable registers (R4-R9)
const register_count: u16 = 6;

/// Entries per source = boxes * registers
const entries_per_source: u16 = max_boxes_per_source * register_count;

/// Total cache entries = 3 sources * entries_per_source
const total_entries: usize = 3 * @as(usize, entries_per_source);

// Compile-time sanity checks (ZIGMA_STYLE: 3+ assertions)
comptime {
    // Cache size must be reasonable
    assert(total_entries == 4608);
    assert(@sizeOf(RegisterCacheEntry) <= 4);
    assert(total_entries * @sizeOf(RegisterCacheEntry) <= 32 * 1024); // <32KB

    // Register indices
    assert(@intFromEnum(Register.R4) == 4);
    assert(@intFromEnum(Register.R9) == 9);
}

// ============================================================================
// Cache Entry
// ============================================================================

/// Error codes for deserialization failures.
/// Stored to provide deterministic error replay on cache hit.
pub const DeserializeErrorCode = enum(u8) {
    /// Unexpected end of data
    unexpected_end = 0,
    /// VLQ overflow
    overflow = 1,
    /// Invalid data format
    invalid_data = 2,
    /// Type mismatch
    type_mismatch = 3,
    /// Invalid group element (not on curve)
    invalid_group_element = 4,
    /// Pool exhausted
    pool_exhausted = 5,
    /// Unsupported type
    unsupported_type = 6,
};

/// Cache entry state for a single register.
pub const RegisterCacheEntry = union(enum) {
    /// Register bytes not yet deserialized
    not_loaded,
    /// Successfully deserialized, value stored at index in ValuePool
    loaded: u16,
    /// Register not present in box (will return Option.None)
    absent,
    /// Deserialization failed (error stored for deterministic replay)
    invalid: DeserializeErrorCode,

    /// Check if this entry needs deserialization
    pub fn needsLoad(self: RegisterCacheEntry) bool {
        return self == .not_loaded;
    }

    /// Check if this entry has a valid cached value
    pub fn isLoaded(self: RegisterCacheEntry) bool {
        return switch (self) {
            .loaded => true,
            else => false,
        };
    }
};

// ============================================================================
// Box Source
// ============================================================================

/// Source of a box (which collection it came from)
pub const BoxSource = enum(u2) {
    inputs = 0,
    outputs = 1,
    data_inputs = 2,
};

// ============================================================================
// Register Cache
// ============================================================================

/// Pre-allocated cache for deserialized register values.
/// Layout: [inputs_R4..R9, inputs_R4..R9, ...][outputs...][data_inputs...]
pub const RegisterCache = struct {
    const Self = @This();

    /// Cache entries: [source][box_idx][reg_idx]
    /// Flattened for simplicity: source * entries_per_source + box_idx * register_count + reg_offset
    entries: [total_entries]RegisterCacheEntry,

    // Compile-time size check
    comptime {
        // Total cache size < 20KB (comfortable for stack allocation)
        assert(@sizeOf(Self) <= 20 * 1024);
    }

    /// Initialize cache with all entries as not_loaded
    pub fn init() Self {
        return .{
            .entries = [_]RegisterCacheEntry{.not_loaded} ** total_entries,
        };
    }

    /// Reset cache for reuse between evaluations (O(1) effective, O(n) actual)
    pub fn reset(self: *Self) void {
        @memset(&self.entries, .not_loaded);
    }

    /// Calculate flat index from (source, box_idx, register)
    fn index(source: BoxSource, box_idx: u16, reg: Register) usize {
        // PRECONDITION: Register is R4-R9
        assert(@intFromEnum(reg) >= 4);
        assert(@intFromEnum(reg) <= 9);
        // PRECONDITION: Box index in range
        assert(box_idx < max_boxes_per_source);

        const reg_offset: usize = @intFromEnum(reg) - 4;
        const box_offset: usize = @as(usize, box_idx) * register_count;
        const source_offset: usize = @intFromEnum(source) * entries_per_source;

        const result = source_offset + box_offset + reg_offset;

        // POSTCONDITION: Index in bounds
        assert(result < total_entries);
        return result;
    }

    /// Get cache entry for a register
    pub fn get(self: *const Self, source: BoxSource, box_idx: u16, reg: Register) RegisterCacheEntry {
        return self.entries[index(source, box_idx, reg)];
    }

    /// Set cache entry for a register
    pub fn set(self: *Self, source: BoxSource, box_idx: u16, reg: Register, entry: RegisterCacheEntry) void {
        self.entries[index(source, box_idx, reg)] = entry;
    }

    /// Mark register as loaded with given ValuePool index
    pub fn markLoaded(self: *Self, source: BoxSource, box_idx: u16, reg: Register, value_idx: u16) void {
        self.set(source, box_idx, reg, .{ .loaded = value_idx });
    }

    /// Mark register as absent (not present in box)
    pub fn markAbsent(self: *Self, source: BoxSource, box_idx: u16, reg: Register) void {
        self.set(source, box_idx, reg, .absent);
    }

    /// Mark register as invalid (deserialization failed)
    pub fn markInvalid(self: *Self, source: BoxSource, box_idx: u16, reg: Register, err: DeserializeErrorCode) void {
        self.set(source, box_idx, reg, .{ .invalid = err });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "register_cache: init all not_loaded" {
    const cache = RegisterCache.init();

    // Check a sample of entries
    try std.testing.expectEqual(RegisterCacheEntry.not_loaded, cache.get(.inputs, 0, .R4));
    try std.testing.expectEqual(RegisterCacheEntry.not_loaded, cache.get(.outputs, 100, .R7));
    try std.testing.expectEqual(RegisterCacheEntry.not_loaded, cache.get(.data_inputs, 255, .R9));
}

test "register_cache: get/set roundtrip" {
    var cache = RegisterCache.init();

    // Set various entries
    cache.markLoaded(.inputs, 5, .R4, 42);
    cache.markAbsent(.outputs, 10, .R6);
    cache.markInvalid(.data_inputs, 0, .R9, .invalid_group_element);

    // Verify
    const loaded = cache.get(.inputs, 5, .R4);
    try std.testing.expect(loaded.isLoaded());
    try std.testing.expectEqual(@as(u16, 42), loaded.loaded);

    try std.testing.expectEqual(RegisterCacheEntry.absent, cache.get(.outputs, 10, .R6));

    const invalid = cache.get(.data_inputs, 0, .R9);
    try std.testing.expectEqual(DeserializeErrorCode.invalid_group_element, invalid.invalid);
}

test "register_cache: reset clears all entries" {
    var cache = RegisterCache.init();

    // Set some entries
    cache.markLoaded(.inputs, 0, .R4, 100);
    cache.markAbsent(.outputs, 50, .R5);

    // Verify they're set
    try std.testing.expect(cache.get(.inputs, 0, .R4).isLoaded());

    // Reset
    cache.reset();

    // All should be not_loaded
    try std.testing.expectEqual(RegisterCacheEntry.not_loaded, cache.get(.inputs, 0, .R4));
    try std.testing.expectEqual(RegisterCacheEntry.not_loaded, cache.get(.outputs, 50, .R5));
}

test "register_cache: needsLoad helper" {
    const not_loaded: RegisterCacheEntry = .not_loaded;
    const loaded: RegisterCacheEntry = .{ .loaded = 5 };
    const absent: RegisterCacheEntry = .absent;
    const invalid: RegisterCacheEntry = .{ .invalid = .overflow };

    try std.testing.expect(not_loaded.needsLoad());
    try std.testing.expect(!loaded.needsLoad());
    try std.testing.expect(!absent.needsLoad());
    try std.testing.expect(!invalid.needsLoad());
}

test "register_cache: isLoaded helper" {
    const not_loaded: RegisterCacheEntry = .not_loaded;
    const loaded: RegisterCacheEntry = .{ .loaded = 5 };
    const absent: RegisterCacheEntry = .absent;
    const invalid: RegisterCacheEntry = .{ .invalid = .overflow };

    try std.testing.expect(!not_loaded.isLoaded());
    try std.testing.expect(loaded.isLoaded());
    try std.testing.expect(!absent.isLoaded());
    try std.testing.expect(!invalid.isLoaded());
}

test "register_cache: index calculation spans all sources" {
    // Test that indices don't overlap between sources
    const idx_inputs_last = RegisterCache.index(.inputs, 255, .R9);
    const idx_outputs_first = RegisterCache.index(.outputs, 0, .R4);

    // Outputs should start right after inputs end
    try std.testing.expectEqual(idx_inputs_last + 1, idx_outputs_first);

    const idx_outputs_last = RegisterCache.index(.outputs, 255, .R9);
    const idx_data_first = RegisterCache.index(.data_inputs, 0, .R4);

    try std.testing.expectEqual(idx_outputs_last + 1, idx_data_first);
}

test "register_cache: max index in bounds" {
    // Verify max index is within array bounds
    const max_idx = RegisterCache.index(.data_inputs, 255, .R9);
    try std.testing.expect(max_idx < total_entries);
    try std.testing.expectEqual(total_entries - 1, max_idx);
}
