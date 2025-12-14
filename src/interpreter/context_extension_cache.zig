//! Context Extension Cache for Per-Input Variables
//!
//! Provides per-input storage of context extension variables for getVarFromInput.
//! Each input (and data_input) can have its own set of context variables (0-255).
//!
//! Design:
//!   - Fixed-size array for O(1) lookup (no HashMap for determinism)
//!   - Two sources: inputs and data_inputs (outputs don't have extensions)
//!   - O(1) lookup, O(n) reset between evaluations
//!   - Memory: ~2MB for worst case (256 boxes * 2 sources * 256 vars * 16 bytes)
//!
//! Reference: Rust ergotree-ir/src/chain/context_extension.rs

const std = @import("std");
const assert = std.debug.assert;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum boxes per source (inputs/data_inputs)
pub const max_boxes_per_source: u16 = 256;

/// Maximum context variables per box
pub const max_vars_per_box: u16 = 256;

/// Entries per source = boxes * vars
const entries_per_source: usize = @as(usize, max_boxes_per_source) * max_vars_per_box;

/// Total cache entries = 2 sources * entries_per_source
/// (inputs + data_inputs, outputs don't have context extensions)
const total_entries: usize = 2 * entries_per_source;

// Compile-time sanity checks (ZIGMA_STYLE: 3+ assertions)
comptime {
    // Cache dimensions
    assert(max_boxes_per_source == 256);
    assert(max_vars_per_box == 256);
    assert(entries_per_source == 65536);
    assert(total_entries == 131072);

    // Slice size check (pointer + length = 16 bytes on 64-bit)
    assert(@sizeOf(?[]const u8) == 16);
}

// ============================================================================
// Extension Source
// ============================================================================

/// Source of context extension (which box collection)
/// Note: outputs don't have context extensions
pub const ExtensionSource = enum(u1) {
    inputs = 0,
    data_inputs = 1,
};

// ============================================================================
// Context Extension Cache
// ============================================================================

/// Pre-allocated cache for per-input context extension variables.
/// Layout: [inputs: box0_var0..var255, box1_var0..var255, ...][data_inputs: ...]
pub const ContextExtensionCache = struct {
    const Self = @This();

    /// Cache entries: [source][box_idx][var_id]
    /// Each entry is optional slice pointing to serialized value bytes
    entries: [total_entries]?[]const u8,

    // Compile-time size check
    comptime {
        // Total cache size ~2MB (acceptable for pre-allocation)
        assert(@sizeOf(Self) <= 2 * 1024 * 1024 + 1024);
    }

    /// Initialize cache with all entries as null (no variables set)
    pub fn init() Self {
        return .{
            .entries = [_]?[]const u8{null} ** total_entries,
        };
    }

    /// Reset cache for reuse between evaluations
    pub fn reset(self: *Self) void {
        @memset(&self.entries, null);
    }

    /// Calculate flat index from (source, box_idx, var_id)
    fn index(source: ExtensionSource, box_idx: u16, var_id: u8) usize {
        // PRECONDITION: Box index in range
        assert(box_idx < max_boxes_per_source);

        const var_offset: usize = var_id;
        const box_offset: usize = @as(usize, box_idx) * max_vars_per_box;
        const source_offset: usize = @intFromEnum(source) * entries_per_source;

        const result = source_offset + box_offset + var_offset;

        // POSTCONDITION: Index in bounds
        assert(result < total_entries);
        return result;
    }

    /// Get context variable for a box
    /// Returns null if variable not set
    pub fn get(self: *const Self, source: ExtensionSource, box_idx: u16, var_id: u8) ?[]const u8 {
        return self.entries[index(source, box_idx, var_id)];
    }

    /// Set context variable for a box
    pub fn set(self: *Self, source: ExtensionSource, box_idx: u16, var_id: u8, data: ?[]const u8) void {
        self.entries[index(source, box_idx, var_id)] = data;
    }

    /// Check if a variable is set for a box
    pub fn has(self: *const Self, source: ExtensionSource, box_idx: u16, var_id: u8) bool {
        return self.entries[index(source, box_idx, var_id)] != null;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "context_extension_cache: init all null" {
    const cache = ContextExtensionCache.init();

    // Check a sample of entries
    try std.testing.expectEqual(@as(?[]const u8, null), cache.get(.inputs, 0, 0));
    try std.testing.expectEqual(@as(?[]const u8, null), cache.get(.inputs, 100, 42));
    try std.testing.expectEqual(@as(?[]const u8, null), cache.get(.data_inputs, 255, 255));
}

test "context_extension_cache: get/set roundtrip" {
    var cache = ContextExtensionCache.init();

    const var_data1 = [_]u8{ 0x04, 0x54 }; // SInt 42
    const var_data2 = [_]u8{ 0x01, 0x01 }; // Boolean true

    // Set variables
    cache.set(.inputs, 0, 5, &var_data1);
    cache.set(.data_inputs, 10, 100, &var_data2);

    // Verify
    const result1 = cache.get(.inputs, 0, 5);
    try std.testing.expect(result1 != null);
    try std.testing.expectEqualSlices(u8, &var_data1, result1.?);

    const result2 = cache.get(.data_inputs, 10, 100);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqualSlices(u8, &var_data2, result2.?);

    // Unset variable should still be null
    try std.testing.expectEqual(@as(?[]const u8, null), cache.get(.inputs, 0, 6));
}

test "context_extension_cache: reset clears all entries" {
    var cache = ContextExtensionCache.init();

    const var_data = [_]u8{0x42};
    cache.set(.inputs, 0, 0, &var_data);
    cache.set(.data_inputs, 50, 128, &var_data);

    // Verify they're set
    try std.testing.expect(cache.has(.inputs, 0, 0));
    try std.testing.expect(cache.has(.data_inputs, 50, 128));

    // Reset
    cache.reset();

    // All should be null
    try std.testing.expect(!cache.has(.inputs, 0, 0));
    try std.testing.expect(!cache.has(.data_inputs, 50, 128));
}

test "context_extension_cache: has helper" {
    var cache = ContextExtensionCache.init();

    try std.testing.expect(!cache.has(.inputs, 0, 0));

    const var_data = [_]u8{0x01};
    cache.set(.inputs, 0, 0, &var_data);

    try std.testing.expect(cache.has(.inputs, 0, 0));
}

test "context_extension_cache: index calculation spans sources" {
    // Test that indices don't overlap between sources
    const idx_inputs_last = ContextExtensionCache.index(.inputs, 255, 255);
    const idx_data_first = ContextExtensionCache.index(.data_inputs, 0, 0);

    // data_inputs should start right after inputs end
    try std.testing.expectEqual(idx_inputs_last + 1, idx_data_first);
}

test "context_extension_cache: max index in bounds" {
    // Verify max index is within array bounds
    const max_idx = ContextExtensionCache.index(.data_inputs, 255, 255);
    try std.testing.expect(max_idx < total_entries);
    try std.testing.expectEqual(total_entries - 1, max_idx);
}

test "context_extension_cache: set null clears entry" {
    var cache = ContextExtensionCache.init();

    const var_data = [_]u8{0x42};
    cache.set(.inputs, 5, 10, &var_data);
    try std.testing.expect(cache.has(.inputs, 5, 10));

    // Clear by setting to null
    cache.set(.inputs, 5, 10, null);
    try std.testing.expect(!cache.has(.inputs, 5, 10));
}
