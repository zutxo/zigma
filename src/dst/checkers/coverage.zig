//! Coverage Tracker for DST
//!
//! Tracks opcode and type coverage during simulation:
//!   - Opcode hits: how many times each opcode was evaluated
//!   - Type hits: how many times each type was seen
//!   - Depth distribution: expression tree size histogram

const std = @import("std");
const zigma = @import("zigma");
const ExprTree = zigma.expr_serializer.ExprTree;
const ExprTag = zigma.expr_serializer.ExprTag;

// ============================================================================
// Types
// ============================================================================

/// Coverage tracker for DST
pub const CoverageTracker = struct {
    /// Hits per opcode
    opcode_hits: [@typeInfo(ExprTag).@"enum".fields.len]u64 = [_]u64{0} ** @typeInfo(ExprTag).@"enum".fields.len,
    /// Hits per type (max 256 types)
    type_hits: [256]u64 = [_]u64{0} ** 256,
    /// Expression size histogram (0-63 nodes)
    size_hits: [64]u64 = [_]u64{0} ** 64,

    /// Record coverage from a tree
    pub fn record(self: *CoverageTracker, tree: *const ExprTree) void {
        for (tree.nodes[0..tree.node_count]) |node| {
            self.opcode_hits[@intFromEnum(node.tag)] += 1;
            self.type_hits[@min(node.result_type, 255)] += 1;
        }
        self.size_hits[@min(tree.node_count, 63)] += 1;
    }

    /// Get opcode coverage percentage
    pub fn opcodeCoverage(self: *const CoverageTracker) f32 {
        const total = @typeInfo(ExprTag).@"enum".fields.len;
        var covered: u32 = 0;
        for (self.opcode_hits) |hits| {
            if (hits > 0) covered += 1;
        }
        return @as(f32, @floatFromInt(covered)) / @as(f32, @floatFromInt(total)) * 100.0;
    }

    /// Get covered/total opcode counts
    pub fn opcodeCounts(self: *const CoverageTracker) struct { covered: u32, total: u32 } {
        const total: u32 = @typeInfo(ExprTag).@"enum".fields.len;
        var covered: u32 = 0;
        for (self.opcode_hits) |hits| {
            if (hits > 0) covered += 1;
        }
        return .{ .covered = covered, .total = total };
    }

    /// Get type coverage percentage
    pub fn typeCoverage(self: *const CoverageTracker, max_types: u32) f32 {
        var covered: u32 = 0;
        for (self.type_hits[0..@min(max_types, 256)]) |hits| {
            if (hits > 0) covered += 1;
        }
        return @as(f32, @floatFromInt(covered)) / @as(f32, @floatFromInt(max_types)) * 100.0;
    }

    /// Reset coverage stats
    pub fn reset(self: *CoverageTracker) void {
        self.* = .{};
    }
};

// ============================================================================
// Tests
// ============================================================================

test "coverage: record tree" {
    const types = zigma.types;

    var tracker = CoverageTracker{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    tracker.record(&tree);

    try std.testing.expect(tracker.opcode_hits[@intFromEnum(ExprTag.true_leaf)] == 1);
    try std.testing.expect(tracker.type_hits[types.TypePool.BOOLEAN] == 1);
    try std.testing.expect(tracker.size_hits[1] == 1);
}

test "coverage: opcode coverage percentage" {
    var tracker = CoverageTracker{};

    // No coverage initially
    try std.testing.expect(tracker.opcodeCoverage() == 0.0);

    // Record one opcode
    tracker.opcode_hits[@intFromEnum(ExprTag.true_leaf)] = 1;

    const coverage = tracker.opcodeCoverage();
    const expected = 100.0 / @as(f32, @floatFromInt(@typeInfo(ExprTag).@"enum".fields.len));
    try std.testing.expect(@abs(coverage - expected) < 0.01);
}

test "coverage: opcode counts" {
    var tracker = CoverageTracker{};

    tracker.opcode_hits[@intFromEnum(ExprTag.true_leaf)] = 10;
    tracker.opcode_hits[@intFromEnum(ExprTag.false_leaf)] = 5;
    tracker.opcode_hits[@intFromEnum(ExprTag.height)] = 1;

    const counts = tracker.opcodeCounts();
    try std.testing.expectEqual(@as(u32, 3), counts.covered);
    try std.testing.expectEqual(@as(u32, @typeInfo(ExprTag).@"enum".fields.len), counts.total);
}

test "coverage: reset" {
    var tracker = CoverageTracker{};
    tracker.opcode_hits[@intFromEnum(ExprTag.true_leaf)] = 100;
    tracker.type_hits[0] = 50;
    tracker.size_hits[1] = 25;

    tracker.reset();

    try std.testing.expectEqual(@as(u64, 0), tracker.opcode_hits[@intFromEnum(ExprTag.true_leaf)]);
    try std.testing.expectEqual(@as(u64, 0), tracker.type_hits[0]);
    try std.testing.expectEqual(@as(u64, 0), tracker.size_hits[1]);
}
