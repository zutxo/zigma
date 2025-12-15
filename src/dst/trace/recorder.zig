//! Execution Trace Recorder for DST
//!
//! Captures evaluation state for debugging divergences:
//!   - Initial tree and context snapshot
//!   - Final result and cost
//!   - Comparison between two traces to find divergence points
//!
//! Design: Non-invasive approach - wraps evaluation with pre/post snapshots
//! rather than modifying evaluator internals.

const std = @import("std");
const assert = std.debug.assert;

// Import from zigma module
const zigma = @import("zigma");
const evaluator_mod = zigma.evaluator;
const expr_mod = zigma.expr_serializer;
const data_mod = zigma.data_serializer;
const context_mod = zigma.context;
const types = zigma.types;

const Evaluator = evaluator_mod.Evaluator;
const EvalError = evaluator_mod.EvalError;
const ExprTree = expr_mod.ExprTree;
const ExprNode = expr_mod.ExprNode;
const ExprTag = expr_mod.ExprTag;
const Value = data_mod.Value;
const Context = context_mod.Context;
const TypeIndex = types.TypeIndex;

// ============================================================================
// Types
// ============================================================================

/// Maximum trace entries
pub const max_entries: usize = 256;

/// Single trace entry capturing evaluation state
pub const TraceEntry = struct {
    /// Root node tag
    root_tag: ExprTag,
    /// Root node type
    root_type: TypeIndex,
    /// Total nodes in tree
    node_count: u16,
    /// Total values in tree
    value_count: u16,
    /// Context height
    height: u32,
    /// Number of inputs
    input_count: u8,
    /// Number of outputs
    output_count: u8,
    /// Cost consumed
    cost_used: u64,
    /// Whether evaluation succeeded
    success: bool,
    /// Error code if failed
    error_code: u8,
    /// Result type (if success)
    result_type: u8,
    /// Simple result hash for comparison
    result_hash: u32,

    pub fn eql(self: TraceEntry, other: TraceEntry) bool {
        return self.root_tag == other.root_tag and
            self.root_type == other.root_type and
            self.node_count == other.node_count and
            self.value_count == other.value_count and
            self.height == other.height and
            self.input_count == other.input_count and
            self.output_count == other.output_count and
            self.cost_used == other.cost_used and
            self.success == other.success and
            self.error_code == other.error_code and
            self.result_type == other.result_type and
            self.result_hash == other.result_hash;
    }
};

/// Divergence information between two traces
pub const Divergence = struct {
    /// Index where traces diverged
    index: usize,
    /// Expected entry
    expected: TraceEntry,
    /// Actual entry
    got: TraceEntry,
    /// Which field diverged first
    field: DivergentField,
};

pub const DivergentField = enum {
    root_tag,
    root_type,
    node_count,
    value_count,
    height,
    input_count,
    output_count,
    cost_used,
    success,
    error_code,
    result_type,
    result_hash,
};

/// Trace recorder
pub const TraceRecorder = struct {
    /// Recorded entries (fixed-size, no allocation)
    entries: [max_entries]TraceEntry = undefined,
    /// Number of entries recorded
    count: usize = 0,

    /// Record initial state before evaluation
    pub fn recordInitial(
        self: *TraceRecorder,
        tree: *const ExprTree,
        ctx: *const Context,
    ) void {
        if (self.count >= max_entries) return;

        const root = tree.root() orelse ExprNode{
            .tag = .unit,
            .result_type = 0,
        };

        self.entries[self.count] = .{
            .root_tag = root.tag,
            .root_type = root.result_type,
            .node_count = tree.node_count,
            .value_count = tree.value_count,
            .height = ctx.height,
            .input_count = @intCast(@min(ctx.inputs.len, 255)),
            .output_count = @intCast(@min(ctx.outputs.len, 255)),
            .cost_used = 0,
            .success = false,
            .error_code = 0,
            .result_type = 0,
            .result_hash = 0,
        };
        self.count += 1;
    }

    /// Record final state after evaluation
    pub fn recordFinal(
        self: *TraceRecorder,
        cost_used: u64,
        result: EvalError!Value,
    ) void {
        if (self.count == 0) return;

        const entry = &self.entries[self.count - 1];
        entry.cost_used = cost_used;

        if (result) |value| {
            entry.success = true;
            entry.error_code = 0;
            entry.result_type = @intFromEnum(std.meta.activeTag(value));
            entry.result_hash = hashValue(value);
        } else |err| {
            entry.success = false;
            entry.error_code = errorToCode(err);
            entry.result_type = 0;
            entry.result_hash = 0;
        }
    }

    /// Compare two traces for divergence
    pub fn compare(self: *const TraceRecorder, other: *const TraceRecorder) ?Divergence {
        const min_count = @min(self.count, other.count);

        for (0..min_count) |i| {
            const a = self.entries[i];
            const b = other.entries[i];

            if (!a.eql(b)) {
                return .{
                    .index = i,
                    .expected = a,
                    .got = b,
                    .field = findDivergentField(a, b),
                };
            }
        }

        // Check if counts differ
        if (self.count != other.count) {
            return .{
                .index = min_count,
                .expected = if (self.count > min_count) self.entries[min_count] else TraceEntry{
                    .root_tag = .unit,
                    .root_type = 0,
                    .node_count = 0,
                    .value_count = 0,
                    .height = 0,
                    .input_count = 0,
                    .output_count = 0,
                    .cost_used = 0,
                    .success = false,
                    .error_code = 0,
                    .result_type = 0,
                    .result_hash = 0,
                },
                .got = if (other.count > min_count) other.entries[min_count] else TraceEntry{
                    .root_tag = .unit,
                    .root_type = 0,
                    .node_count = 0,
                    .value_count = 0,
                    .height = 0,
                    .input_count = 0,
                    .output_count = 0,
                    .cost_used = 0,
                    .success = false,
                    .error_code = 0,
                    .result_type = 0,
                    .result_hash = 0,
                },
                .field = .node_count, // Arbitrary
            };
        }

        return null;
    }

    /// Serialize trace to binary format
    pub fn serialize(self: *const TraceRecorder, writer: anytype) !void {
        // Write header
        try writer.writeInt(u32, @intCast(self.count), .little);

        // Write entries
        for (self.entries[0..self.count]) |entry| {
            try writer.writeInt(u8, @intFromEnum(entry.root_tag), .little);
            try writer.writeInt(u16, entry.root_type, .little);
            try writer.writeInt(u16, entry.node_count, .little);
            try writer.writeInt(u16, entry.value_count, .little);
            try writer.writeInt(u32, entry.height, .little);
            try writer.writeInt(u8, entry.input_count, .little);
            try writer.writeInt(u8, entry.output_count, .little);
            try writer.writeInt(u64, entry.cost_used, .little);
            try writer.writeInt(u8, if (entry.success) 1 else 0, .little);
            try writer.writeInt(u8, entry.error_code, .little);
            try writer.writeInt(u8, entry.result_type, .little);
            try writer.writeInt(u32, entry.result_hash, .little);
        }
    }

    /// Clear recorded entries
    pub fn clear(self: *TraceRecorder) void {
        self.count = 0;
    }
};

/// Traced evaluation result
pub const TraceResult = struct {
    /// The evaluation result
    result: EvalError!Value,
    /// Cost consumed
    cost_used: u64,
    /// Trace of the evaluation
    trace: TraceRecorder,
};

/// Perform traced evaluation
pub fn traceEvaluation(tree: *const ExprTree, ctx: *const Context) TraceResult {
    var recorder = TraceRecorder{};

    // Record initial state
    recorder.recordInitial(tree, ctx);

    // Create mutable copies for evaluation
    var tree_copy = tree.*;
    var ctx_copy = ctx.*;

    // Evaluate
    var eval = Evaluator.init(&tree_copy, &ctx_copy);
    const result = eval.evaluate();

    // Record final state
    recorder.recordFinal(eval.cost_used, result);

    return .{
        .result = result,
        .cost_used = eval.cost_used,
        .trace = recorder,
    };
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple hash of a Value for comparison
fn hashValue(value: Value) u32 {
    var hash: u32 = 0;

    switch (value) {
        .unit => hash = 0,
        .boolean => |v| hash = if (v) 1 else 0,
        .byte => |v| hash = @as(u32, @bitCast(@as(i32, v))),
        .short => |v| hash = @bitCast(@as(i32, v)),
        .int => |v| hash = @bitCast(v),
        .long => |v| hash = @truncate(@as(u64, @bitCast(v))),
        .big_int => |v| {
            for (v.bytes[0..v.len]) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .unsigned_big_int => |v| {
            for (v.bytes[0..v.len]) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .group_element => |v| {
            for (v) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .sigma_prop => |v| {
            for (v.data) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .coll_byte => |v| {
            for (v) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .option => |v| {
            hash = v.inner_type;
            hash = hash *% 31 +% v.value_idx;
        },
        .box => |v| {
            hash = @intFromEnum(v.source);
            hash = hash *% 31 +% v.index;
        },
        .box_coll => |v| {
            hash = @intFromEnum(v.source);
        },
        .header => |v| {
            for (v.id) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .avl_tree => |v| {
            for (v.digest) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .hash32 => |v| {
            for (v) |b| {
                hash = hash *% 31 +% b;
            }
        },
        .soft_fork_placeholder => hash = 0xDEAD,
        .tuple => |v| {
            hash = v.start;
            hash = hash *% 31 +% v.len;
        },
        .coll => |v| {
            hash = v.elem_type;
            hash = hash *% 31 +% v.start;
            hash = hash *% 31 +% v.len;
        },
    }

    return hash;
}

/// Convert error to numeric code
fn errorToCode(err: EvalError) u8 {
    return switch (err) {
        error.CostLimitExceeded => 1,
        error.WorkStackOverflow => 2,
        error.ValueStackOverflow => 3,
        error.DivisionByZero => 4,
        error.IndexOutOfBounds => 5,
        error.TypeMismatch => 6,
        error.UnsupportedExpression => 7,
        error.ArithmeticOverflow => 8,
        error.InvalidData => 9,
        error.TimeoutExceeded => 10,
        error.InvalidGroupElement => 11,
        error.InvalidBigInt => 12,
        error.OptionNone => 13,
        error.UndefinedVariable => 14,
        error.InvalidBinOp => 15,
        error.InvalidNodeIndex => 16,
        error.InvalidConstantIndex => 17,
        error.ValueStackUnderflow => 18,
        error.InvalidShift => 19,
        error.InvalidContext => 20,
        error.InvalidState => 21,
        error.CollectionTooLarge => 22,
        error.SoftForkAccepted => 23,
        error.OutOfMemory => 254,
    };
}

/// Find which field diverged first between two entries
fn findDivergentField(a: TraceEntry, b: TraceEntry) DivergentField {
    if (a.root_tag != b.root_tag) return .root_tag;
    if (a.root_type != b.root_type) return .root_type;
    if (a.node_count != b.node_count) return .node_count;
    if (a.value_count != b.value_count) return .value_count;
    if (a.height != b.height) return .height;
    if (a.input_count != b.input_count) return .input_count;
    if (a.output_count != b.output_count) return .output_count;
    if (a.cost_used != b.cost_used) return .cost_used;
    if (a.success != b.success) return .success;
    if (a.error_code != b.error_code) return .error_code;
    if (a.result_type != b.result_type) return .result_type;
    return .result_hash;
}

// ============================================================================
// Tests
// ============================================================================

test "recorder: record initial state" {
    var recorder = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder.recordInitial(&tree, &ctx);

    try std.testing.expectEqual(@as(usize, 1), recorder.count);
    try std.testing.expectEqual(ExprTag.true_leaf, recorder.entries[0].root_tag);
    try std.testing.expectEqual(@as(u16, 1), recorder.entries[0].node_count);
    try std.testing.expectEqual(@as(u32, 100), recorder.entries[0].height);
}

test "recorder: record final success" {
    var recorder = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder.recordInitial(&tree, &ctx);
    recorder.recordFinal(50, Value{ .boolean = true });

    try std.testing.expect(recorder.entries[0].success);
    try std.testing.expectEqual(@as(u64, 50), recorder.entries[0].cost_used);
    try std.testing.expectEqual(@as(u32, 1), recorder.entries[0].result_hash); // true = 1
}

test "recorder: record final error" {
    var recorder = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = types.TypePool.INT };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder.recordInitial(&tree, &ctx);
    recorder.recordFinal(10, error.CostLimitExceeded);

    try std.testing.expect(!recorder.entries[0].success);
    try std.testing.expectEqual(@as(u8, 1), recorder.entries[0].error_code);
}

test "recorder: compare identical traces" {
    var recorder1 = TraceRecorder{};
    var recorder2 = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder1.recordInitial(&tree, &ctx);
    recorder1.recordFinal(50, Value{ .boolean = true });

    recorder2.recordInitial(&tree, &ctx);
    recorder2.recordFinal(50, Value{ .boolean = true });

    const divergence = recorder1.compare(&recorder2);
    try std.testing.expect(divergence == null);
}

test "recorder: compare divergent traces" {
    var recorder1 = TraceRecorder{};
    var recorder2 = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder1.recordInitial(&tree, &ctx);
    recorder1.recordFinal(50, Value{ .boolean = true });

    recorder2.recordInitial(&tree, &ctx);
    recorder2.recordFinal(60, Value{ .boolean = true }); // Different cost

    const divergence = recorder1.compare(&recorder2);
    try std.testing.expect(divergence != null);
    try std.testing.expectEqual(DivergentField.cost_used, divergence.?.field);
}

test "recorder: trace evaluation" {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    const trace_result = traceEvaluation(&tree, &ctx);

    try std.testing.expect(trace_result.trace.count == 1);
    if (trace_result.result) |value| {
        try std.testing.expectEqual(Value{ .boolean = true }, value);
    } else |_| {
        try std.testing.expect(false); // Should not fail
    }
}

test "recorder: serialize" {
    var recorder = TraceRecorder{};

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = types.TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]context_mod.BoxView{context_mod.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    recorder.recordInitial(&tree, &ctx);
    recorder.recordFinal(50, Value{ .boolean = true });

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try recorder.serialize(fbs.writer());

    // Just verify it doesn't crash and writes something
    try std.testing.expect(fbs.pos > 0);
}
