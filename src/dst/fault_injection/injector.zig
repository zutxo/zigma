//! Fault Injector for DST
//!
//! Systematically injects faults to test error handling paths:
//!   - Boundary conditions (overflow, underflow, zero division)
//!   - Malformed data (invalid indices, types, opcodes)
//!   - Resource exhaustion (cost limits)
//!
//! Faults are injected in-place into expression trees, and the evaluator
//! is expected to return appropriate errors (not crash).

const std = @import("std");
const assert = std.debug.assert;

const prng_mod = @import("../prng.zig");
const PRNG = prng_mod.PRNG;

// Import from zigma module
const zigma = @import("zigma");
const expr_mod = zigma.expr_serializer;
const data_mod = zigma.data_serializer;
const types = zigma.types;

const ExprTree = expr_mod.ExprTree;
const ExprNode = expr_mod.ExprNode;
const ExprTag = expr_mod.ExprTag;
const BinOpKind = expr_mod.BinOpKind;
const Value = data_mod.Value;
const TypePool = types.TypePool;
const TypeIndex = types.TypeIndex;

// ============================================================================
// Types
// ============================================================================

/// Types of faults that can be injected
pub const FaultKind = enum {
    // Boundary conditions
    /// Set constant to i32 max value
    int_max,
    /// Set constant to i32 min value
    int_min,
    /// Set constant to i64 max value
    long_max,
    /// Set constant to i64 min value
    long_min,
    /// Set divisor to 0 in division operation
    zero_divisor,
    /// Set very low cost limit (causes CostLimitExceeded)
    cost_exhaustion,

    // Malformed tree
    /// Reference node index beyond tree size
    invalid_node_idx,
    /// Set type index to invalid value
    invalid_type,
    /// Set opcode to unsupported value
    invalid_opcode,

    /// Count of fault kinds for random selection
    pub const count = @typeInfo(FaultKind).@"enum".fields.len;
};

/// Result of fault injection
pub const InjectionResult = struct {
    /// What fault was injected
    kind: FaultKind,
    /// Index of node that was modified
    node_idx: u16,
    /// Whether injection was successful
    success: bool,
};

/// Fault injector
pub const FaultInjector = struct {
    prng: *PRNG,

    pub fn init(prng: *PRNG) FaultInjector {
        return .{ .prng = prng };
    }

    /// Inject a random fault into the tree
    pub fn injectRandom(self: *FaultInjector, tree: *ExprTree) InjectionResult {
        // Select random fault kind
        const kind_int = self.prng.range(u8, 0, FaultKind.count);
        const kind: FaultKind = @enumFromInt(kind_int);

        return self.inject(tree, kind);
    }

    /// Inject a specific fault
    pub fn inject(self: *FaultInjector, tree: *ExprTree, kind: FaultKind) InjectionResult {
        if (tree.node_count == 0) {
            return .{ .kind = kind, .node_idx = 0, .success = false };
        }

        const node_idx = self.prng.range(u16, 0, tree.node_count);

        const success = switch (kind) {
            .int_max => self.injectIntBoundary(tree, std.math.maxInt(i32)),
            .int_min => self.injectIntBoundary(tree, std.math.minInt(i32)),
            .long_max => self.injectLongBoundary(tree, std.math.maxInt(i64)),
            .long_min => self.injectLongBoundary(tree, std.math.minInt(i64)),
            .zero_divisor => self.injectZeroDivisor(tree),
            .cost_exhaustion => true, // This is handled externally via cost_limit
            .invalid_node_idx => self.injectInvalidNodeIdx(tree, node_idx),
            .invalid_type => self.injectInvalidType(tree, node_idx),
            .invalid_opcode => self.injectInvalidOpcode(tree, node_idx),
        };

        return .{ .kind = kind, .node_idx = node_idx, .success = success };
    }

    /// Inject int boundary value into a constant
    fn injectIntBoundary(self: *FaultInjector, tree: *ExprTree, value: i32) bool {
        // Find a constant node with INT type
        for (tree.nodes[0..tree.node_count], 0..) |*node, i| {
            if (node.tag == .constant and node.result_type == TypePool.INT) {
                // Modify the value in the values array
                const val_idx = node.data;
                if (val_idx < tree.value_count) {
                    tree.values[val_idx] = .{ .int = value };
                    return true;
                }
            }
            _ = i;
        }

        // No suitable constant found - create one
        if (tree.value_count < expr_mod.max_constants and tree.node_count < expr_mod.max_constants) {
            const val_idx = tree.value_count;
            tree.values[val_idx] = .{ .int = value };
            tree.value_count += 1;

            // Find a node to replace or modify
            const target_idx = self.prng.range(u16, 0, tree.node_count);
            tree.nodes[target_idx] = .{
                .tag = .constant,
                .data = val_idx,
                .result_type = TypePool.INT,
            };
            return true;
        }

        return false;
    }

    /// Inject long boundary value into a constant
    fn injectLongBoundary(self: *FaultInjector, tree: *ExprTree, value: i64) bool {
        // Find a constant node with LONG type
        for (tree.nodes[0..tree.node_count], 0..) |*node, i| {
            if (node.tag == .constant and node.result_type == TypePool.LONG) {
                const val_idx = node.data;
                if (val_idx < tree.value_count) {
                    tree.values[val_idx] = .{ .long = value };
                    return true;
                }
            }
            _ = i;
        }

        // No suitable constant found - create one
        if (tree.value_count < expr_mod.max_constants and tree.node_count < expr_mod.max_constants) {
            const val_idx = tree.value_count;
            tree.values[val_idx] = .{ .long = value };
            tree.value_count += 1;

            const target_idx = self.prng.range(u16, 0, tree.node_count);
            tree.nodes[target_idx] = .{
                .tag = .constant,
                .data = val_idx,
                .result_type = TypePool.LONG,
            };
            return true;
        }

        return false;
    }

    /// Inject zero divisor into a division operation
    fn injectZeroDivisor(self: *FaultInjector, tree: *ExprTree) bool {
        _ = self;

        // Find a division operation
        for (tree.nodes[0..tree.node_count], 0..) |node, idx| {
            if (node.tag == .bin_op) {
                const kind = node.binOpKind() orelse continue;
                if (kind == .divide or kind == .modulo) {
                    // Division has children following it
                    // Second child (divisor) is at varying positions
                    // For simple case, we can modify a constant if present
                    if (idx + 2 < tree.node_count) {
                        const divisor_idx = idx + 2;
                        const divisor = &tree.nodes[divisor_idx];
                        if (divisor.tag == .constant) {
                            const val_idx = divisor.data;
                            if (val_idx < tree.value_count) {
                                // Set divisor to 0
                                switch (tree.values[val_idx]) {
                                    .int => tree.values[val_idx] = .{ .int = 0 },
                                    .long => tree.values[val_idx] = .{ .long = 0 },
                                    .short => tree.values[val_idx] = .{ .short = 0 },
                                    .byte => tree.values[val_idx] = .{ .byte = 0 },
                                    else => {},
                                }
                                return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    /// Inject invalid node index reference
    fn injectInvalidNodeIdx(_: *FaultInjector, tree: *ExprTree, node_idx: u16) bool {
        if (node_idx >= tree.node_count) return false;

        // Set the node's data to an out-of-bounds index
        // This depends on the node type - some use data as index
        const node = &tree.nodes[node_idx];
        switch (node.tag) {
            .constant, .constant_placeholder => {
                // data is index into values/constants array
                node.data = @intCast(@min(tree.value_count + 100, std.math.maxInt(u16)));
                return true;
            },
            .val_use => {
                // data is variable ID - set to invalid
                node.data = 255; // Out of range for typical var IDs
                return true;
            },
            else => {
                // For other nodes, corrupt the data field
                node.data = std.math.maxInt(u16);
                return true;
            },
        }
    }

    /// Inject invalid type index
    fn injectInvalidType(_: *FaultInjector, tree: *ExprTree, node_idx: u16) bool {
        if (node_idx >= tree.node_count) return false;

        // Set result_type to an invalid index
        tree.nodes[node_idx].result_type = 0xFFFF;
        return true;
    }

    /// Inject invalid/unsupported opcode
    fn injectInvalidOpcode(_: *FaultInjector, tree: *ExprTree, node_idx: u16) bool {
        if (node_idx >= tree.node_count) return false;

        // Set tag to unsupported
        tree.nodes[node_idx].tag = .unsupported;
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "injector: inject int_max" {
    var prng = PRNG.from_seed(12345);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0, .result_type = TypePool.INT };
    tree.values[0] = .{ .int = 42 };
    tree.node_count = 1;
    tree.value_count = 1;

    const result = injector.inject(&tree, .int_max);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(FaultKind.int_max, result.kind);
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), tree.values[0].int);
}

test "injector: inject int_min" {
    var prng = PRNG.from_seed(12345);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0, .result_type = TypePool.INT };
    tree.values[0] = .{ .int = 42 };
    tree.node_count = 1;
    tree.value_count = 1;

    const result = injector.inject(&tree, .int_min);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(i32, std.math.minInt(i32)), tree.values[0].int);
}

test "injector: inject invalid_opcode" {
    var prng = PRNG.from_seed(12345);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = TypePool.INT };
    tree.node_count = 1;

    const result = injector.inject(&tree, .invalid_opcode);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(ExprTag.unsupported, tree.nodes[result.node_idx].tag);
}

test "injector: inject invalid_type" {
    var prng = PRNG.from_seed(12345);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = TypePool.INT };
    tree.node_count = 1;

    const result = injector.inject(&tree, .invalid_type);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(TypeIndex, 0xFFFF), tree.nodes[result.node_idx].result_type);
}

test "injector: inject random" {
    var prng = PRNG.from_seed(67890);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .constant, .data = 0, .result_type = TypePool.INT };
    tree.values[0] = .{ .int = 100 };
    tree.node_count = 1;
    tree.value_count = 1;

    // Just verify it doesn't crash
    _ = injector.injectRandom(&tree);
}

test "injector: empty tree" {
    var prng = PRNG.from_seed(11111);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    // Empty tree

    const result = injector.inject(&tree, .int_max);

    // Should fail gracefully
    try std.testing.expect(!result.success);
}

test "injector: zero divisor injection" {
    var prng = PRNG.from_seed(22222);
    var injector = FaultInjector.init(&prng);

    var tree = ExprTree.init();
    // a / b where b = constant
    tree.nodes[0] = .{
        .tag = .bin_op,
        .data = @intFromEnum(BinOpKind.divide),
        .result_type = TypePool.INT,
    };
    tree.nodes[1] = .{ .tag = .height, .result_type = TypePool.INT }; // a
    tree.nodes[2] = .{ .tag = .constant, .data = 0, .result_type = TypePool.INT }; // b
    tree.values[0] = .{ .int = 5 }; // b = 5
    tree.node_count = 3;
    tree.value_count = 1;

    const result = injector.inject(&tree, .zero_divisor);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(i32, 0), tree.values[0].int);
}
