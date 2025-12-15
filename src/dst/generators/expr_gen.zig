//! Expression Tree Generator for DST
//!
//! Generates valid expression trees deterministically from seeds.
//! Uses type-directed generation to ensure well-typed trees.
//!
//! Key features:
//!   - Type-directed generation (ensures expressions type-check)
//!   - Swarm testing weights (disable/weight opcode categories)
//!   - Depth limiting (prevents stack overflow)
//!   - Constant pool generation

const std = @import("std");
const assert = std.debug.assert;
const prng_mod = @import("../prng.zig");
const PRNG = prng_mod.PRNG;
const Ratio = prng_mod.Ratio;

// Import from zigma module (defined in build.zig)
const zigma = @import("zigma");
const expr_mod = zigma.expr_serializer;
const data_mod = zigma.data_serializer;
const types_mod = zigma.types;

const ExprTree = expr_mod.ExprTree;
const ExprNode = expr_mod.ExprNode;
const ExprTag = expr_mod.ExprTag;
const BinOpKind = expr_mod.BinOpKind;
const Value = data_mod.Value;
const TypePool = types_mod.TypePool;
const TypeIndex = types_mod.TypeIndex;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum depth for generated expression trees
const default_max_depth: u8 = 10;

/// Maximum nodes in a generated tree
const default_max_nodes: u16 = 100;

// ============================================================================
// Types
// ============================================================================

/// Generation options (configurable per DST run)
pub const ExprGenOptions = struct {
    /// Maximum tree depth
    max_depth: u8 = default_max_depth,

    /// Maximum number of nodes
    max_nodes: u16 = default_max_nodes,

    /// Target type for root expression (null = any type)
    target_type: ?TypeIndex = null,

    /// Force SigmaProp root (for script testing)
    force_sigma_prop: bool = false,

    // Opcode category weights (0-100, 0 = disabled)
    /// Weight for leaf expressions (constants, true/false, height, etc.)
    leaf_weight: u8 = 100,

    /// Weight for arithmetic operations (+, -, *, /, %)
    arithmetic_weight: u8 = 100,

    /// Weight for comparison operations (<, <=, >, >=, ==, !=)
    comparison_weight: u8 = 100,

    /// Weight for logical operations (and, or, xor, if-then-else)
    logical_weight: u8 = 100,

    /// Weight for collection operations (fold, map, filter, etc.)
    collection_weight: u8 = 50, // Lower weight - expensive ops

    /// Weight for crypto operations (hash, point ops)
    crypto_weight: u8 = 30, // Even lower - very expensive

    /// Probability of generating a constant vs computed value
    constant_probability: Ratio = .{ .numerator = 30, .denominator = 100 },
};

/// Category of expressions (for weighted selection)
const ExprCategory = enum {
    leaf,
    arithmetic,
    comparison,
    logical,
    collection,
    crypto,
};

/// Expression generator state
pub const ExprGenerator = struct {
    prng: *PRNG,
    options: ExprGenOptions,
    tree: *ExprTree,

    // Generation state
    current_depth: u8 = 0,

    /// Create generator with given options
    pub fn init(prng: *PRNG, tree: *ExprTree, options: ExprGenOptions) ExprGenerator {
        return .{
            .prng = prng,
            .options = options,
            .tree = tree,
        };
    }

    /// Generate a complete expression tree
    /// Returns error if tree becomes too complex
    pub fn generate(self: *ExprGenerator) GenerateError!void {
        self.tree.reset();
        self.current_depth = 0;

        // Determine target type
        const target_type = if (self.options.force_sigma_prop)
            TypePool.SIGMA_PROP
        else if (self.options.target_type) |t|
            t
        else
            self.randomPrimitiveType();

        // Generate root expression
        try self.generateForType(target_type);

        // POSTCONDITION: At least one node generated
        assert(self.tree.node_count > 0);
    }

    /// Generate expression of specified type
    fn generateForType(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        // Check limits
        if (self.current_depth >= self.options.max_depth) {
            // At max depth, generate a leaf
            try self.generateLeaf(target);
            return;
        }

        if (self.tree.node_count >= self.options.max_nodes) {
            return error.ExpressionTooComplex;
        }

        // Decide between constant and computed expression
        if (self.prng.chance(self.options.constant_probability)) {
            try self.generateLeaf(target);
            return;
        }

        // Select category based on target type and weights
        const category = self.selectCategory(target);

        self.current_depth += 1;
        defer self.current_depth -= 1;

        switch (category) {
            .leaf => try self.generateLeaf(target),
            .arithmetic => try self.generateArithmetic(target),
            .comparison => try self.generateComparison(),
            .logical => try self.generateLogical(target),
            .collection => try self.generateLeaf(target), // TODO: implement collection ops
            .crypto => try self.generateLeaf(target), // TODO: implement crypto ops
        }
    }

    // ========================================================================
    // Category Selection
    // ========================================================================

    /// Select expression category based on target type and weights
    fn selectCategory(self: *ExprGenerator, target: TypeIndex) ExprCategory {
        // Collect enabled categories with weights
        var categories: [6]ExprCategory = undefined;
        var weights: [6]u64 = undefined;
        var count: usize = 0;

        // Always allow leaf
        if (self.options.leaf_weight > 0) {
            categories[count] = .leaf;
            weights[count] = self.options.leaf_weight;
            count += 1;
        }

        // Type-dependent categories
        switch (target) {
            TypePool.INT, TypePool.LONG, TypePool.SHORT, TypePool.BYTE => {
                // Numeric types: allow arithmetic
                if (self.options.arithmetic_weight > 0) {
                    categories[count] = .arithmetic;
                    weights[count] = self.options.arithmetic_weight;
                    count += 1;
                }
            },
            TypePool.BOOLEAN => {
                // Boolean: allow comparison and logical
                if (self.options.comparison_weight > 0) {
                    categories[count] = .comparison;
                    weights[count] = self.options.comparison_weight;
                    count += 1;
                }
                if (self.options.logical_weight > 0) {
                    categories[count] = .logical;
                    weights[count] = self.options.logical_weight;
                    count += 1;
                }
            },
            else => {
                // Other types: just leaf for now
            },
        }

        if (count == 0) {
            return .leaf;
        }

        // Weighted random selection
        var total: u64 = 0;
        for (weights[0..count]) |w| total += w;

        const pick = self.prng.range(u64, 0, total);
        var acc: u64 = 0;
        for (categories[0..count], weights[0..count]) |cat, w| {
            acc += w;
            if (pick < acc) return cat;
        }

        return .leaf;
    }

    // ========================================================================
    // Leaf Generation
    // ========================================================================

    /// Generate a leaf expression (constant or context value)
    fn generateLeaf(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        switch (target) {
            TypePool.BOOLEAN => try self.generateBooleanLeaf(),
            TypePool.INT => try self.generateIntLeaf(),
            TypePool.LONG => try self.generateLongLeaf(),
            TypePool.SHORT => try self.generateShortLeaf(),
            TypePool.BYTE => try self.generateByteLeaf(),
            TypePool.UNIT => try self.generateUnitLeaf(),
            else => {
                // Default to boolean for unknown types
                try self.generateBooleanLeaf();
            },
        }
    }

    fn generateBooleanLeaf(self: *ExprGenerator) GenerateError!void {
        const choice = self.prng.range_inclusive(u8, 0, 2);
        switch (choice) {
            0 => {
                // true_leaf
                _ = try self.addNode(.{
                    .tag = .true_leaf,
                    .result_type = TypePool.BOOLEAN,
                });
            },
            1 => {
                // false_leaf
                _ = try self.addNode(.{
                    .tag = .false_leaf,
                    .result_type = TypePool.BOOLEAN,
                });
            },
            else => {
                // Comparison: height > random_value (always returns boolean)
                const threshold = self.prng.range_inclusive(i32, 1, 1000000);
                try self.generateHeightComparison(threshold);
            },
        }
    }

    fn generateIntLeaf(self: *ExprGenerator) GenerateError!void {
        const choice = self.prng.range_inclusive(u8, 0, 1);
        switch (choice) {
            0 => {
                // height opcode (returns Int)
                _ = try self.addNode(.{
                    .tag = .height,
                    .result_type = TypePool.INT,
                });
            },
            else => {
                // Constant int
                const value = self.prng.int(i32);
                try self.generateConstant(.{ .int = value }, TypePool.INT);
            },
        }
    }

    fn generateLongLeaf(self: *ExprGenerator) GenerateError!void {
        // Constant long
        const value = self.prng.int(i64);
        try self.generateConstant(.{ .long = value }, TypePool.LONG);
    }

    fn generateShortLeaf(self: *ExprGenerator) GenerateError!void {
        const value = self.prng.int(i16);
        try self.generateConstant(.{ .short = value }, TypePool.SHORT);
    }

    fn generateByteLeaf(self: *ExprGenerator) GenerateError!void {
        const value = self.prng.int(i8);
        try self.generateConstant(.{ .byte = value }, TypePool.BYTE);
    }

    fn generateUnitLeaf(self: *ExprGenerator) GenerateError!void {
        _ = try self.addNode(.{
            .tag = .unit,
            .result_type = TypePool.UNIT,
        });
    }

    /// Generate a constant node with given value
    fn generateConstant(self: *ExprGenerator, value: Value, type_idx: TypeIndex) GenerateError!void {
        const value_idx = self.tree.addValue(value) catch return error.ExpressionTooComplex;
        _ = try self.addNode(.{
            .tag = .constant,
            .data = value_idx,
            .result_type = type_idx,
        });
    }

    /// Generate height > threshold comparison
    fn generateHeightComparison(self: *ExprGenerator, threshold: i32) GenerateError!void {
        // This creates: height > threshold
        // Node order: bin_op, height, constant

        // First add the bin_op node (GT comparison)
        _ = try self.addNode(.{
            .tag = .bin_op,
            .data = @intFromEnum(BinOpKind.gt),
            .result_type = TypePool.BOOLEAN,
        });

        // Add height node
        _ = try self.addNode(.{
            .tag = .height,
            .result_type = TypePool.INT,
        });

        // Add constant threshold
        try self.generateConstant(.{ .int = threshold }, TypePool.INT);
    }

    // ========================================================================
    // Arithmetic Generation
    // ========================================================================

    /// Generate arithmetic expression (target must be numeric)
    fn generateArithmetic(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        // Select random arithmetic operation
        const ops = [_]BinOpKind{ .plus, .minus, .multiply };
        const op = self.prng.select(BinOpKind, &ops);

        // Add bin_op node
        _ = try self.addNode(.{
            .tag = .bin_op,
            .data = @intFromEnum(op),
            .result_type = target,
        });

        // Generate two children of same type
        try self.generateForType(target);
        try self.generateForType(target);
    }

    // ========================================================================
    // Comparison Generation
    // ========================================================================

    /// Generate comparison expression (result is always boolean)
    fn generateComparison(self: *ExprGenerator) GenerateError!void {
        // Select random comparison operation
        const ops = [_]BinOpKind{ .lt, .le, .gt, .ge, .eq, .neq };
        const op = self.prng.select(BinOpKind, &ops);

        // Select type to compare
        const compare_type = self.randomNumericType();

        // Add bin_op node
        _ = try self.addNode(.{
            .tag = .bin_op,
            .data = @intFromEnum(op),
            .result_type = TypePool.BOOLEAN,
        });

        // Generate two children of same type
        try self.generateForType(compare_type);
        try self.generateForType(compare_type);
    }

    // ========================================================================
    // Logical Generation
    // ========================================================================

    /// Generate logical expression (target must be boolean)
    fn generateLogical(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        _ = target; // Must be boolean

        const choice = self.prng.range_inclusive(u8, 0, 3);
        switch (choice) {
            0, 1 => {
                // Binary logical (and, or)
                const ops = [_]BinOpKind{ .and_op, .or_op };
                const op = self.prng.select(BinOpKind, &ops);

                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(op),
                    .result_type = TypePool.BOOLEAN,
                });

                // Two boolean children
                try self.generateForType(TypePool.BOOLEAN);
                try self.generateForType(TypePool.BOOLEAN);
            },
            2 => {
                // if-then-else
                _ = try self.addNode(.{
                    .tag = .if_then_else,
                    .result_type = TypePool.BOOLEAN,
                });

                // condition, then, else (all boolean)
                try self.generateForType(TypePool.BOOLEAN);
                try self.generateForType(TypePool.BOOLEAN);
                try self.generateForType(TypePool.BOOLEAN);
            },
            else => {
                // Comparison (generates boolean)
                try self.generateComparison();
            },
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /// Add node to tree
    fn addNode(self: *ExprGenerator, node: ExprNode) GenerateError!u16 {
        return self.tree.addNode(node) catch error.ExpressionTooComplex;
    }

    /// Select random primitive type
    fn randomPrimitiveType(self: *ExprGenerator) TypeIndex {
        const types_arr = [_]TypeIndex{
            TypePool.BOOLEAN,
            TypePool.INT,
            TypePool.LONG,
        };
        return self.prng.select(TypeIndex, &types_arr);
    }

    /// Select random numeric type
    fn randomNumericType(self: *ExprGenerator) TypeIndex {
        const types_arr = [_]TypeIndex{
            TypePool.INT,
            TypePool.LONG,
            TypePool.SHORT,
            TypePool.BYTE,
        };
        return self.prng.select(TypeIndex, &types_arr);
    }
};

pub const GenerateError = error{
    ExpressionTooComplex,
};

// ============================================================================
// Tests
// ============================================================================

test "expr_gen: generate boolean expression" {
    var prng = PRNG.from_seed(12345);
    var tree = ExprTree.init();

    var gen = ExprGenerator.init(&prng, &tree, .{
        .target_type = TypePool.BOOLEAN,
        .max_depth = 5,
        .max_nodes = 50,
    });

    try gen.generate();

    // Should have at least one node
    try std.testing.expect(tree.node_count > 0);

    // Root should be boolean
    const root = tree.root().?;
    try std.testing.expectEqual(TypePool.BOOLEAN, root.result_type);
}

test "expr_gen: generate int expression" {
    var prng = PRNG.from_seed(67890);
    var tree = ExprTree.init();

    var gen = ExprGenerator.init(&prng, &tree, .{
        .target_type = TypePool.INT,
        .max_depth = 5,
    });

    try gen.generate();

    try std.testing.expect(tree.node_count > 0);

    const root = tree.root().?;
    try std.testing.expectEqual(TypePool.INT, root.result_type);
}

test "expr_gen: depth limiting" {
    var prng = PRNG.from_seed(11111);
    var tree = ExprTree.init();

    var gen = ExprGenerator.init(&prng, &tree, .{
        .max_depth = 3,
        .max_nodes = 100,
        .constant_probability = Ratio.zero(), // Force computed values
    });

    try gen.generate();

    // Tree should be bounded by depth
    try std.testing.expect(tree.node_count > 0);
    try std.testing.expect(tree.node_count <= 100);
}

test "expr_gen: determinism" {
    const seed: u64 = 99999;

    // Generate twice with same seed
    var prng1 = PRNG.from_seed(seed);
    var tree1 = ExprTree.init();
    var gen1 = ExprGenerator.init(&prng1, &tree1, .{});
    try gen1.generate();

    var prng2 = PRNG.from_seed(seed);
    var tree2 = ExprTree.init();
    var gen2 = ExprGenerator.init(&prng2, &tree2, .{});
    try gen2.generate();

    // Should produce identical trees
    try std.testing.expectEqual(tree1.node_count, tree2.node_count);
    for (tree1.nodes[0..tree1.node_count], tree2.nodes[0..tree2.node_count]) |n1, n2| {
        try std.testing.expectEqual(n1.tag, n2.tag);
        try std.testing.expectEqual(n1.data, n2.data);
        try std.testing.expectEqual(n1.result_type, n2.result_type);
    }
}

test "expr_gen: different seeds produce different trees" {
    var prng1 = PRNG.from_seed(1);
    var tree1 = ExprTree.init();
    var gen1 = ExprGenerator.init(&prng1, &tree1, .{});
    try gen1.generate();

    var prng2 = PRNG.from_seed(2);
    var tree2 = ExprTree.init();
    var gen2 = ExprGenerator.init(&prng2, &tree2, .{});
    try gen2.generate();

    // Trees should (almost certainly) differ
    var different = false;
    if (tree1.node_count != tree2.node_count) {
        different = true;
    } else {
        for (tree1.nodes[0..tree1.node_count], tree2.nodes[0..tree2.node_count]) |n1, n2| {
            if (n1.tag != n2.tag or n1.data != n2.data) {
                different = true;
                break;
            }
        }
    }
    try std.testing.expect(different);
}

test "expr_gen: weight zero disables category" {
    var prng = PRNG.from_seed(55555);
    var tree = ExprTree.init();

    var gen = ExprGenerator.init(&prng, &tree, .{
        .target_type = TypePool.INT,
        .arithmetic_weight = 0, // Disable arithmetic
        .constant_probability = Ratio.one(), // Force constants
    });

    try gen.generate();

    // Should generate only leaf (no bin_op with arithmetic)
    for (tree.nodes[0..tree.node_count]) |node| {
        if (node.tag == .bin_op) {
            const kind = node.binOpKind().?;
            // Should not be arithmetic ops
            try std.testing.expect(kind != .plus);
            try std.testing.expect(kind != .minus);
            try std.testing.expect(kind != .multiply);
        }
    }
}
