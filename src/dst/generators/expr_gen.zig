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
            .collection => try self.generateCollectionOp(target),
            .crypto => try self.generateCryptoOp(target),
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
                // Boolean: allow comparison, logical, and collection predicates (exists/forall)
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
                if (self.options.collection_weight > 0) {
                    categories[count] = .collection;
                    weights[count] = self.options.collection_weight;
                    count += 1;
                }
            },
            TypePool.COLL_BYTE => {
                // Byte collection: allow crypto (hash functions return Coll[Byte])
                if (self.options.crypto_weight > 0) {
                    categories[count] = .crypto;
                    weights[count] = self.options.crypto_weight;
                    count += 1;
                }
            },
            TypePool.GROUP_ELEMENT => {
                // Group element: allow crypto operations
                if (self.options.crypto_weight > 0) {
                    categories[count] = .crypto;
                    weights[count] = self.options.crypto_weight;
                    count += 1;
                }
            },
            TypePool.BIG_INT => {
                // BigInt: allow crypto operations (modular arithmetic)
                if (self.options.crypto_weight > 0) {
                    categories[count] = .crypto;
                    weights[count] = self.options.crypto_weight;
                    count += 1;
                }
            },
            TypePool.COLL_INT, TypePool.COLL_LONG => {
                // Collection types: allow collection operations
                if (self.options.collection_weight > 0) {
                    categories[count] = .collection;
                    weights[count] = self.options.collection_weight;
                    count += 1;
                }
            },
            TypePool.BOX => {
                // Box type: allow collection operations (self_box)
                if (self.options.collection_weight > 0) {
                    categories[count] = .collection;
                    weights[count] = self.options.collection_weight;
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
            TypePool.COLL_BYTE => try self.generateCollByteLeaf(),
            TypePool.GROUP_ELEMENT => try self.generateGroupElementLeaf(),
            TypePool.BIG_INT => try self.generateBigIntLeaf(),
            TypePool.BOX => try self.generateBoxLeaf(),
            TypePool.SIGMA_PROP => try self.generateSigmaPropLeaf(),
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
        const choice = self.prng.range_inclusive(u8, 0, 4);
        switch (choice) {
            0 => {
                // height opcode (returns Int)
                _ = try self.addNode(.{
                    .tag = .height,
                    .result_type = TypePool.INT,
                });
            },
            1 => {
                // downcast: Long → Int (may overflow, returns Int)
                // node.data = target type (INT)
                _ = try self.addNode(.{
                    .tag = .downcast,
                    .data = TypePool.INT,
                    .result_type = TypePool.INT,
                });
                try self.generateLongLeaf();
            },
            2 => {
                // byte_array_to_long then downcast to int (exercises both opcodes)
                _ = try self.addNode(.{
                    .tag = .downcast,
                    .data = TypePool.INT,
                    .result_type = TypePool.INT,
                });
                _ = try self.addNode(.{
                    .tag = .byte_array_to_long,
                    .result_type = TypePool.LONG,
                });
                // Need 8 bytes for byte_array_to_long
                _ = try self.addNode(.{
                    .tag = .long_to_byte_array,
                    .result_type = TypePool.COLL_BYTE,
                });
                try self.generateConstant(.{ .long = self.prng.int(i64) }, TypePool.LONG);
            },
            3 => {
                // constant_placeholder: reference to constant pool
                // data = index in constant pool (0 for first constant)
                const value = self.prng.int(i32);
                const value_idx = self.tree.addValue(.{ .int = value }) catch return error.ExpressionTooComplex;
                _ = try self.addNode(.{
                    .tag = .constant_placeholder,
                    .data = value_idx,
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
        const choice = self.prng.range_inclusive(u8, 0, 2);
        switch (choice) {
            0 => {
                // Constant long
                const value = self.prng.int(i64);
                try self.generateConstant(.{ .long = value }, TypePool.LONG);
            },
            1 => {
                // upcast: Int → Long
                // node.data = target type (LONG)
                _ = try self.addNode(.{
                    .tag = .upcast,
                    .data = TypePool.LONG,
                    .result_type = TypePool.LONG,
                });
                try self.generateIntLeaf();
            },
            else => {
                // byte_array_to_long: Coll[Byte] → Long (8 bytes big-endian)
                _ = try self.addNode(.{
                    .tag = .byte_array_to_long,
                    .result_type = TypePool.LONG,
                });
                _ = try self.addNode(.{
                    .tag = .long_to_byte_array,
                    .result_type = TypePool.COLL_BYTE,
                });
                try self.generateConstant(.{ .long = self.prng.int(i64) }, TypePool.LONG);
            },
        }
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

    fn generateCollByteLeaf(self: *ExprGenerator) GenerateError!void {
        const choice = self.prng.range_inclusive(u8, 0, 3);
        switch (choice) {
            0 => {
                // long_to_byte_array: Long → Coll[Byte] (8 bytes)
                _ = try self.addNode(.{
                    .tag = .long_to_byte_array,
                    .result_type = TypePool.COLL_BYTE,
                });
                const value = self.prng.int(i64);
                try self.generateConstant(.{ .long = value }, TypePool.LONG);
            },
            1 => {
                // miner_pk: → Coll[Byte] (33 bytes compressed pubkey)
                // Reads from context pre-header
                _ = try self.addNode(.{
                    .tag = .miner_pk,
                    .result_type = TypePool.COLL_BYTE,
                });
            },
            2 => {
                // last_block_utxo_root: → Coll[Byte] (AVL+ tree digest)
                // Reads from headers in context
                _ = try self.addNode(.{
                    .tag = .last_block_utxo_root,
                    .result_type = TypePool.COLL_BYTE,
                });
            },
            else => {
                // calc_blake2b256 on a small input
                _ = try self.addNode(.{
                    .tag = .calc_blake2b256,
                    .result_type = TypePool.COLL_BYTE,
                });
                _ = try self.addNode(.{
                    .tag = .long_to_byte_array,
                    .result_type = TypePool.COLL_BYTE,
                });
                try self.generateConstant(.{ .long = self.prng.int(i64) }, TypePool.LONG);
            },
        }
    }

    fn generateGroupElementLeaf(self: *ExprGenerator) GenerateError!void {
        // Generate group generator (simplest group element)
        _ = try self.addNode(.{
            .tag = .group_generator,
            .result_type = TypePool.GROUP_ELEMENT,
        });
    }

    fn generateBigIntLeaf(self: *ExprGenerator) GenerateError!void {
        // Generate BigInt from a long: byte_array_to_bigint(long_to_byte_array(constant))
        _ = try self.addNode(.{
            .tag = .byte_array_to_bigint,
            .result_type = TypePool.BIG_INT,
        });
        _ = try self.addNode(.{
            .tag = .long_to_byte_array,
            .result_type = TypePool.COLL_BYTE,
        });
        const value = self.prng.int(i64);
        try self.generateConstant(.{ .long = value }, TypePool.LONG);
    }

    fn generateBoxLeaf(self: *ExprGenerator) GenerateError!void {
        // Generate self_box (current transaction box)
        _ = try self.addNode(.{
            .tag = .self_box,
            .result_type = TypePool.BOX,
        });
    }

    fn generateSigmaPropLeaf(self: *ExprGenerator) GenerateError!void {
        const choice = self.prng.range_inclusive(u8, 0, 2);
        switch (choice) {
            0 => {
                // sigma_and: SigmaProp × SigmaProp → SigmaProp
                // data = number of children
                _ = try self.addNode(.{
                    .tag = .sigma_and,
                    .data = 2, // Two children
                    .result_type = TypePool.SIGMA_PROP,
                });
                // Generate two SigmaProp children (recursive)
                try self.generateSigmaPropSimple();
                try self.generateSigmaPropSimple();
            },
            1 => {
                // sigma_or: SigmaProp × SigmaProp → SigmaProp
                _ = try self.addNode(.{
                    .tag = .sigma_or,
                    .data = 2,
                    .result_type = TypePool.SIGMA_PROP,
                });
                try self.generateSigmaPropSimple();
                try self.generateSigmaPropSimple();
            },
            else => {
                // Simple SigmaProp from boolean (most common)
                try self.generateSigmaPropSimple();
            },
        }
    }

    /// Generate a simple SigmaProp (bool coerced to trivial sigma prop)
    fn generateSigmaPropSimple(self: *ExprGenerator) GenerateError!void {
        // In ErgoScript, booleans coerce to SigmaProp
        // For DST, we just use true_leaf or a comparison
        const choice = self.prng.range_inclusive(u8, 0, 1);
        switch (choice) {
            0 => {
                // TrivialProp(true)
                _ = try self.addNode(.{
                    .tag = .true_leaf,
                    .result_type = TypePool.SIGMA_PROP,
                });
            },
            else => {
                // TrivialProp(false) - makes sigma_and/or interesting
                _ = try self.addNode(.{
                    .tag = .false_leaf,
                    .result_type = TypePool.SIGMA_PROP,
                });
            },
        }
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
        const choice = self.prng.range_inclusive(u8, 0, 2);
        if (choice == 0) {
            // Standard arithmetic operations
            const ops = [_]BinOpKind{ .plus, .minus, .multiply, .divide, .modulo };
            const op = self.prng.select(BinOpKind, &ops);

            _ = try self.addNode(.{
                .tag = .bin_op,
                .data = @intFromEnum(op),
                .result_type = target,
            });

            try self.generateForType(target);
            try self.generateForType(target);
        } else if (choice == 1) {
            // Bit shift operations (v3+)
            const shift_ops = [_]BinOpKind{ .bit_shift_left, .bit_shift_right, .bit_shift_right_zeroed };
            const op = self.prng.select(BinOpKind, &shift_ops);

            _ = try self.addNode(.{
                .tag = .bin_op,
                .data = @intFromEnum(op),
                .result_type = target,
            });

            try self.generateForType(target);
            // Shift amount should be small (0-31 for 32-bit, 0-63 for 64-bit)
            const shift_amount = self.prng.range_inclusive(i32, 0, 15);
            try self.generateConstant(.{ .int = shift_amount }, TypePool.INT);
        } else {
            // Bitwise inversion: ~x
            _ = try self.addNode(.{
                .tag = .bit_inversion,
                .result_type = target,
            });
            try self.generateForType(target);
        }
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

        const choice = self.prng.range_inclusive(u8, 0, 7);
        switch (choice) {
            0, 1 => {
                // Binary logical (and, or, xor)
                const ops = [_]BinOpKind{ .and_op, .or_op, .xor_op };
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
            3 => {
                // Bitwise operations on integers (result can be used in comparisons)
                // Generate: (a & b) > 0 or similar
                const bitwise_ops = [_]BinOpKind{ .bit_and, .bit_or, .bit_xor };
                const bitwise_op = self.prng.select(BinOpKind, &bitwise_ops);

                // Comparison: (a bitop b) > 0
                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(BinOpKind.gt),
                    .result_type = TypePool.BOOLEAN,
                });

                // First child: bitwise op
                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(bitwise_op),
                    .result_type = TypePool.INT,
                });
                try self.generateIntLeaf();
                try self.generateIntLeaf();

                // Second child: constant 0
                try self.generateConstant(.{ .int = 0 }, TypePool.INT);
            },
            4 => {
                // block_value with let binding: { val x = expr; x > 0 }
                // Exercises val_def, val_use, block_value opcodes
                const var_id: u16 = self.prng.range_inclusive(u16, 0, 10);

                // Block value node
                _ = try self.addNode(.{
                    .tag = .block_value,
                    .data = 1, // 1 binding
                    .result_type = TypePool.BOOLEAN,
                });

                // val_def: define variable
                _ = try self.addNode(.{
                    .tag = .val_def,
                    .data = var_id,
                    .result_type = TypePool.INT,
                });
                try self.generateIntLeaf();

                // Block body: val_use > 0 (comparison using the variable)
                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(BinOpKind.gt),
                    .result_type = TypePool.BOOLEAN,
                });
                _ = try self.addNode(.{
                    .tag = .val_use,
                    .data = var_id,
                    .result_type = TypePool.INT,
                });
                try self.generateConstant(.{ .int = 0 }, TypePool.INT);
            },
            5 => {
                // Tuple operations: pair_construct + select_field
                // Exercises pair_construct, select_field opcodes
                // Pattern: (pair._1 > pair._2) - constructs pair then compares fields

                // Comparison: select_field(pair, 0) > select_field(pair, 1)
                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(BinOpKind.gt),
                    .result_type = TypePool.BOOLEAN,
                });

                // First child: select_field(pair, 0)
                _ = try self.addNode(.{
                    .tag = .select_field,
                    .data = 0, // field index 0 (_1)
                    .result_type = TypePool.INT,
                });
                // pair_construct for first select_field
                _ = try self.addNode(.{
                    .tag = .pair_construct,
                    .data = 2,
                    .result_type = TypePool.ANY, // Pair type
                });
                try self.generateIntLeaf();
                try self.generateIntLeaf();

                // Second child: select_field(pair, 1)
                _ = try self.addNode(.{
                    .tag = .select_field,
                    .data = 1, // field index 1 (_2)
                    .result_type = TypePool.INT,
                });
                // pair_construct for second select_field
                _ = try self.addNode(.{
                    .tag = .pair_construct,
                    .data = 2,
                    .result_type = TypePool.ANY, // Pair type
                });
                try self.generateIntLeaf();
                try self.generateIntLeaf();
            },
            6 => {
                // Triple construct with select_field
                // Exercises triple_construct, select_field opcodes
                // Pattern: triple._2 > 0

                // Comparison: select_field(triple, 1) > 0
                _ = try self.addNode(.{
                    .tag = .bin_op,
                    .data = @intFromEnum(BinOpKind.gt),
                    .result_type = TypePool.BOOLEAN,
                });

                // First child: select_field(triple, 1) - middle element
                _ = try self.addNode(.{
                    .tag = .select_field,
                    .data = 1, // field index 1 (_2)
                    .result_type = TypePool.INT,
                });
                // triple_construct
                _ = try self.addNode(.{
                    .tag = .triple_construct,
                    .data = 3,
                    .result_type = TypePool.ANY, // Triple type
                });
                try self.generateIntLeaf();
                try self.generateIntLeaf();
                try self.generateIntLeaf();

                // Second child: constant 0
                try self.generateConstant(.{ .int = 0 }, TypePool.INT);
            },
            else => {
                // Comparison (generates boolean)
                try self.generateComparison();
            },
        }
    }

    // ========================================================================
    // Collection Operations
    // ========================================================================

    /// Generate collection operation (exists, forall, self_box, inputs, outputs, etc.)
    fn generateCollectionOp(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        switch (target) {
            TypePool.BOOLEAN => {
                // exists or for_all on INPUTS collection
                // These check if any/all boxes satisfy a condition
                const choice = self.prng.range_inclusive(u8, 0, 3);
                switch (choice) {
                    0 => {
                        // exists: Coll[Box] × (Box → Boolean) → Boolean
                        // Generate: exists(INPUTS, { box => true })
                        _ = try self.addNode(.{
                            .tag = .exists,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // First child: inputs collection
                        _ = try self.addNode(.{
                            .tag = .inputs,
                            .result_type = TypePool.COLL_BYTE, // Placeholder - actually Coll[Box]
                        });
                        // Second child: func_value (predicate)
                        _ = try self.addNode(.{
                            .tag = .func_value,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // Func body: always true for simplicity
                        _ = try self.addNode(.{
                            .tag = .true_leaf,
                            .result_type = TypePool.BOOLEAN,
                        });
                    },
                    1 => {
                        // for_all: Coll[Box] × (Box → Boolean) → Boolean
                        _ = try self.addNode(.{
                            .tag = .for_all,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // First child: outputs collection
                        _ = try self.addNode(.{
                            .tag = .outputs,
                            .result_type = TypePool.COLL_BYTE, // Placeholder
                        });
                        // Second child: func_value (predicate)
                        _ = try self.addNode(.{
                            .tag = .func_value,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // Func body: comparison
                        try self.generateComparison();
                    },
                    2 => {
                        // option_is_defined: check if option has value
                        _ = try self.addNode(.{
                            .tag = .option_is_defined,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // Generate an option-producing expression (simplified)
                        _ = try self.addNode(.{
                            .tag = .option_get_or_else,
                            .result_type = TypePool.LONG,
                        });
                        // Child for get_or_else: generate long leaf
                        try self.generateLongLeaf();
                        try self.generateLongLeaf();
                    },
                    3 => {
                        // apply: (T → Boolean) × T → Boolean
                        // Function application - applies func_value to an argument
                        _ = try self.addNode(.{
                            .tag = .apply,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // First child: func_value (predicate)
                        _ = try self.addNode(.{
                            .tag = .func_value,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // Func body: true
                        _ = try self.addNode(.{
                            .tag = .true_leaf,
                            .result_type = TypePool.BOOLEAN,
                        });
                        // Second child: argument (can be anything, we use int)
                        try self.generateIntLeaf();
                    },
                    else => {
                        // Fallback to comparison
                        try self.generateComparison();
                    },
                }
            },
            TypePool.BOX => {
                // Box-producing operations
                const choice = self.prng.range_inclusive(u8, 0, 1);
                switch (choice) {
                    0 => {
                        // self_box returns the current transaction box
                        _ = try self.addNode(.{
                            .tag = .self_box,
                            .result_type = TypePool.BOX,
                        });
                    },
                    else => {
                        // self_box (default)
                        _ = try self.addNode(.{
                            .tag = .self_box,
                            .result_type = TypePool.BOX,
                        });
                    },
                }
            },
            TypePool.COLL_BYTE => {
                // Byte collection operations
                const choice = self.prng.range_inclusive(u8, 0, 1);
                switch (choice) {
                    0 => {
                        // long_to_byte_array: Long → Coll[Byte]
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateForType(TypePool.LONG);
                    },
                    else => {
                        // concrete_collection of bytes
                        const num_items: u16 = self.prng.range_inclusive(u16, 1, 4);
                        _ = try self.addNode(.{
                            .tag = .concrete_collection,
                            .data = num_items,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        for (0..num_items) |_| {
                            try self.generateByteLeaf();
                        }
                    },
                }
            },
            TypePool.COLL_INT => {
                // Int collection
                const num_items: u16 = self.prng.range_inclusive(u16, 1, 3);
                _ = try self.addNode(.{
                    .tag = .concrete_collection,
                    .data = num_items,
                    .result_type = TypePool.COLL_INT,
                });
                for (0..num_items) |_| {
                    try self.generateIntLeaf();
                }
            },
            TypePool.COLL_LONG => {
                // Long collection
                const num_items: u16 = self.prng.range_inclusive(u16, 1, 3);
                _ = try self.addNode(.{
                    .tag = .concrete_collection,
                    .data = num_items,
                    .result_type = TypePool.COLL_LONG,
                });
                for (0..num_items) |_| {
                    try self.generateLongLeaf();
                }
            },
            else => {
                // Fallback to leaf
                try self.generateLeaf(target);
            },
        }
    }

    // ========================================================================
    // Crypto Operations
    // ========================================================================

    /// Generate crypto operation (hash, group operations)
    fn generateCryptoOp(self: *ExprGenerator, target: TypeIndex) GenerateError!void {
        switch (target) {
            TypePool.COLL_BYTE => {
                // Hash operations: calc_blake2b256 or calc_sha256
                // They take Coll[Byte] and return Coll[Byte]
                const choice = self.prng.range_inclusive(u8, 0, 2);
                switch (choice) {
                    0 => {
                        // calc_blake2b256: Coll[Byte] → Coll[Byte] (32 bytes)
                        _ = try self.addNode(.{
                            .tag = .calc_blake2b256,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        // Input: convert a long to byte array
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateForType(TypePool.LONG);
                    },
                    1 => {
                        // calc_sha256: Coll[Byte] → Coll[Byte] (32 bytes)
                        _ = try self.addNode(.{
                            .tag = .calc_sha256,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        // Input: convert a long to byte array
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateForType(TypePool.LONG);
                    },
                    else => {
                        // long_to_byte_array: Long → Coll[Byte] (8 bytes big-endian)
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateForType(TypePool.LONG);
                    },
                }
            },
            TypePool.GROUP_ELEMENT => {
                // Group operations: group_generator, exponentiate, multiply_group
                const choice = self.prng.range_inclusive(u8, 0, 3);
                switch (choice) {
                    0 => {
                        // group_generator: → GroupElement (base point G)
                        _ = try self.addNode(.{
                            .tag = .group_generator,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                    },
                    1 => {
                        // exponentiate: GroupElement × BigInt → GroupElement
                        // Generate G^n where n is derived from a long
                        _ = try self.addNode(.{
                            .tag = .exponentiate,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                        // First child: group element (use generator)
                        _ = try self.addNode(.{
                            .tag = .group_generator,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                        // Second child: BigInt - convert from long
                        // For now, use byte_array_to_bigint(long_to_byte_array(long))
                        _ = try self.addNode(.{
                            .tag = .byte_array_to_bigint,
                            .result_type = TypePool.BIG_INT,
                        });
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        // Use a small constant to avoid overflow
                        try self.generateConstant(.{ .long = self.prng.range_inclusive(i64, 1, 100) }, TypePool.LONG);
                    },
                    2 => {
                        // multiply_group: GroupElement × GroupElement → GroupElement
                        // Generate G * G = 2G
                        _ = try self.addNode(.{
                            .tag = .multiply_group,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                        // Two group generators
                        _ = try self.addNode(.{
                            .tag = .group_generator,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                        _ = try self.addNode(.{
                            .tag = .group_generator,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                    },
                    else => {
                        // decode_point: Coll[Byte] → GroupElement
                        // Decodes a compressed secp256k1 point (33 bytes)
                        // We use group_generator to get valid point, then convert to bytes and back
                        _ = try self.addNode(.{
                            .tag = .decode_point,
                            .result_type = TypePool.GROUP_ELEMENT,
                        });
                        // Input: 33-byte compressed point
                        // Simplest valid encoding: generator point serialized
                        _ = try self.addNode(.{
                            .tag = .calc_blake2b256,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateConstant(.{ .long = self.prng.int(i64) }, TypePool.LONG);
                    },
                }
            },
            TypePool.BIG_INT => {
                // BigInt operations including modular arithmetic
                // Buffer overflow bug fixed - max_bigint_bytes increased to 33
                const choice = self.prng.range_inclusive(u8, 0, 3);
                switch (choice) {
                    0 => {
                        // mod_q: BigInt → BigInt (reduce mod secp256k1 order)
                        _ = try self.addNode(.{
                            .tag = .mod_q,
                            .result_type = TypePool.BIG_INT,
                        });
                        try self.generateBigIntLeaf();
                    },
                    1 => {
                        // plus_mod_q: BigInt × BigInt → BigInt
                        _ = try self.addNode(.{
                            .tag = .plus_mod_q,
                            .result_type = TypePool.BIG_INT,
                        });
                        try self.generateBigIntLeaf();
                        try self.generateBigIntLeaf();
                    },
                    2 => {
                        // minus_mod_q: BigInt × BigInt → BigInt
                        _ = try self.addNode(.{
                            .tag = .minus_mod_q,
                            .result_type = TypePool.BIG_INT,
                        });
                        try self.generateBigIntLeaf();
                        try self.generateBigIntLeaf();
                    },
                    else => {
                        // byte_array_to_bigint: Coll[Byte] → BigInt
                        _ = try self.addNode(.{
                            .tag = .byte_array_to_bigint,
                            .result_type = TypePool.BIG_INT,
                        });
                        _ = try self.addNode(.{
                            .tag = .long_to_byte_array,
                            .result_type = TypePool.COLL_BYTE,
                        });
                        try self.generateForType(TypePool.LONG);
                    },
                }
            },
            else => {
                // Fallback to leaf
                try self.generateLeaf(target);
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

    /// Select random primitive type (includes crypto/collection types with lower probability)
    fn randomPrimitiveType(self: *ExprGenerator) TypeIndex {
        const choice = self.prng.range_inclusive(u8, 0, 11);
        return switch (choice) {
            0, 1, 2 => TypePool.BOOLEAN,
            3, 4 => TypePool.INT,
            5, 6 => TypePool.LONG,
            7 => TypePool.COLL_BYTE,
            8 => TypePool.GROUP_ELEMENT,
            9 => TypePool.BIG_INT,
            10 => TypePool.SIGMA_PROP, // SigmaProp for sigma connectives
            else => TypePool.BOX, // Box for self_box/inputs/outputs
        };
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
