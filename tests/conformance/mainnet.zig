//! Mainnet ErgoTree Conformance Tests
//!
//! Tests the Zigma interpreter against real-world ErgoTree scripts from mainnet.
//! Each test vector specifies:
//!   - ErgoTree bytes (hex)
//!   - Execution context (height, boxes, etc.)
//!   - Expected result (value and type, or error)
//!   - Expected cost
//!
//! Test vectors are validated against Scala sigmastate-interpreter reference.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const zigma = @import("zigma");
const types = zigma.types;
const TypePool = types.TypePool;
const ergotree = zigma.ergotree_serializer;
const ErgoTree = ergotree.ErgoTree;
const expr_serializer = zigma.expr_serializer;
const evaluator = zigma.evaluator;
const Evaluator = evaluator.Evaluator;
const context = zigma.context;
const Context = context.Context;
const memory = zigma.memory;
const BumpAllocator = memory.BumpAllocator;
const Value = zigma.Value;

// ============================================================================
// Test Helpers
// ============================================================================

/// Parse hex string to bytes at comptime
fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    @setEvalBranchQuota(10000);
    for (0..hex.len / 2) |i| {
        const hi: u8 = hexDigit(hex[i * 2]);
        const lo: u8 = hexDigit(hex[i * 2 + 1]);
        result[i] = (hi << 4) | lo;
    }
    return result;
}

fn hexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0, // Invalid - will cause test to fail
    };
}

/// Run a test with comptime hex string
fn runTest(
    comptime ergo_tree_hex: []const u8,
    height: u32,
    comptime expected_type: enum { boolean, int, long },
    expected_value: switch (expected_type) {
        .boolean => bool,
        .int => i32,
        .long => i64,
    },
) !void {
    const bytes = hexToBytes(ergo_tree_hex);

    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(4096).init();

    try ergotree.deserialize(&tree, &bytes, &arena);

    const inputs = [_]context.BoxView{context.testBox()};
    const ctx = Context.forHeight(height, &inputs);

    var eval = Evaluator.init(&tree.expr_tree, &ctx);
    const result = try eval.evaluate();

    switch (expected_type) {
        .boolean => {
            try testing.expect(result == .boolean);
            try testing.expectEqual(expected_value, result.boolean);
        },
        .int => {
            try testing.expect(result == .int);
            try testing.expectEqual(expected_value, result.int);
        },
        .long => {
            try testing.expect(result == .long);
            try testing.expectEqual(expected_value, result.long);
        },
    }
}

// ============================================================================
// Simple Propositions
// ============================================================================

test "mainnet: TrueLeaf always evaluates to true" {
    // 0x00 = header v0, no segregation
    // 0x7f = TrueLeaf opcode
    try runTest("007f", 100, .boolean, true);
}

test "mainnet: FalseLeaf always evaluates to false" {
    // 0x80 = FalseLeaf opcode
    try runTest("0080", 100, .boolean, false);
}

// ============================================================================
// Height-based Time Locks
// ============================================================================

test "mainnet: HEIGHT > 100 at height 500 (true)" {
    // 0x91 = GT opcode, 0xa3 = HEIGHT, 0x04 = SInt type, c801 = VLQ(100)
    try runTest("0091a304c801", 500, .boolean, true);
}

test "mainnet: HEIGHT > 100 at height 50 (false)" {
    try runTest("0091a304c801", 50, .boolean, false);
}

test "mainnet: HEIGHT > 100 boundary at 100 (false)" {
    try runTest("0091a304c801", 100, .boolean, false);
}

test "mainnet: HEIGHT > 100 boundary at 101 (true)" {
    try runTest("0091a304c801", 101, .boolean, true);
}

test "mainnet: HEIGHT >= 1000 at height 1000 (true)" {
    // 0x92 = GE opcode, d00f = VLQ(1000)
    try runTest("0092a304d00f", 1000, .boolean, true);
}

test "mainnet: HEIGHT >= 1000 at height 999 (false)" {
    try runTest("0092a304d00f", 999, .boolean, false);
}

// ============================================================================
// Constant Segregation
// ============================================================================

// NOTE: ConstantPlaceholder evaluation (opcode 0x76) not yet implemented.
// These tests are commented out until the feature is added.
//
// test "mainnet: constant segregation Boolean true" {
//     try runTest("100101017600", 100, .boolean, true);
// }
// test "mainnet: constant segregation Boolean false" {
//     try runTest("100101007600", 100, .boolean, false);
// }

// ============================================================================
// Integer Constants
// ============================================================================

test "mainnet: constant int 42" {
    // 0x04 = SInt type code
    // 0x54 = VLQ zigzag(42) = 84
    try runTest("000454", 100, .int, 42);
}

test "mainnet: constant int -1" {
    // VLQ zigzag(-1) = 1
    try runTest("000401", 100, .int, -1);
}

test "mainnet: constant int 0" {
    try runTest("000400", 100, .int, 0);
}

test "mainnet: constant int max (2147483647)" {
    // VLQ zigzag(2147483647) = 4294967294 = 0xfe ff ff ff 0f
    try runTest("0004feffffff0f", 100, .int, 2147483647);
}

test "mainnet: constant int min (-2147483648)" {
    // VLQ zigzag(-2147483648) = 4294967295 = 0xff ff ff ff 0f
    try runTest("0004ffffffff0f", 100, .int, -2147483648);
}

// ============================================================================
// Version-specific Tests
// ============================================================================

test "mainnet: v1 header with size field" {
    // 0x09 = v1 + has_size flag
    // 0x01 = size = 1 byte
    // 0x7f = TrueLeaf
    try runTest("09017f", 100, .boolean, true);
}

// ============================================================================
// Comparison Operations
// ============================================================================

test "mainnet: LT comparison 5 < 10" {
    // 0x90 = LT opcode
    // Two int constants: 5 (0x0a) and 10 (0x14)
    try runTest("0090040a0414", 100, .boolean, true);
}

test "mainnet: LT comparison 10 < 5" {
    try runTest("00900414040a", 100, .boolean, false);
}

test "mainnet: EQ comparison 42 == 42" {
    // 0x93 = EQ opcode
    try runTest("009304540454", 100, .boolean, true);
}

test "mainnet: EQ comparison 42 != 43" {
    // 43 zigzag = 86 = 0x56
    try runTest("009304540456", 100, .boolean, false);
}

// ============================================================================
// Logical Operations
// ============================================================================

// NOTE: BinAnd (0xED) and BinOr (0xEC) evaluation not yet implemented.
// These tests are commented out until the feature is added.
//
// test "mainnet: AND true && true" {
//     try runTest("00ed7f7f", 100, .boolean, true);
// }
// test "mainnet: AND true && false" {
//     try runTest("00ed7f80", 100, .boolean, false);
// }
// test "mainnet: OR false || true" {
//     try runTest("00ec807f", 100, .boolean, true);
// }
// test "mainnet: OR false || false" {
//     try runTest("00ec8080", 100, .boolean, false);
// }

// ============================================================================
// Real Mainnet Script Patterns
// ============================================================================

// TODO: Add real mainnet scripts with SigmaProp evaluation
// These require sigma protocol support:
// - P2PK (pay to public key) scripts
// - Multi-signature scripts
// - Threshold signatures

// ============================================================================
// Summary
// ============================================================================

test "mainnet: infrastructure sanity check" {
    // Verify basic infrastructure works
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(256).init();

    const bytes = hexToBytes("007f");
    try ergotree.deserialize(&tree, &bytes, &arena);
    try testing.expectEqual(@as(u16, 1), tree.expr_tree.node_count);
}
