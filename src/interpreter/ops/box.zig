//! Box Operations for ErgoTree Interpreter
//!
//! Implements box property extraction operations:
//! - extractAmount: Get box value in nanoERGs
//! - extractId: Get box ID (32 bytes)
//! - extractScriptBytes: Get proposition bytes
//! - extractRegister: Get register value (R4-R9)
//! - extractCreationInfo: Get creation height and tx ID
//!
//! Reference: sigmastate/src/main/scala/sigmastate/utxo/BoxOps.scala

const std = @import("std");
const assert = std.debug.assert;
const context = @import("../context.zig");

const BoxView = context.BoxView;
const Register = context.Register;
const Token = context.Token;

// ============================================================================
// Box Extraction Operations
// ============================================================================

/// Extract box value (nanoERGs)
/// OpCode: ExtractAmount (0xC5)
pub fn extractAmount(box: *const BoxView) i64 {
    assert(box.value >= 0); // Box values are always non-negative
    return box.value;
}

/// Extract box ID (32 bytes Blake2b hash)
/// OpCode: ExtractId (0xC9)
pub fn extractId(box: *const BoxView) [32]u8 {
    return box.id;
}

/// Extract proposition (script) bytes
/// OpCode: ExtractScriptBytes (0xC6)
pub fn extractScriptBytes(box: *const BoxView) []const u8 {
    assert(box.proposition_bytes.len > 0);
    return box.proposition_bytes;
}

/// Extract creation height
/// OpCode: ExtractCreationInfo (part of)
pub fn extractCreationHeight(box: *const BoxView) u32 {
    return box.creation_height;
}

/// Extract transaction ID that created this box
pub fn extractTxId(box: *const BoxView) [32]u8 {
    return box.tx_id;
}

/// Extract output index in creating transaction
pub fn extractIndex(box: *const BoxView) u16 {
    return box.index;
}

/// Extract register value (R4-R9)
/// OpCode: ExtractRegisterAs (0xC7)
/// Returns null if register is not defined
pub fn extractRegister(box: *const BoxView, reg: Register) ?[]const u8 {
    assert(@intFromEnum(reg) <= 9);
    return box.getRegister(reg);
}

/// Check if register is defined
pub fn hasRegister(box: *const BoxView, reg: Register) bool {
    return box.hasRegister(reg);
}

/// Extract tokens (token ID + amount pairs)
pub fn extractTokens(box: *const BoxView) []const Token {
    return box.tokens;
}

/// Get number of tokens in box
pub fn tokenCount(box: *const BoxView) usize {
    return box.tokens.len;
}

/// Get specific token by index
pub fn getToken(box: *const BoxView, index: usize) ?Token {
    if (index >= box.tokens.len) return null;
    return box.tokens[index];
}

// ============================================================================
// Creation Info (compound extraction)
// ============================================================================

/// Creation info: (height, tx_id)
pub const CreationInfo = struct {
    height: u32,
    tx_id: [32]u8,
};

/// Extract creation info as compound value
/// OpCode: ExtractCreationInfo (0xC8)
pub fn extractCreationInfo(box: *const BoxView) CreationInfo {
    return .{
        .height = box.creation_height,
        .tx_id = box.tx_id,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "box: extractAmount" {
    var box = context.testBox();
    box.value = 1_000_000_000; // 1 ERG

    try std.testing.expectEqual(@as(i64, 1_000_000_000), extractAmount(&box));
}

test "box: extractId" {
    var box = context.testBox();
    box.id[0] = 0xAA;
    box.id[31] = 0xBB;

    const id = extractId(&box);
    try std.testing.expectEqual(@as(u8, 0xAA), id[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), id[31]);
}

test "box: extractScriptBytes" {
    const script = [_]u8{ 0x00, 0x7F }; // TrueLeaf
    var box = context.testBox();
    box.proposition_bytes = &script;

    const bytes = extractScriptBytes(&box);
    try std.testing.expectEqualSlices(u8, &script, bytes);
}

test "box: extractCreationHeight" {
    var box = context.testBox();
    box.creation_height = 500_000;

    try std.testing.expectEqual(@as(u32, 500_000), extractCreationHeight(&box));
}

test "box: extractRegister R4" {
    const r4_data = [_]u8{ 0x01, 0x02, 0x03 };
    var box = context.testBox();
    box.registers[0] = &r4_data; // R4 is at index 0

    const data = extractRegister(&box, .R4);
    try std.testing.expect(data != null);
    try std.testing.expectEqualSlices(u8, &r4_data, data.?);
}

test "box: extractRegister undefined" {
    const box = context.testBox();

    try std.testing.expectEqual(@as(?[]const u8, null), extractRegister(&box, .R5));
    try std.testing.expect(!hasRegister(&box, .R5));
}

test "box: extractCreationInfo" {
    var box = context.testBox();
    box.creation_height = 100_000;
    box.tx_id[0] = 0xFF;

    const info = extractCreationInfo(&box);
    try std.testing.expectEqual(@as(u32, 100_000), info.height);
    try std.testing.expectEqual(@as(u8, 0xFF), info.tx_id[0]);
}

test "box: tokens" {
    const tokens = [_]Token{
        .{ .id = [_]u8{0xAA} ** 32, .amount = 100 },
        .{ .id = [_]u8{0xBB} ** 32, .amount = 200 },
    };

    var box = context.testBox();
    box.tokens = &tokens;

    try std.testing.expectEqual(@as(usize, 2), tokenCount(&box));

    const tok0 = getToken(&box, 0).?;
    try std.testing.expectEqual(@as(u8, 0xAA), tok0.id[0]);
    try std.testing.expectEqual(@as(i64, 100), tok0.amount);

    try std.testing.expectEqual(@as(?Token, null), getToken(&box, 99));
}
