//! Context Operations for ErgoTree Interpreter
//!
//! Implements context access operations:
//! - HEIGHT: Current block height
//! - INPUTS: Input boxes being spent
//! - OUTPUTS: Output boxes being created
//! - SELF: The box containing this script
//! - DATA_INPUTS: Read-only reference boxes
//! - HEADERS: Last N block headers
//! - PRE_HEADER: Current block pre-header
//!
//! Reference: sigmastate/src/main/scala/sigmastate/utxo/ContextOps.scala

const std = @import("std");
const assert = std.debug.assert;
const ctx = @import("../context.zig");

const Context = ctx.Context;
const BoxView = ctx.BoxView;
const HeaderView = ctx.HeaderView;
const PreHeaderView = ctx.PreHeaderView;

// ============================================================================
// Error Types
// ============================================================================

pub const ContextError = error{
    /// Variable not defined
    VarNotDefined,
    /// Index out of bounds
    IndexOutOfBounds,
};

// ============================================================================
// Block Context Operations
// ============================================================================

/// Get current block height
/// OpCode: Height (0xA3)
pub fn height(context: *const Context) u32 {
    assert(context.height > 0);
    return context.height;
}

/// Get block height as i32 (for Value compatibility)
pub fn heightAsInt(context: *const Context) i32 {
    assert(context.height > 0);
    assert(context.height <= std.math.maxInt(i32));
    return @intCast(context.height);
}

// ============================================================================
// Box Collection Operations
// ============================================================================

/// Get input boxes being spent
/// OpCode: Inputs (0xA4)
pub fn inputs(context: *const Context) []const BoxView {
    assert(context.inputs.len > 0);
    return context.inputs;
}

/// Get number of inputs
pub fn inputsCount(context: *const Context) usize {
    return context.inputs.len;
}

/// Get specific input by index
pub fn getInput(context: *const Context, index: usize) ContextError!*const BoxView {
    if (index >= context.inputs.len) return error.IndexOutOfBounds;
    return &context.inputs[index];
}

/// Get output boxes being created
/// OpCode: Outputs (0xA5)
pub fn outputs(context: *const Context) []const BoxView {
    return context.outputs;
}

/// Get number of outputs
pub fn outputsCount(context: *const Context) usize {
    return context.outputs.len;
}

/// Get specific output by index
pub fn getOutput(context: *const Context, index: usize) ContextError!*const BoxView {
    if (index >= context.outputs.len) return error.IndexOutOfBounds;
    return &context.outputs[index];
}

/// Get SELF box (the box being validated)
/// OpCode: Self (0xA6)
pub fn selfBox(context: *const Context) *const BoxView {
    assert(context.self_index < context.inputs.len);
    return context.getSelf();
}

/// Get index of SELF in inputs
pub fn selfIndex(context: *const Context) u16 {
    return context.self_index;
}

/// Get data input boxes (read-only references)
/// OpCode: DataInputs
pub fn dataInputs(context: *const Context) []const BoxView {
    return context.data_inputs;
}

/// Get number of data inputs
pub fn dataInputsCount(context: *const Context) usize {
    return context.data_inputs.len;
}

/// Get specific data input by index
pub fn getDataInput(context: *const Context, index: usize) ContextError!*const BoxView {
    if (index >= context.data_inputs.len) return error.IndexOutOfBounds;
    return &context.data_inputs[index];
}

// ============================================================================
// Header Operations
// ============================================================================

/// Get last N block headers (newest first)
/// OpCode: Headers
pub fn headers(context: *const Context) []const HeaderView {
    return context.headers;
}

/// Get number of available headers
pub fn headersCount(context: *const Context) usize {
    return context.headers.len;
}

/// Get specific header by index (0 = most recent)
pub fn getHeader(context: *const Context, index: usize) ContextError!*const HeaderView {
    if (index >= context.headers.len) return error.IndexOutOfBounds;
    return &context.headers[index];
}

/// Get pre-header for current block
/// OpCode: PreHeader
pub fn preHeader(context: *const Context) PreHeaderView {
    return context.pre_header;
}

// ============================================================================
// Context Variables
// ============================================================================

/// Get context variable by ID
/// OpCode: GetVar
/// Returns null if variable is not defined
pub fn getVar(context: *const Context, var_id: u8) ?[]const u8 {
    return context.getVar(var_id);
}

/// Get context variable, error if not defined
pub fn getVarRequired(context: *const Context, var_id: u8) ContextError![]const u8 {
    return context.getVar(var_id) orelse error.VarNotDefined;
}

// ============================================================================
// Tests
// ============================================================================

test "context_ops: height" {
    const test_inputs = [_]BoxView{ctx.testBox()};
    const context = Context.forHeight(500, &test_inputs);

    try std.testing.expectEqual(@as(u32, 500), height(&context));
    try std.testing.expectEqual(@as(i32, 500), heightAsInt(&context));
}

test "context_ops: inputs" {
    var box1 = ctx.testBox();
    box1.value = 100;
    var box2 = ctx.testBox();
    box2.value = 200;
    const test_inputs = [_]BoxView{ box1, box2 };

    const context = Context.forHeight(100, &test_inputs);

    try std.testing.expectEqual(@as(usize, 2), inputsCount(&context));

    const inp0 = try getInput(&context, 0);
    try std.testing.expectEqual(@as(i64, 100), inp0.value);

    const inp1 = try getInput(&context, 1);
    try std.testing.expectEqual(@as(i64, 200), inp1.value);

    try std.testing.expectError(error.IndexOutOfBounds, getInput(&context, 99));
}

test "context_ops: outputs" {
    const test_inputs = [_]BoxView{ctx.testBox()};
    var context = Context.forHeight(100, &test_inputs);

    var out_box = ctx.testBox();
    out_box.value = 999;
    const test_outputs = [_]BoxView{out_box};
    context.outputs = &test_outputs;

    try std.testing.expectEqual(@as(usize, 1), outputsCount(&context));

    const out0 = try getOutput(&context, 0);
    try std.testing.expectEqual(@as(i64, 999), out0.value);
}

test "context_ops: selfBox" {
    var box1 = ctx.testBox();
    box1.value = 111;
    var box2 = ctx.testBox();
    box2.value = 222;
    const test_inputs = [_]BoxView{ box1, box2 };

    var context = Context.forHeight(100, &test_inputs);
    context.self_index = 1;

    const self = selfBox(&context);
    try std.testing.expectEqual(@as(i64, 222), self.value);
    try std.testing.expectEqual(@as(u16, 1), selfIndex(&context));
}

test "context_ops: dataInputs" {
    const test_inputs = [_]BoxView{ctx.testBox()};
    var context = Context.forHeight(100, &test_inputs);

    var data_box = ctx.testBox();
    data_box.value = 5555;
    const test_data_inputs = [_]BoxView{data_box};
    context.data_inputs = &test_data_inputs;

    try std.testing.expectEqual(@as(usize, 1), dataInputsCount(&context));

    const di0 = try getDataInput(&context, 0);
    try std.testing.expectEqual(@as(i64, 5555), di0.value);
}

test "context_ops: getVar" {
    const test_inputs = [_]BoxView{ctx.testBox()};
    var context = Context.forHeight(100, &test_inputs);

    const var_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    context.context_vars[10] = &var_data;

    try std.testing.expectEqual(@as(?[]const u8, null), getVar(&context, 0));
    try std.testing.expectEqualSlices(u8, &var_data, getVar(&context, 10).?);

    try std.testing.expectError(error.VarNotDefined, getVarRequired(&context, 99));
}

test "context_ops: preHeader" {
    const test_inputs = [_]BoxView{ctx.testBox()};
    const context = Context.forHeight(500, &test_inputs);

    const pre = preHeader(&context);
    try std.testing.expectEqual(@as(u32, 500), pre.height);
}
