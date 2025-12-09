//! Operations Module for ErgoTree Interpreter
//!
//! Re-exports all operation categories for convenient access:
//! - arithmetic: +, -, *, /, %, negate, min, max
//! - comparison: <, <=, >, >=, ==, !=
//! - logical: and, or, xor, not (boolean and bitwise)
//!
//! Usage:
//!   const ops = @import("ops.zig");
//!   const result = try ops.arithmetic.add(i32, 1, 2);

const std = @import("std");

pub const arithmetic = @import("ops/arithmetic.zig");
pub const comparison = @import("ops/comparison.zig");
pub const logical = @import("ops/logical.zig");
pub const box = @import("ops/box.zig");
pub const context_ops = @import("ops/context_ops.zig");
pub const collection = @import("ops/collection.zig");
pub const crypto = @import("ops/crypto.zig");

// Re-export common error types
pub const ArithmeticError = arithmetic.ArithmeticError;
pub const Order = comparison.Order;

// Re-export context error type
pub const ContextError = context_ops.ContextError;
pub const CollectionError = collection.CollectionError;

// Pull in tests from all submodules
comptime {
    _ = arithmetic;
    _ = comparison;
    _ = logical;
    _ = box;
    _ = context_ops;
    _ = collection;
    _ = crypto;
}

test "ops: module imports work" {
    // Verify all modules are accessible
    _ = try arithmetic.add(i32, 1, 2);
    _ = comparison.lt(i32, 1, 2);
    _ = logical.logicalAnd(true, true);
    _ = crypto.calcBlake2b256("test");
    _ = crypto.calcSha256("test");
}
