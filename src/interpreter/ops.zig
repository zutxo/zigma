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

// Re-export common error types
pub const ArithmeticError = arithmetic.ArithmeticError;
pub const Order = comparison.Order;

// Pull in tests from all submodules
comptime {
    _ = arithmetic;
    _ = comparison;
    _ = logical;
}

test "ops: module imports work" {
    // Verify all modules are accessible
    _ = try arithmetic.add(i32, 1, 2);
    _ = comparison.lt(i32, 1, 2);
    _ = logical.logicalAnd(true, true);
}
