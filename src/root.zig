//! Zigma - High-performance ErgoTree Interpreter
//!
//! A Zig implementation of the ErgoTree bytecode interpreter following
//! TigerBeetle-style data-oriented design principles.
//!
//! Design goals (in order):
//! 1. Safety - cryptographic correctness, no undefined behavior
//! 2. Determinism - identical results across all platforms
//! 3. Performance - sub-millisecond transaction validation
//! 4. Developer experience - clear code, good documentation

const std = @import("std");

// ============================================================================
// Public API Modules
// ============================================================================

/// Serialization primitives (VLQ, ZigZag encoding)
pub const vlq = @import("serialization/vlq.zig");

/// Type serialization (type codes to TypePool indices)
pub const type_serializer = @import("serialization/type_serializer.zig");

/// Data serialization (values to/from bytes)
pub const data_serializer = @import("serialization/data_serializer.zig");

/// Expression serialization (expression trees to/from bytes)
pub const expr_serializer = @import("serialization/expr_serializer.zig");

/// ErgoTree envelope serialization (header, constants, root expression)
pub const ergotree_serializer = @import("serialization/ergotree_serializer.zig");

/// Core type system (SType, TypePool)
pub const types = @import("core/types.zig");

/// Opcode catalog with metadata
pub const opcodes = @import("core/opcodes.zig");

/// Memory management pools
pub const memory = @import("interpreter/memory.zig");

/// Execution context (boxes, headers, height)
pub const context = @import("interpreter/context.zig");

/// Per-input context extension cache (for getVarFromInput)
pub const context_extension_cache = @import("interpreter/context_extension_cache.zig");

/// Expression evaluator
pub const evaluator = @import("interpreter/evaluator.zig");

/// Modular operations (arithmetic, comparison, logical)
pub const ops = @import("interpreter/ops.zig");

/// Cryptographic hash functions (Blake2b256, SHA256)
pub const hash = @import("crypto/hash.zig");

/// 256-bit signed integer arithmetic
pub const bigint = @import("crypto/bigint.zig");

/// secp256k1 elliptic curve operations
pub const secp256k1 = @import("crypto/secp256k1.zig");

/// SigmaBoolean tree representation
pub const sigma_tree = @import("sigma/sigma_tree.zig");

/// Fiat-Shamir challenge computation
pub const challenge = @import("sigma/challenge.zig");

/// Schnorr signature verification (ProveDlog)
pub const schnorr = @import("sigma/schnorr.zig");

/// Sigma protocol verifier (AND/OR/THRESHOLD)
pub const verifier = @import("sigma/verifier.zig");

/// AVL+ tree data structure and proof verification
pub const avl_tree = @import("crypto/avl_tree.zig");

// Re-export commonly used types
pub const SType = types.SType;
pub const TypePool = types.TypePool;
pub const OpCode = opcodes.OpCode;
pub const EvalPools = memory.EvalPools;

// Pull in tests from all modules
comptime {
    _ = vlq;
    _ = type_serializer;
    _ = data_serializer;
    _ = expr_serializer;
    _ = ergotree_serializer;
    _ = types;
    _ = opcodes;
    _ = memory;
    _ = context;
    _ = context_extension_cache;
    _ = evaluator;
    _ = ops;
    _ = hash;
    _ = bigint;
    _ = secp256k1;
    _ = sigma_tree;
    _ = challenge;
    _ = schnorr;
    _ = verifier;
    _ = avl_tree;
}

/// Protocol version constants
pub const ProtocolVersion = enum(u8) {
    v0 = 0, // Pre-4.0 (legacy)
    v1 = 1, // Post-4.0 hard fork
    v2 = 2, // 5.0 soft fork (JIT) - current mainnet
    v3 = 3, // 6.0 soft fork (EIP-50)

    pub fn supportsJIT(self: ProtocolVersion) bool {
        return @intFromEnum(self) >= 2;
    }

    pub fn supportsV6Features(self: ProtocolVersion) bool {
        return @intFromEnum(self) >= 3;
    }
};

/// Current target protocol version
pub const current_version: ProtocolVersion = .v2;

/// Maximum supported protocol version
pub const max_supported_version: ProtocolVersion = .v3;

test "protocol version ordering" {
    try std.testing.expect(@intFromEnum(ProtocolVersion.v0) < @intFromEnum(ProtocolVersion.v1));
    try std.testing.expect(@intFromEnum(ProtocolVersion.v1) < @intFromEnum(ProtocolVersion.v2));
    try std.testing.expect(@intFromEnum(ProtocolVersion.v2) < @intFromEnum(ProtocolVersion.v3));
}

test "protocol version features" {
    try std.testing.expect(!ProtocolVersion.v1.supportsJIT());
    try std.testing.expect(ProtocolVersion.v2.supportsJIT());
    try std.testing.expect(!ProtocolVersion.v2.supportsV6Features());
    try std.testing.expect(ProtocolVersion.v3.supportsV6Features());
}
