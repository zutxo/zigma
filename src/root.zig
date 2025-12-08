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
