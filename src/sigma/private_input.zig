//! Private Inputs for Sigma Protocol Proving
//!
//! Contains secret key types for generating proofs:
//! - DlogProverInput: Secret scalar for ProveDlog (Schnorr)
//! - DhTupleProverInput: Secret scalar for ProveDHTuple
//!
//! Reference: sigma-rust/ergotree-interpreter/src/sigma_protocol/private_input.rs

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const sigma_tree = @import("sigma_tree.zig");

const Point = secp256k1.Point;
const Scalar = secp256k1.Scalar;
const ProveDlog = sigma_tree.ProveDlog;
const ProveDHTuple = sigma_tree.ProveDHTuple;

// ============================================================================
// DlogProverInput - Secret for ProveDlog
// ============================================================================

/// Secret input for proving knowledge of discrete log
/// Statement: "I know x such that PK = g^x"
pub const DlogProverInput = struct {
    /// Secret scalar x
    w: Scalar,

    /// Create from raw scalar bytes (big-endian)
    pub fn init(secret_bytes: [32]u8) !DlogProverInput {
        const w = Scalar.fromBytes(secret_bytes) catch return error.InvalidScalar;
        return .{ .w = w };
    }

    /// Create from scalar
    pub fn fromScalar(w: Scalar) DlogProverInput {
        return .{ .w = w };
    }

    /// Compute the public image: g^w
    pub fn publicImage(self: DlogProverInput) ProveDlog {
        const g = Point.generator();
        const pk = g.mul(self.w);
        var compressed: [33]u8 = undefined;
        pk.encode(&compressed);
        return ProveDlog.init(compressed);
    }

    /// Check if this secret corresponds to a given public key
    pub fn matchesPublicKey(self: DlogProverInput, pk: ProveDlog) bool {
        const computed = self.publicImage();
        return std.mem.eql(u8, &computed.public_key, &pk.public_key);
    }
};

// ============================================================================
// DhTupleProverInput - Secret for ProveDHTuple
// ============================================================================

/// Secret input for proving knowledge of DH tuple
/// Statement: "I know x such that u = g^x AND v = h^x"
pub const DhTupleProverInput = struct {
    /// Secret scalar x
    w: Scalar,
    /// The public DH tuple proposition
    common_input: ProveDHTuple,

    /// Create from secret and proposition
    pub fn init(secret_bytes: [32]u8, proposition: ProveDHTuple) !DhTupleProverInput {
        const w = Scalar.fromBytes(secret_bytes) catch return error.InvalidScalar;
        return .{
            .w = w,
            .common_input = proposition,
        };
    }

    /// Create from scalar and proposition
    pub fn fromScalar(w: Scalar, proposition: ProveDHTuple) DhTupleProverInput {
        return .{
            .w = w,
            .common_input = proposition,
        };
    }

    /// Get the public proposition
    pub fn publicImage(self: DhTupleProverInput) ProveDHTuple {
        return self.common_input;
    }
};

// ============================================================================
// PrivateInput - Union of all secret types
// ============================================================================

/// Union of all private input types
pub const PrivateInput = union(enum) {
    dlog: DlogProverInput,
    dh_tuple: DhTupleProverInput,

    /// Get the public image as a SigmaBoolean
    pub fn publicImage(self: PrivateInput) sigma_tree.SigmaBoolean {
        return switch (self) {
            .dlog => |d| .{ .prove_dlog = d.publicImage() },
            .dh_tuple => |dh| .{ .prove_dh_tuple = dh.publicImage() },
        };
    }

    /// Check if this private input matches a given sigma boolean
    pub fn matches(self: PrivateInput, sb: sigma_tree.SigmaBoolean) bool {
        return switch (self) {
            .dlog => |d| switch (sb) {
                .prove_dlog => |pk| d.matchesPublicKey(pk),
                else => false,
            },
            .dh_tuple => |dh| switch (sb) {
                .prove_dh_tuple => |prop| dh.common_input.eql(prop),
                else => false,
            },
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DlogProverInput: public image computation" {
    // Known test vector: secret = 1, public = generator
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 1; // scalar = 1

    const input = try DlogProverInput.init(secret);
    const pub_image = input.publicImage();

    // Generator point compressed form starts with 0x02 or 0x03
    try std.testing.expect(pub_image.public_key[0] == 0x02 or pub_image.public_key[0] == 0x03);
}

test "DlogProverInput: matches public key" {
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 42;

    const input = try DlogProverInput.init(secret);
    const pub_image = input.publicImage();

    try std.testing.expect(input.matchesPublicKey(pub_image));

    // Different key should not match
    var other_pk = pub_image;
    other_pk.public_key[5] ^= 0xFF;
    try std.testing.expect(!input.matchesPublicKey(other_pk));
}

test "PrivateInput: union access" {
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 7;

    const dlog_input = try DlogProverInput.init(secret);
    const private_input = PrivateInput{ .dlog = dlog_input };

    const sb = private_input.publicImage();
    try std.testing.expect(sb == .prove_dlog);
    try std.testing.expect(private_input.matches(sb));
}
