//! SigmaBoolean Tree Representation
//!
//! Core of Ergo's authentication language. Represents propositions that
//! can be proven via Σ-protocols:
//! - ProveDlog: knowledge of discrete log (Schnorr)
//! - ProveDHTuple: knowledge of DH tuple (Chaum-Pedersen)
//! - AND/OR/THRESHOLD: logical connectives
//!
//! The tree is evaluated during script reduction to produce either:
//! - SigmaBoolean (needs cryptographic proof)
//! - TrivialProp (always true/false, no proof needed)
//!
//! Reference: ErgoTree Spec Section A.7, Figure 13

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const timing = @import("../crypto/timing.zig");

const Point = secp256k1.Point;

// ============================================================================
// Cryptographic Primitive Types
// ============================================================================

/// ProveDlog: Prove knowledge of discrete log
/// Statement: "I know x such that PK = g^x"
/// where g is the secp256k1 generator
pub const ProveDlog = struct {
    /// Public key: g^x (SEC1 compressed, 33 bytes)
    public_key: [33]u8,

    /// Create from public key bytes (no validation)
    pub fn init(pk: [33]u8) ProveDlog {
        // Precondition: public key has valid compressed prefix (0x02 or 0x03)
        assert(pk[0] == 0x02 or pk[0] == 0x03);
        // Precondition: public key is 33 bytes (ensured by type)
        assert(pk.len == 33);

        const result = ProveDlog{ .public_key = pk };
        // Postcondition: stored key matches input
        assert(std.mem.eql(u8, &result.public_key, &pk));
        return result;
    }

    /// Create from public key bytes with curve validation
    /// CRITICAL: Use this for untrusted input to ensure point is on curve
    pub fn initValidated(pk: [33]u8) !ProveDlog {
        // PRECONDITION 1: valid compressed prefix
        assert(pk[0] == 0x02 or pk[0] == 0x03 or isAllZeros(&pk));

        // Validate point is on curve (or infinity)
        _ = Point.decode(&pk) catch return error.InvalidGroupElement;

        const result = ProveDlog{ .public_key = pk };

        // POSTCONDITION: stored key matches input
        assert(std.mem.eql(u8, &result.public_key, &pk));
        return result;
    }

    /// Check equality (NOT constant-time)
    pub fn eql(a: ProveDlog, b: ProveDlog) bool {
        return std.mem.eql(u8, &a.public_key, &b.public_key);
    }

    /// Constant-time equality (for cryptographic use)
    pub fn constantTimeEql(a: ProveDlog, b: ProveDlog) bool {
        return timing.constantTimeEqlFixed(33, &a.public_key, &b.public_key);
    }
};

/// ProveDHTuple: Prove knowledge of DH tuple
/// Statement: "I know x such that u = g^x AND v = h^x"
/// Used for more complex authentication schemes
pub const ProveDHTuple = struct {
    /// Generator g (SEC1 compressed, 33 bytes)
    g: [33]u8,
    /// Second base h (SEC1 compressed, 33 bytes)
    h: [33]u8,
    /// u = g^x (SEC1 compressed, 33 bytes)
    u: [33]u8,
    /// v = h^x (SEC1 compressed, 33 bytes)
    v: [33]u8,

    /// Create from raw bytes (no validation)
    pub fn init(g: [33]u8, h: [33]u8, u: [33]u8, v: [33]u8) ProveDHTuple {
        return .{ .g = g, .h = h, .u = u, .v = v };
    }

    /// Create from bytes with curve validation on all 4 points
    /// CRITICAL: Use this for untrusted input
    /// All 4 group elements MUST be validated before cryptographic use
    pub fn initValidated(g: [33]u8, h: [33]u8, u: [33]u8, v: [33]u8) !ProveDHTuple {
        // PRECONDITION 1: All points have valid prefix or are all-zeros (infinity)
        assert(g[0] == 0x02 or g[0] == 0x03 or isAllZeros(&g));
        assert(h[0] == 0x02 or h[0] == 0x03 or isAllZeros(&h));
        assert(u[0] == 0x02 or u[0] == 0x03 or isAllZeros(&u));
        assert(v[0] == 0x02 or v[0] == 0x03 or isAllZeros(&v));

        // Validate all 4 points are on curve
        _ = Point.decode(&g) catch return error.InvalidGroupElement;
        _ = Point.decode(&h) catch return error.InvalidGroupElement;
        _ = Point.decode(&u) catch return error.InvalidGroupElement;
        _ = Point.decode(&v) catch return error.InvalidGroupElement;

        const result = ProveDHTuple{ .g = g, .h = h, .u = u, .v = v };

        // POSTCONDITION: all bytes stored correctly
        assert(std.mem.eql(u8, &result.g, &g));
        assert(std.mem.eql(u8, &result.h, &h));
        assert(std.mem.eql(u8, &result.u, &u));
        assert(std.mem.eql(u8, &result.v, &v));

        return result;
    }

    /// Check equality (NOT constant-time)
    pub fn eql(a: ProveDHTuple, b: ProveDHTuple) bool {
        return std.mem.eql(u8, &a.g, &b.g) and
            std.mem.eql(u8, &a.h, &b.h) and
            std.mem.eql(u8, &a.u, &b.u) and
            std.mem.eql(u8, &a.v, &b.v);
    }

    /// Constant-time equality (for cryptographic use)
    /// CRITICAL: No early exit - always examines all bytes
    pub fn constantTimeEql(a: ProveDHTuple, b: ProveDHTuple) bool {
        const g_eq = timing.constantTimeEqlFixed(33, &a.g, &b.g);
        const h_eq = timing.constantTimeEqlFixed(33, &a.h, &b.h);
        const u_eq = timing.constantTimeEqlFixed(33, &a.u, &b.u);
        const v_eq = timing.constantTimeEqlFixed(33, &a.v, &b.v);
        // Combine results without short-circuit evaluation
        return g_eq and h_eq and u_eq and v_eq;
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a byte array is all zeros (represents point at infinity)
fn isAllZeros(bytes: []const u8) bool {
    for (bytes) |b| {
        if (b != 0) return false;
    }
    return true;
}

// ============================================================================
// SigmaBoolean Tree
// ============================================================================

/// Maximum depth of SigmaBoolean tree (prevents stack overflow during reduction)
pub const max_tree_depth: usize = 128;

/// Maximum number of children in AND/OR/THRESHOLD nodes
pub const max_children: usize = 255;

// Compile-time assertions for tree limits
comptime {
    // Depth must be bounded to prevent stack overflow
    assert(max_tree_depth <= 256);
    // Children count must fit in u8 for compact representation
    assert(max_children <= 255);
    // Tree depth must allow reasonable nesting
    assert(max_tree_depth >= 8);
}

/// SigmaBoolean tree node
/// Tagged union representing all possible proposition types
pub const SigmaBoolean = union(enum) {
    /// Trivially true proposition (always valid, no proof needed)
    trivial_true: void,

    /// Trivially false proposition (always invalid)
    trivial_false: void,

    /// Prove knowledge of discrete log
    prove_dlog: ProveDlog,

    /// Prove knowledge of DH tuple
    prove_dh_tuple: ProveDHTuple,

    /// Conjunction (AND): All children must be proven
    cand: struct {
        children: []const *const SigmaBoolean,
    },

    /// Disjunction (OR): At least one child must be proven
    cor: struct {
        children: []const *const SigmaBoolean,
    },

    /// Threshold: At least k of n children must be proven
    cthreshold: struct {
        /// Required number of proofs
        k: u16,
        /// Child propositions
        children: []const *const SigmaBoolean,
    },

    // ========================================================================
    // Trivial Predicate Checks
    // ========================================================================

    /// Check if this is a trivial proposition (known true/false)
    pub fn isTrivial(self: SigmaBoolean) bool {
        return self == .trivial_true or self == .trivial_false;
    }

    /// Check if trivially true
    pub fn isTrue(self: SigmaBoolean) bool {
        return self == .trivial_true;
    }

    /// Check if trivially false
    pub fn isFalse(self: SigmaBoolean) bool {
        return self == .trivial_false;
    }

    /// Check if this requires a cryptographic proof
    pub fn requiresProof(self: SigmaBoolean) bool {
        return switch (self) {
            .trivial_true, .trivial_false => false,
            .prove_dlog, .prove_dh_tuple => true,
            .cand, .cor, .cthreshold => !self.isTrivial(),
        };
    }

    // ========================================================================
    // Tree Reduction (Simplification)
    // ========================================================================

    /// Reduce tree by simplifying trivial branches
    /// Returns a semantically equivalent but potentially simpler proposition
    pub fn reduce(self: *const SigmaBoolean) SigmaBoolean {
        return reduceWithDepth(self, 0);
    }

    fn reduceWithDepth(self: *const SigmaBoolean, depth: usize) SigmaBoolean {
        // Precondition: depth is within bounds
        assert(depth <= max_tree_depth);

        // Prevent infinite recursion
        if (depth >= max_tree_depth) {
            return self.*;
        }

        switch (self.*) {
            // Leaf nodes: already reduced
            .trivial_true, .trivial_false, .prove_dlog, .prove_dh_tuple => return self.*,

            .cand => |and_node| {
                // AND reduction:
                // - If ANY child is false → whole thing is false
                // - If ALL children are true → whole thing is true
                // - Otherwise, keep non-trivial children
                var all_true = true;

                for (and_node.children) |child| {
                    const reduced = child.reduceWithDepth(depth + 1);
                    if (reduced.isFalse()) return .trivial_false;
                    if (!reduced.isTrue()) all_true = false;
                }

                if (all_true) return .trivial_true;
                return self.*;
            },

            .cor => |or_node| {
                // OR reduction:
                // - If ANY child is true → whole thing is true
                // - If ALL children are false → whole thing is false
                // - Otherwise, keep non-trivial children
                var all_false = true;

                for (or_node.children) |child| {
                    const reduced = child.reduceWithDepth(depth + 1);
                    if (reduced.isTrue()) return .trivial_true;
                    if (!reduced.isFalse()) all_false = false;
                }

                if (all_false) return .trivial_false;
                return self.*;
            },

            .cthreshold => |th| {
                // THRESHOLD reduction:
                // - Count trivially true children
                // - If true_count >= k → whole thing is true
                // - If remaining children can't reach k → whole thing is false
                var true_count: u16 = 0;
                var false_count: u16 = 0;
                const n: u16 = @intCast(th.children.len);

                for (th.children) |child| {
                    const reduced = child.reduceWithDepth(depth + 1);
                    if (reduced.isTrue()) true_count += 1;
                    if (reduced.isFalse()) false_count += 1;
                }

                // Enough are already true
                if (true_count >= th.k) return .trivial_true;

                // Too many are false (can't possibly reach threshold)
                // Need: n - false_count >= k
                // Equivalent: false_count > n - k
                if (false_count > n - th.k) return .trivial_false;

                return self.*;
            },
        }
    }

    // ========================================================================
    // Equality
    // ========================================================================

    /// Check structural equality
    pub fn eql(a: SigmaBoolean, b: SigmaBoolean) bool {
        if (@intFromEnum(a) != @intFromEnum(b)) return false;

        return switch (a) {
            .trivial_true, .trivial_false => true,
            .prove_dlog => |dlog_a| dlog_a.eql(b.prove_dlog),
            .prove_dh_tuple => |dht_a| dht_a.eql(b.prove_dh_tuple),
            .cand => |and_a| {
                const and_b = b.cand;
                if (and_a.children.len != and_b.children.len) return false;
                for (and_a.children, and_b.children) |ca, cb| {
                    if (!ca.eql(cb.*)) return false;
                }
                return true;
            },
            .cor => |or_a| {
                const or_b = b.cor;
                if (or_a.children.len != or_b.children.len) return false;
                for (or_a.children, or_b.children) |ca, cb| {
                    if (!ca.eql(cb.*)) return false;
                }
                return true;
            },
            .cthreshold => |th_a| {
                const th_b = b.cthreshold;
                if (th_a.k != th_b.k) return false;
                if (th_a.children.len != th_b.children.len) return false;
                for (th_a.children, th_b.children) |ca, cb| {
                    if (!ca.eql(cb.*)) return false;
                }
                return true;
            },
        };
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /// Count total nodes in tree (for complexity analysis)
    pub fn nodeCount(self: *const SigmaBoolean) usize {
        return switch (self.*) {
            .trivial_true, .trivial_false, .prove_dlog, .prove_dh_tuple => 1,
            .cand => |and_node| {
                var count: usize = 1;
                for (and_node.children) |child| {
                    count += child.nodeCount();
                }
                return count;
            },
            .cor => |or_node| {
                var count: usize = 1;
                for (or_node.children) |child| {
                    count += child.nodeCount();
                }
                return count;
            },
            .cthreshold => |th| {
                var count: usize = 1;
                for (th.children) |child| {
                    count += child.nodeCount();
                }
                return count;
            },
        };
    }

    /// Count crypto primitives (ProveDlog + ProveDHTuple)
    pub fn primitiveCount(self: *const SigmaBoolean) usize {
        return switch (self.*) {
            .trivial_true, .trivial_false => 0,
            .prove_dlog, .prove_dh_tuple => 1,
            .cand => |and_node| {
                var count: usize = 0;
                for (and_node.children) |child| {
                    count += child.primitiveCount();
                }
                return count;
            },
            .cor => |or_node| {
                var count: usize = 0;
                for (or_node.children) |child| {
                    count += child.primitiveCount();
                }
                return count;
            },
            .cthreshold => |th| {
                var count: usize = 0;
                for (th.children) |child| {
                    count += child.primitiveCount();
                }
                return count;
            },
        };
    }
};

// ============================================================================
// Constants
// ============================================================================

/// Trivially true proposition
pub const sigma_true = SigmaBoolean{ .trivial_true = {} };

/// Trivially false proposition
pub const sigma_false = SigmaBoolean{ .trivial_false = {} };

// ============================================================================
// Tests
// ============================================================================

test "sigma: trivial predicates" {
    try std.testing.expect(sigma_true.isTrue());
    try std.testing.expect(!sigma_true.isFalse());
    try std.testing.expect(sigma_true.isTrivial());

    try std.testing.expect(sigma_false.isFalse());
    try std.testing.expect(!sigma_false.isTrue());
    try std.testing.expect(sigma_false.isTrivial());
}

test "sigma: ProveDlog creation" {
    const pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const dlog = ProveDlog.init(pk);
    const sigma = SigmaBoolean{ .prove_dlog = dlog };

    try std.testing.expect(!sigma.isTrivial());
    try std.testing.expect(sigma.requiresProof());
}

test "sigma: AND reduction with false child" {
    const child_true = sigma_true;
    const child_false = sigma_false;
    const children = [_]*const SigmaBoolean{ &child_true, &child_false };

    const and_prop = SigmaBoolean{ .cand = .{ .children = &children } };
    const reduced = and_prop.reduce();

    try std.testing.expect(reduced.isFalse());
}

test "sigma: AND reduction with all true" {
    const child1 = sigma_true;
    const child2 = sigma_true;
    const children = [_]*const SigmaBoolean{ &child1, &child2 };

    const and_prop = SigmaBoolean{ .cand = .{ .children = &children } };
    const reduced = and_prop.reduce();

    try std.testing.expect(reduced.isTrue());
}

test "sigma: OR reduction with true child" {
    const child_true = sigma_true;
    const child_false = sigma_false;
    const children = [_]*const SigmaBoolean{ &child_false, &child_true };

    const or_prop = SigmaBoolean{ .cor = .{ .children = &children } };
    const reduced = or_prop.reduce();

    try std.testing.expect(reduced.isTrue());
}

test "sigma: OR reduction with all false" {
    const child1 = sigma_false;
    const child2 = sigma_false;
    const children = [_]*const SigmaBoolean{ &child1, &child2 };

    const or_prop = SigmaBoolean{ .cor = .{ .children = &children } };
    const reduced = or_prop.reduce();

    try std.testing.expect(reduced.isFalse());
}

test "sigma: THRESHOLD 2-of-3 with 2 true" {
    const child1 = sigma_true;
    const child2 = sigma_false;
    const child3 = sigma_true;
    const children = [_]*const SigmaBoolean{ &child1, &child2, &child3 };

    const th_prop = SigmaBoolean{ .cthreshold = .{ .k = 2, .children = &children } };
    const reduced = th_prop.reduce();

    try std.testing.expect(reduced.isTrue());
}

test "sigma: THRESHOLD 2-of-3 with 2 false" {
    const child1 = sigma_true;
    const child2 = sigma_false;
    const child3 = sigma_false;
    const children = [_]*const SigmaBoolean{ &child1, &child2, &child3 };

    const th_prop = SigmaBoolean{ .cthreshold = .{ .k = 2, .children = &children } };
    const reduced = th_prop.reduce();

    try std.testing.expect(reduced.isFalse());
}

test "sigma: nested tree reduction" {
    // (true AND false) OR true = false OR true = true
    const inner_true = sigma_true;
    const inner_false = sigma_false;
    const and_children = [_]*const SigmaBoolean{ &inner_true, &inner_false };
    const and_prop = SigmaBoolean{ .cand = .{ .children = &and_children } };

    const outer_true = sigma_true;
    const or_children = [_]*const SigmaBoolean{ &and_prop, &outer_true };
    const or_prop = SigmaBoolean{ .cor = .{ .children = &or_children } };

    const reduced = or_prop.reduce();
    try std.testing.expect(reduced.isTrue());
}

test "sigma: node count" {
    const pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const dlog = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk) };
    const t = sigma_true;

    const children = [_]*const SigmaBoolean{ &dlog, &t };
    const and_prop = SigmaBoolean{ .cand = .{ .children = &children } };

    try std.testing.expectEqual(@as(usize, 3), and_prop.nodeCount());
    try std.testing.expectEqual(@as(usize, 1), and_prop.primitiveCount());
}

test "sigma: equality" {
    const pk1 = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const pk2 = [_]u8{0x02} ++ [_]u8{0xBB} ** 32;

    const dlog1 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk1) };
    const dlog2 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk1) };
    const dlog3 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk2) };

    try std.testing.expect(dlog1.eql(dlog2));
    try std.testing.expect(!dlog1.eql(dlog3));
    try std.testing.expect(sigma_true.eql(sigma_true));
    try std.testing.expect(!sigma_true.eql(sigma_false));
}
