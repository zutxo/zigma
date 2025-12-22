//! Unproven Tree Types for Sigma Protocol Proving
//!
//! During proving, SigmaBoolean is converted to UnprovenTree which tracks:
//! - Whether each node is "real" (we have the secret) or "simulated"
//! - Commitments (first prover messages)
//! - Randomness used for commitments
//! - Challenges assigned during proving
//!
//! Reference: sigma-rust/ergotree-interpreter/src/sigma_protocol/unproven_tree.rs

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const sigma_tree = @import("sigma_tree.zig");
const challenge_mod = @import("challenge.zig");

const Point = secp256k1.Point;
const Scalar = secp256k1.Scalar;
const ProveDlog = sigma_tree.ProveDlog;
const ProveDHTuple = sigma_tree.ProveDHTuple;
const SigmaBoolean = sigma_tree.SigmaBoolean;
const Challenge = challenge_mod.Challenge;

pub const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;
pub const SCALAR_SIZE = 32;
pub const MAX_CHILDREN = 16;

// ============================================================================
// First Prover Messages (Commitments)
// ============================================================================

/// First message for Schnorr protocol: a = g^r
pub const FirstDlogProverMessage = struct {
    /// Commitment point a = g^r
    a: Point,
};

/// First message for DH tuple protocol: (a, b) where a = g^r, b = h^r
pub const FirstDhTupleProverMessage = struct {
    /// First commitment a = g^r
    a: Point,
    /// Second commitment b = h^r
    b: Point,
};

/// Union of first prover messages
pub const FirstProverMessage = union(enum) {
    dlog: FirstDlogProverMessage,
    dh_tuple: FirstDhTupleProverMessage,
};

// ============================================================================
// Node Position in Tree
// ============================================================================

/// Position of a node in the tree (for Fiat-Shamir ordering)
pub const NodePosition = struct {
    /// Path from root: each byte is the child index at that level
    path: [32]u8,
    /// Length of the path (depth)
    depth: u8,

    pub const ROOT: NodePosition = .{
        .path = [_]u8{0} ** 32,
        .depth = 0,
    };

    /// Create child position
    pub fn child(self: NodePosition, index: u8) NodePosition {
        assert(self.depth < 31);
        var new_path = self.path;
        new_path[self.depth] = index;
        return .{
            .path = new_path,
            .depth = self.depth + 1,
        };
    }

    /// Check equality
    pub fn eql(self: NodePosition, other: NodePosition) bool {
        if (self.depth != other.depth) return false;
        return std.mem.eql(u8, self.path[0..self.depth], other.path[0..other.depth]);
    }
};

// ============================================================================
// Unproven Leaf Types
// ============================================================================

/// Unproven Schnorr (ProveDlog) leaf
pub const UnprovenSchnorr = struct {
    /// The ProveDlog proposition
    proposition: ProveDlog,
    /// Commitment (if computed)
    commitment_opt: ?FirstDlogProverMessage,
    /// Randomness r used for commitment a = g^r (if real)
    randomness_opt: ?Scalar,
    /// Challenge assigned to this node
    challenge_opt: ?Challenge,
    /// True if simulated, false if real
    simulated: bool,
    /// Position in tree
    position: NodePosition,

    pub fn isReal(self: UnprovenSchnorr) bool {
        return !self.simulated;
    }

    pub fn withSimulated(self: UnprovenSchnorr, sim: bool) UnprovenSchnorr {
        var copy = self;
        copy.simulated = sim;
        return copy;
    }

    pub fn withChallenge(self: UnprovenSchnorr, c: Challenge) UnprovenSchnorr {
        var copy = self;
        copy.challenge_opt = c;
        return copy;
    }

    pub fn withPosition(self: UnprovenSchnorr, pos: NodePosition) UnprovenSchnorr {
        var copy = self;
        copy.position = pos;
        return copy;
    }

    pub fn withCommitment(self: UnprovenSchnorr, fm: FirstDlogProverMessage, r: Scalar) UnprovenSchnorr {
        var copy = self;
        copy.commitment_opt = fm;
        copy.randomness_opt = r;
        return copy;
    }
};

/// Unproven DH tuple leaf
pub const UnprovenDhTuple = struct {
    /// The ProveDHTuple proposition
    proposition: ProveDHTuple,
    /// Commitment (if computed)
    commitment_opt: ?FirstDhTupleProverMessage,
    /// Randomness r used for commitment
    randomness_opt: ?Scalar,
    /// Challenge assigned to this node
    challenge_opt: ?Challenge,
    /// True if simulated, false if real
    simulated: bool,
    /// Position in tree
    position: NodePosition,

    pub fn isReal(self: UnprovenDhTuple) bool {
        return !self.simulated;
    }

    pub fn withSimulated(self: UnprovenDhTuple, sim: bool) UnprovenDhTuple {
        var copy = self;
        copy.simulated = sim;
        return copy;
    }

    pub fn withChallenge(self: UnprovenDhTuple, c: Challenge) UnprovenDhTuple {
        var copy = self;
        copy.challenge_opt = c;
        return copy;
    }

    pub fn withPosition(self: UnprovenDhTuple, pos: NodePosition) UnprovenDhTuple {
        var copy = self;
        copy.position = pos;
        return copy;
    }
};

/// Unproven leaf (union of leaf types)
pub const UnprovenLeaf = union(enum) {
    schnorr: UnprovenSchnorr,
    dh_tuple: UnprovenDhTuple,

    pub fn isReal(self: UnprovenLeaf) bool {
        return switch (self) {
            .schnorr => |s| s.isReal(),
            .dh_tuple => |d| d.isReal(),
        };
    }

    pub fn simulated(self: UnprovenLeaf) bool {
        return !self.isReal();
    }

    pub fn position(self: UnprovenLeaf) NodePosition {
        return switch (self) {
            .schnorr => |s| s.position,
            .dh_tuple => |d| d.position,
        };
    }

    pub fn challenge(self: UnprovenLeaf) ?Challenge {
        return switch (self) {
            .schnorr => |s| s.challenge_opt,
            .dh_tuple => |d| d.challenge_opt,
        };
    }

    pub fn withSimulated(self: UnprovenLeaf, sim: bool) UnprovenLeaf {
        return switch (self) {
            .schnorr => |s| .{ .schnorr = s.withSimulated(sim) },
            .dh_tuple => |d| .{ .dh_tuple = d.withSimulated(sim) },
        };
    }

    pub fn withChallenge(self: UnprovenLeaf, c: Challenge) UnprovenLeaf {
        return switch (self) {
            .schnorr => |s| .{ .schnorr = s.withChallenge(c) },
            .dh_tuple => |d| .{ .dh_tuple = d.withChallenge(c) },
        };
    }

    pub fn withPosition(self: UnprovenLeaf, pos: NodePosition) UnprovenLeaf {
        return switch (self) {
            .schnorr => |s| .{ .schnorr = s.withPosition(pos) },
            .dh_tuple => |d| .{ .dh_tuple = d.withPosition(pos) },
        };
    }

    /// Get the proposition as SigmaBoolean
    pub fn proposition(self: UnprovenLeaf) SigmaBoolean {
        return switch (self) {
            .schnorr => |s| .{ .prove_dlog = s.proposition },
            .dh_tuple => |d| .{ .prove_dh_tuple = d.proposition },
        };
    }
};

// ============================================================================
// Unproven Conjecture Types (AND/OR/THRESHOLD)
// ============================================================================

/// Unproven AND node
pub const CandUnproven = struct {
    /// Children
    children: [MAX_CHILDREN]?UnprovenTree,
    /// Number of children
    child_count: u8,
    /// Challenge assigned to this node
    challenge_opt: ?Challenge,
    /// True if simulated
    simulated: bool,
    /// Position in tree
    position: NodePosition,

    pub fn isReal(self: CandUnproven) bool {
        return !self.simulated;
    }

    pub fn withSimulated(self: CandUnproven, sim: bool) CandUnproven {
        var copy = self;
        copy.simulated = sim;
        return copy;
    }

    pub fn withChallenge(self: CandUnproven, c: Challenge) CandUnproven {
        var copy = self;
        copy.challenge_opt = c;
        return copy;
    }

    pub fn withPosition(self: CandUnproven, pos: NodePosition) CandUnproven {
        var copy = self;
        copy.position = pos;
        return copy;
    }

    pub fn getChildren(self: *const CandUnproven) []const ?UnprovenTree {
        return self.children[0..self.child_count];
    }

    pub fn getChildrenMut(self: *CandUnproven) []?UnprovenTree {
        return self.children[0..self.child_count];
    }
};

/// Unproven OR node
pub const CorUnproven = struct {
    /// Children
    children: [MAX_CHILDREN]?UnprovenTree,
    /// Number of children
    child_count: u8,
    /// Challenge assigned to this node
    challenge_opt: ?Challenge,
    /// True if simulated
    simulated: bool,
    /// Position in tree
    position: NodePosition,

    pub fn isReal(self: CorUnproven) bool {
        return !self.simulated;
    }

    pub fn withSimulated(self: CorUnproven, sim: bool) CorUnproven {
        var copy = self;
        copy.simulated = sim;
        return copy;
    }

    pub fn withChallenge(self: CorUnproven, c: Challenge) CorUnproven {
        var copy = self;
        copy.challenge_opt = c;
        return copy;
    }

    pub fn withPosition(self: CorUnproven, pos: NodePosition) CorUnproven {
        var copy = self;
        copy.position = pos;
        return copy;
    }

    pub fn getChildren(self: *const CorUnproven) []const ?UnprovenTree {
        return self.children[0..self.child_count];
    }

    pub fn getChildrenMut(self: *CorUnproven) []?UnprovenTree {
        return self.children[0..self.child_count];
    }
};

/// Unproven THRESHOLD node
pub const CthresholdUnproven = struct {
    /// Required number of children to prove
    k: u8,
    /// Children
    children: [MAX_CHILDREN]?UnprovenTree,
    /// Number of children
    child_count: u8,
    /// Challenge assigned to this node
    challenge_opt: ?Challenge,
    /// Polynomial for challenge distribution (THRESHOLD specific)
    polynomial_opt: ?[MAX_CHILDREN * SOUNDNESS_BYTES]u8,
    /// True if simulated
    simulated: bool,
    /// Position in tree
    position: NodePosition,

    pub fn isReal(self: CthresholdUnproven) bool {
        return !self.simulated;
    }

    pub fn withSimulated(self: CthresholdUnproven, sim: bool) CthresholdUnproven {
        var copy = self;
        copy.simulated = sim;
        return copy;
    }

    pub fn withChallenge(self: CthresholdUnproven, c: Challenge) CthresholdUnproven {
        var copy = self;
        copy.challenge_opt = c;
        return copy;
    }

    pub fn withPosition(self: CthresholdUnproven, pos: NodePosition) CthresholdUnproven {
        var copy = self;
        copy.position = pos;
        return copy;
    }
};

/// Unproven conjecture (union of AND/OR/THRESHOLD)
pub const UnprovenConjecture = union(enum) {
    cand: CandUnproven,
    cor: CorUnproven,
    cthreshold: CthresholdUnproven,

    pub fn isReal(self: UnprovenConjecture) bool {
        return switch (self) {
            .cand => |c| c.isReal(),
            .cor => |c| c.isReal(),
            .cthreshold => |c| c.isReal(),
        };
    }

    pub fn simulated(self: UnprovenConjecture) bool {
        return !self.isReal();
    }

    pub fn position(self: UnprovenConjecture) NodePosition {
        return switch (self) {
            .cand => |c| c.position,
            .cor => |c| c.position,
            .cthreshold => |c| c.position,
        };
    }

    pub fn challenge(self: UnprovenConjecture) ?Challenge {
        return switch (self) {
            .cand => |c| c.challenge_opt,
            .cor => |c| c.challenge_opt,
            .cthreshold => |c| c.challenge_opt,
        };
    }

    pub fn withSimulated(self: UnprovenConjecture, sim: bool) UnprovenConjecture {
        return switch (self) {
            .cand => |c| .{ .cand = c.withSimulated(sim) },
            .cor => |c| .{ .cor = c.withSimulated(sim) },
            .cthreshold => |c| .{ .cthreshold = c.withSimulated(sim) },
        };
    }

    pub fn withChallenge(self: UnprovenConjecture, ch: Challenge) UnprovenConjecture {
        return switch (self) {
            .cand => |c| .{ .cand = c.withChallenge(ch) },
            .cor => |c| .{ .cor = c.withChallenge(ch) },
            .cthreshold => |c| .{ .cthreshold = c.withChallenge(ch) },
        };
    }

    pub fn withPosition(self: UnprovenConjecture, pos: NodePosition) UnprovenConjecture {
        return switch (self) {
            .cand => |c| .{ .cand = c.withPosition(pos) },
            .cor => |c| .{ .cor = c.withPosition(pos) },
            .cthreshold => |c| .{ .cthreshold = c.withPosition(pos) },
        };
    }

    pub fn childCount(self: UnprovenConjecture) u8 {
        return switch (self) {
            .cand => |c| c.child_count,
            .cor => |c| c.child_count,
            .cthreshold => |c| c.child_count,
        };
    }
};

// ============================================================================
// UnprovenTree - Top-level union
// ============================================================================

/// Unproven tree node (during proving)
pub const UnprovenTree = union(enum) {
    leaf: UnprovenLeaf,
    conjecture: UnprovenConjecture,

    pub fn isReal(self: UnprovenTree) bool {
        return switch (self) {
            .leaf => |l| l.isReal(),
            .conjecture => |c| c.isReal(),
        };
    }

    pub fn simulated(self: UnprovenTree) bool {
        return !self.isReal();
    }

    pub fn position(self: UnprovenTree) NodePosition {
        return switch (self) {
            .leaf => |l| l.position(),
            .conjecture => |c| c.position(),
        };
    }

    pub fn challenge(self: UnprovenTree) ?Challenge {
        return switch (self) {
            .leaf => |l| l.challenge(),
            .conjecture => |c| c.challenge(),
        };
    }

    pub fn withSimulated(self: UnprovenTree, sim: bool) UnprovenTree {
        return switch (self) {
            .leaf => |l| .{ .leaf = l.withSimulated(sim) },
            .conjecture => |c| .{ .conjecture = c.withSimulated(sim) },
        };
    }

    pub fn withChallenge(self: UnprovenTree, ch: Challenge) UnprovenTree {
        return switch (self) {
            .leaf => |l| .{ .leaf = l.withChallenge(ch) },
            .conjecture => |c| .{ .conjecture = c.withChallenge(ch) },
        };
    }

    pub fn withPosition(self: UnprovenTree, pos: NodePosition) UnprovenTree {
        return switch (self) {
            .leaf => |l| .{ .leaf = l.withPosition(pos) },
            .conjecture => |c| .{ .conjecture = c.withPosition(pos) },
        };
    }
};

// ============================================================================
// Conversion from SigmaBoolean
// ============================================================================

/// Convert SigmaBoolean to UnprovenTree
/// All nodes start as simulated (not marked real yet)
pub fn convertToUnproven(sb: SigmaBoolean) UnprovenTree {
    return convertToUnprovenWithPosition(sb, NodePosition.ROOT);
}

fn convertToUnprovenWithPosition(sb: SigmaBoolean, pos: NodePosition) UnprovenTree {
    return switch (sb) {
        .trivial_true, .trivial_false => unreachable, // Should be handled before
        .prove_dlog => |prop| .{
            .leaf = .{
                .schnorr = .{
                    .proposition = prop,
                    .commitment_opt = null,
                    .randomness_opt = null,
                    .challenge_opt = null,
                    .simulated = true, // Default to simulated
                    .position = pos,
                },
            },
        },
        .prove_dh_tuple => |prop| .{
            .leaf = .{
                .dh_tuple = .{
                    .proposition = prop,
                    .commitment_opt = null,
                    .randomness_opt = null,
                    .challenge_opt = null,
                    .simulated = true,
                    .position = pos,
                },
            },
        },
        .and_node => |children| blk: {
            var cand = CandUnproven{
                .children = [_]?UnprovenTree{null} ** MAX_CHILDREN,
                .child_count = @intCast(children.len),
                .challenge_opt = null,
                .simulated = true,
                .position = pos,
            };
            for (children, 0..) |child, i| {
                cand.children[i] = convertToUnprovenWithPosition(child, pos.child(@intCast(i)));
            }
            break :blk .{ .conjecture = .{ .cand = cand } };
        },
        .or_node => |children| blk: {
            var cor = CorUnproven{
                .children = [_]?UnprovenTree{null} ** MAX_CHILDREN,
                .child_count = @intCast(children.len),
                .challenge_opt = null,
                .simulated = true,
                .position = pos,
            };
            for (children, 0..) |child, i| {
                cor.children[i] = convertToUnprovenWithPosition(child, pos.child(@intCast(i)));
            }
            break :blk .{ .conjecture = .{ .cor = cor } };
        },
        .threshold => |t| blk: {
            var ct = CthresholdUnproven{
                .k = t.k,
                .children = [_]?UnprovenTree{null} ** MAX_CHILDREN,
                .child_count = @intCast(t.children.len),
                .challenge_opt = null,
                .polynomial_opt = null,
                .simulated = true,
                .position = pos,
            };
            for (t.children, 0..) |child, i| {
                ct.children[i] = convertToUnprovenWithPosition(child, pos.child(@intCast(i)));
            }
            break :blk .{ .conjecture = .{ .cthreshold = ct } };
        },
    };
}

// ============================================================================
// Tests
// ============================================================================

test "NodePosition: child positions" {
    const root = NodePosition.ROOT;
    try std.testing.expectEqual(@as(u8, 0), root.depth);

    const child0 = root.child(0);
    try std.testing.expectEqual(@as(u8, 1), child0.depth);
    try std.testing.expectEqual(@as(u8, 0), child0.path[0]);

    const child1 = root.child(1);
    try std.testing.expectEqual(@as(u8, 1), child1.depth);
    try std.testing.expectEqual(@as(u8, 1), child1.path[0]);

    const grandchild = child0.child(5);
    try std.testing.expectEqual(@as(u8, 2), grandchild.depth);
    try std.testing.expectEqual(@as(u8, 0), grandchild.path[0]);
    try std.testing.expectEqual(@as(u8, 5), grandchild.path[1]);
}

test "UnprovenTree: convert from ProveDlog" {
    const pk = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    const prop = ProveDlog.init(pk);
    const sb = SigmaBoolean{ .prove_dlog = prop };

    const tree = convertToUnproven(sb);
    try std.testing.expect(tree == .leaf);
    try std.testing.expect(tree.leaf == .schnorr);
    try std.testing.expect(tree.simulated()); // Default is simulated
}
