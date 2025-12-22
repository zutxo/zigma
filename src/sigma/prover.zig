//! Sigma Protocol Prover
//!
//! Implements the 9-step proving algorithm from the ErgoScript whitepaper
//! for generating zero-knowledge proofs over SigmaBoolean propositions.
//!
//! The algorithm converts a SigmaBoolean tree into a proof by:
//! 1. Marking which nodes are "real" (we have the secret) vs "simulated"
//! 2. Computing commitments for all nodes
//! 3. Using Fiat-Shamir to derive the root challenge
//! 4. Computing responses for real nodes
//!
//! Reference: sigma-rust/ergotree-interpreter/src/sigma_protocol/prover.rs

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const hash = @import("../crypto/hash.zig");
const sigma_tree = @import("sigma_tree.zig");
const challenge_mod = @import("challenge.zig");
const private_input = @import("private_input.zig");
const unproven_tree = @import("unproven_tree.zig");
const schnorr = @import("schnorr.zig");
const dh_tuple = @import("dh_tuple.zig");

const Point = secp256k1.Point;
const Scalar = secp256k1.Scalar;
const SigmaBoolean = sigma_tree.SigmaBoolean;
const ProveDlog = sigma_tree.ProveDlog;
const ProveDHTuple = sigma_tree.ProveDHTuple;
const Challenge = challenge_mod.Challenge;
const PrivateInput = private_input.PrivateInput;
const DlogProverInput = private_input.DlogProverInput;
const DhTupleProverInput = private_input.DhTupleProverInput;
const UnprovenTree = unproven_tree.UnprovenTree;
const UnprovenLeaf = unproven_tree.UnprovenLeaf;
const UnprovenConjecture = unproven_tree.UnprovenConjecture;
const UnprovenSchnorr = unproven_tree.UnprovenSchnorr;
const UnprovenDhTuple = unproven_tree.UnprovenDhTuple;
const CandUnproven = unproven_tree.CandUnproven;
const CorUnproven = unproven_tree.CorUnproven;
const CthresholdUnproven = unproven_tree.CthresholdUnproven;
const FirstDlogProverMessage = unproven_tree.FirstDlogProverMessage;
const FirstDhTupleProverMessage = unproven_tree.FirstDhTupleProverMessage;
const NodePosition = unproven_tree.NodePosition;

pub const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;
pub const MAX_SECRETS = 16;
pub const MAX_TREE_DEPTH = 32;
pub const MAX_CHILDREN = unproven_tree.MAX_CHILDREN;

// ============================================================================
// Error Types
// ============================================================================

pub const ProverError = error{
    /// Root is not real (no secret for any branch)
    RootNotReal,
    /// Required secret is missing
    MissingSecret,
    /// Invalid proposition structure
    InvalidProposition,
    /// Commitment computation failed
    CommitmentFailed,
    /// Challenge computation failed
    ChallengeFailed,
    /// Response computation failed
    ResponseFailed,
    /// Tree is too deep
    TreeTooDeep,
    /// Too many children in conjecture
    TooManyChildren,
    /// Invalid point on curve
    InvalidPoint,
    /// Invalid scalar value
    InvalidScalar,
    /// Random number generation failed
    RandomFailed,
    /// Serialization buffer too small
    BufferTooSmall,
};

// ============================================================================
// Proof Types
// ============================================================================

/// Schnorr proof (ProveDlog)
pub const SchnorrProof = struct {
    /// Commitment a = g^r
    commitment: [33]u8,
    /// Response z = r + e*x (mod q)
    response: [32]u8,
    /// Challenge e
    challenge: Challenge,
};

/// DH tuple proof (ProveDHTuple)
pub const DhTupleProof = struct {
    /// Commitment a = g^r
    a: [33]u8,
    /// Commitment b = h^r
    b: [33]u8,
    /// Response z = r + e*x (mod q)
    response: [32]u8,
    /// Challenge e
    challenge: Challenge,
};

/// Proven leaf node
pub const ProvenLeaf = union(enum) {
    schnorr: SchnorrProof,
    dh_tuple: DhTupleProof,
};

/// Full proof for a SigmaBoolean tree
/// Encoded as UncheckedSigmaTree for verification
pub const Proof = struct {
    /// Serialized proof bytes
    bytes: [1024]u8,
    /// Length of proof
    len: u16,

    pub fn toSlice(self: *const Proof) []const u8 {
        return self.bytes[0..self.len];
    }
};

// ============================================================================
// Prover State
// ============================================================================

/// Prover context holding secrets and working state
pub const Prover = struct {
    /// Private inputs (secrets)
    secrets: [MAX_SECRETS]?PrivateInput,
    secret_count: u8,

    /// Random number generator state (xorshift128+)
    rng_state: [2]u64,

    /// Working stack for tree traversal (avoid recursion)
    work_stack: [MAX_TREE_DEPTH * MAX_CHILDREN]WorkItem,
    work_sp: u16,

    /// Unproven tree being processed
    tree: ?UnprovenTree,

    /// Initialize prover with secrets
    pub fn init(secrets: []const PrivateInput) Prover {
        assert(secrets.len <= MAX_SECRETS);

        var prover = Prover{
            .secrets = [_]?PrivateInput{null} ** MAX_SECRETS,
            .secret_count = @intCast(secrets.len),
            .rng_state = .{ 0x853c49e6748fea9b, 0xda3e39cb94b95bdb }, // Default seed
            .work_stack = undefined,
            .work_sp = 0,
            .tree = null,
        };

        for (secrets, 0..) |s, i| {
            prover.secrets[i] = s;
        }

        return prover;
    }

    /// Initialize with custom RNG seed
    pub fn initWithSeed(secrets: []const PrivateInput, seed: u64) Prover {
        var prover = init(secrets);
        // Mix seed into RNG state
        prover.rng_state[0] = seed ^ 0x853c49e6748fea9b;
        prover.rng_state[1] = (seed *% 0x5851f42d4c957f2d) ^ 0xda3e39cb94b95bdb;
        return prover;
    }

    /// Generate random scalar using xorshift128+
    fn randomScalar(self: *Prover) !Scalar {
        var bytes: [32]u8 = undefined;

        // Generate 4 random u64s
        for (0..4) |i| {
            const rand = self.xorshift128plus();
            std.mem.writeInt(u64, bytes[i * 8 ..][0..8], rand, .little);
        }

        return Scalar.fromBytes(bytes) catch return error.InvalidScalar;
    }

    /// xorshift128+ RNG
    fn xorshift128plus(self: *Prover) u64 {
        var s1 = self.rng_state[0];
        const s0 = self.rng_state[1];
        self.rng_state[0] = s0;
        s1 ^= s1 << 23;
        self.rng_state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
        return self.rng_state[1] +% s0;
    }

    /// Generate random challenge for simulated nodes
    fn randomChallenge(self: *Prover) Challenge {
        var bytes: [SOUNDNESS_BYTES]u8 = undefined;

        // Generate 3 random u64s (24 bytes)
        for (0..3) |i| {
            const rand = self.xorshift128plus();
            std.mem.writeInt(u64, bytes[i * 8 ..][0..8], rand, .little);
        }

        return Challenge{ .bytes = bytes };
    }

    /// Find secret for a given SigmaBoolean leaf
    fn findSecret(self: *const Prover, sb: SigmaBoolean) ?PrivateInput {
        for (self.secrets[0..self.secret_count]) |maybe_secret| {
            if (maybe_secret) |secret| {
                if (secret.matches(sb)) {
                    return secret;
                }
            }
        }
        return null;
    }

    // ========================================================================
    // Step 1: markReal - Mark nodes where we have secrets
    // ========================================================================

    /// Mark nodes as real (not simulated) if we have the secret
    /// A node is real if:
    /// - Leaf: we have the secret for that proposition
    /// - AND: ALL children are real
    /// - OR: at least ONE child is real
    /// - THRESHOLD(k,n): at least k children are real
    pub fn markReal(self: *Prover, tree: *UnprovenTree) void {
        // Use iterative post-order traversal
        self.work_sp = 0;
        self.pushWork(.{ .node = tree, .phase = .descend });

        while (self.work_sp > 0) {
            const work = self.popWork();

            switch (work.phase) {
                .descend => {
                    switch (work.node.*) {
                        .leaf => |leaf| {
                            // Leaf: check if we have the secret
                            const prop = leaf.proposition();
                            const has_secret = self.findSecret(prop) != null;
                            work.node.* = work.node.withSimulated(!has_secret);
                        },
                        .conjecture => |*conj| {
                            // Push self for compute phase, then children
                            self.pushWork(.{ .node = work.node, .phase = .compute });

                            // Push children in reverse order (so first child is processed first)
                            var i: usize = conj.childCount();
                            while (i > 0) {
                                i -= 1;
                                switch (conj.*) {
                                    .cand => |*c| {
                                        if (c.children[i]) |*child| {
                                            self.pushWork(.{ .node = child, .phase = .descend });
                                        }
                                    },
                                    .cor => |*c| {
                                        if (c.children[i]) |*child| {
                                            self.pushWork(.{ .node = child, .phase = .descend });
                                        }
                                    },
                                    .cthreshold => |*c| {
                                        if (c.children[i]) |*child| {
                                            self.pushWork(.{ .node = child, .phase = .descend });
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
                .compute => {
                    // Children have been processed, now compute this node's real status
                    switch (work.node.*) {
                        .leaf => {}, // Already handled in descend
                        .conjecture => |*conj| {
                            const is_real = switch (conj.*) {
                                .cand => |c| self.allChildrenReal(&c),
                                .cor => |c| self.anyChildReal(&c),
                                .cthreshold => |c| self.kChildrenReal(&c),
                            };
                            work.node.* = work.node.withSimulated(!is_real);
                        },
                    }
                },
            }
        }
    }

    fn allChildrenReal(self: *const Prover, cand: *const CandUnproven) bool {
        _ = self;
        for (cand.children[0..cand.child_count]) |maybe_child| {
            if (maybe_child) |child| {
                if (child.simulated()) return false;
            }
        }
        return true;
    }

    fn anyChildReal(self: *const Prover, cor: *const CorUnproven) bool {
        _ = self;
        for (cor.children[0..cor.child_count]) |maybe_child| {
            if (maybe_child) |child| {
                if (child.isReal()) return true;
            }
        }
        return false;
    }

    fn kChildrenReal(self: *const Prover, ct: *const CthresholdUnproven) bool {
        _ = self;
        var real_count: u8 = 0;
        for (ct.children[0..ct.child_count]) |maybe_child| {
            if (maybe_child) |child| {
                if (child.isReal()) {
                    real_count += 1;
                    if (real_count >= ct.k) return true;
                }
            }
        }
        return false;
    }

    // ========================================================================
    // Step 3: polishSimulated - Ensure proper simulated child counts
    // ========================================================================

    /// For OR nodes: mark all but one real child as simulated
    /// For THRESHOLD(k,n): mark all but k real children as simulated
    /// This ensures proper challenge distribution
    pub fn polishSimulated(self: *Prover, tree: *UnprovenTree) void {
        self.work_sp = 0;
        self.pushWork(.{ .node = tree, .phase = .descend });

        while (self.work_sp > 0) {
            const work = self.popWork();

            switch (work.node.*) {
                .leaf => {}, // Nothing to polish for leaves
                .conjecture => |*conj| {
                    switch (conj.*) {
                        .cand => |*c| {
                            // AND: recurse into children
                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                        .cor => |*c| {
                            // OR: keep only ONE real child, make rest simulated
                            var found_real = false;
                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    if (child.isReal()) {
                                        if (found_real) {
                                            // Already found one real, make this simulated
                                            child.* = child.withSimulated(true);
                                        } else {
                                            found_real = true;
                                        }
                                    }
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                        .cthreshold => |*c| {
                            // THRESHOLD(k,n): keep only k real children
                            var real_count: u8 = 0;
                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    if (child.isReal()) {
                                        real_count += 1;
                                        if (real_count > c.k) {
                                            // Exceeded k, make this simulated
                                            child.* = child.withSimulated(true);
                                        }
                                    }
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                    }
                },
            }
        }
    }

    // ========================================================================
    // Steps 4-6: simulateAndCommit
    // ========================================================================

    /// Compute commitments and challenges:
    /// - Simulated leaves: generate random challenge, compute fake commitment
    /// - Real leaves: generate random r, compute commitment a = g^r
    /// - Simulated conjectures: generate random challenge
    pub fn simulateAndCommit(self: *Prover, tree: *UnprovenTree) ProverError!void {
        self.work_sp = 0;
        self.pushWork(.{ .node = tree, .phase = .descend });

        while (self.work_sp > 0) {
            const work = self.popWork();

            switch (work.node.*) {
                .leaf => |*leaf| {
                    switch (leaf.*) {
                        .schnorr => |*s| {
                            if (s.simulated) {
                                // Simulated: generate random challenge, will compute fake response later
                                s.challenge_opt = self.randomChallenge();
                            } else {
                                // Real: generate random r and commitment a = g^r
                                const r = self.randomScalar() catch return error.RandomFailed;
                                const g = Point.generator();
                                const a = g.mul(r);
                                s.randomness_opt = r;
                                s.commitment_opt = .{ .a = a };
                            }
                        },
                        .dh_tuple => |*d| {
                            if (d.simulated) {
                                d.challenge_opt = self.randomChallenge();
                            } else {
                                // Real: generate random r, compute a = g^r, b = h^r
                                const r = self.randomScalar() catch return error.RandomFailed;
                                const g = Point.decode(&d.proposition.g) catch return error.InvalidPoint;
                                const h = Point.decode(&d.proposition.h) catch return error.InvalidPoint;
                                const a = g.mul(r);
                                const b = h.mul(r);
                                d.randomness_opt = r;
                                d.commitment_opt = .{ .a = a, .b = b };
                            }
                        },
                    }
                },
                .conjecture => |*conj| {
                    // Process children first
                    const child_count = conj.childCount();
                    var i: usize = child_count;
                    while (i > 0) {
                        i -= 1;
                        switch (conj.*) {
                            .cand => |*c| {
                                if (c.children[i]) |*child| {
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            },
                            .cor => |*c| {
                                if (c.children[i]) |*child| {
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            },
                            .cthreshold => |*c| {
                                if (c.children[i]) |*child| {
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            },
                        }
                    }
                },
            }
        }
    }

    // ========================================================================
    // Step 7: Fiat-Shamir serialization (for challenge computation)
    // ========================================================================

    /// Serialize tree with commitments for Fiat-Shamir challenge
    pub fn serializeForFiatShamir(self: *const Prover, tree: *const UnprovenTree, buffer: []u8) ProverError![]u8 {
        _ = self;
        var pos: usize = 0;

        // Use iterative serialization with explicit stack
        var stack: [MAX_TREE_DEPTH]SerializeState = undefined;
        var sp: usize = 0;

        stack[sp] = .{ .node = tree, .child_idx = 0 };
        sp += 1;

        while (sp > 0) {
            sp -= 1;
            const state = stack[sp];

            switch (state.node.*) {
                .leaf => |leaf| {
                    // Serialize leaf: prefix + proposition + commitment
                    if (pos + 200 > buffer.len) return error.BufferTooSmall;

                    buffer[pos] = challenge_mod.LEAF_PREFIX;
                    pos += 1;

                    // Serialize proposition
                    switch (leaf) {
                        .schnorr => |s| {
                            // ProveDlog: 0x08cd || pk
                            buffer[pos] = 0x00;
                            buffer[pos + 1] = 35; // length = 35
                            pos += 2;
                            buffer[pos] = 0x08;
                            buffer[pos + 1] = 0xcd;
                            @memcpy(buffer[pos + 2 .. pos + 35], &s.proposition.public_key);
                            pos += 35;

                            // Commitment (33 bytes)
                            if (s.commitment_opt) |commit| {
                                buffer[pos] = 0x00;
                                buffer[pos + 1] = 33;
                                pos += 2;
                                var encoded: [33]u8 = undefined;
                                commit.a.encode(&encoded);
                                @memcpy(buffer[pos .. pos + 33], &encoded);
                                pos += 33;
                            } else {
                                return error.CommitmentFailed;
                            }
                        },
                        .dh_tuple => |d| {
                            // ProveDHTuple: header + 4 points
                            buffer[pos] = 0x00;
                            buffer[pos + 1] = 134;
                            pos += 2;
                            buffer[pos] = 0x08;
                            buffer[pos + 1] = 0xce;
                            @memcpy(buffer[pos + 2 .. pos + 35], &d.proposition.g);
                            @memcpy(buffer[pos + 35 .. pos + 68], &d.proposition.h);
                            @memcpy(buffer[pos + 68 .. pos + 101], &d.proposition.u);
                            @memcpy(buffer[pos + 101 .. pos + 134], &d.proposition.v);
                            pos += 134;

                            // Commitment (66 bytes)
                            if (d.commitment_opt) |commit| {
                                buffer[pos] = 0x00;
                                buffer[pos + 1] = 66;
                                pos += 2;
                                var a_encoded: [33]u8 = undefined;
                                var b_encoded: [33]u8 = undefined;
                                commit.a.encode(&a_encoded);
                                commit.b.encode(&b_encoded);
                                @memcpy(buffer[pos .. pos + 33], &a_encoded);
                                @memcpy(buffer[pos + 33 .. pos + 66], &b_encoded);
                                pos += 66;
                            } else {
                                return error.CommitmentFailed;
                            }
                        },
                    }
                },
                .conjecture => |conj| {
                    // Internal node: prefix + type + num_children + children
                    if (pos + 10 > buffer.len) return error.BufferTooSmall;

                    buffer[pos] = challenge_mod.INTERNAL_NODE_PREFIX;
                    pos += 1;

                    // Extract conjecture type and children based on variant
                    const conj_type: challenge_mod.ConjectureType = switch (conj) {
                        .cand => .and_connective,
                        .cor => .or_connective,
                        .cthreshold => .threshold,
                    };
                    const child_count: u8 = switch (conj) {
                        .cand => |c| c.child_count,
                        .cor => |c| c.child_count,
                        .cthreshold => |c| c.child_count,
                    };

                    buffer[pos] = @intFromEnum(conj_type);
                    pos += 1;

                    // For threshold, also write k
                    if (conj == .cthreshold) {
                        buffer[pos] = conj.cthreshold.k;
                        pos += 1;
                    }

                    // Write number of children
                    buffer[pos] = child_count;
                    pos += 1;

                    // Push children onto stack (in reverse order)
                    var i: usize = child_count;
                    while (i > 0) {
                        i -= 1;
                        const maybe_child = switch (conj) {
                            .cand => |c| c.children[i],
                            .cor => |c| c.children[i],
                            .cthreshold => |c| c.children[i],
                        };
                        if (maybe_child) |*child| {
                            if (sp >= MAX_TREE_DEPTH) return error.TreeTooDeep;
                            stack[sp] = .{ .node = child, .child_idx = 0 };
                            sp += 1;
                        }
                    }
                },
            }
        }

        return buffer[0..pos];
    }

    // ========================================================================
    // Step 8: Compute root challenge
    // ========================================================================

    /// Compute root challenge using Fiat-Shamir
    pub fn computeRootChallenge(self: *const Prover, tree: *const UnprovenTree, message: []const u8) ProverError!Challenge {
        var fs_buffer: [4096]u8 = undefined;
        const tree_bytes = try self.serializeForFiatShamir(tree, &fs_buffer);
        return challenge_mod.computeChallenge(tree_bytes, message);
    }

    // ========================================================================
    // Step 9: proving - Compute responses
    // ========================================================================

    /// Distribute challenge through tree and compute responses
    pub fn proving(self: *Prover, tree: *UnprovenTree, root_challenge: Challenge) ProverError!void {
        // Set root challenge
        tree.* = tree.withChallenge(root_challenge);

        // Distribute challenges through tree (top-down)
        self.work_sp = 0;
        self.pushWork(.{ .node = tree, .phase = .descend });

        while (self.work_sp > 0) {
            const work = self.popWork();

            switch (work.node.*) {
                .leaf => |*leaf| {
                    // Leaf: compute response if real
                    const node_challenge = work.node.challenge() orelse return error.ChallengeFailed;

                    switch (leaf.*) {
                        .schnorr => |*s| {
                            if (!s.simulated) {
                                // Real: z = r + e*x (mod q)
                                const r = s.randomness_opt orelse return error.ResponseFailed;
                                const e = challengeToScalar(node_challenge);
                                const prop = SigmaBoolean{ .prove_dlog = s.proposition };
                                const secret = self.findSecret(prop) orelse return error.MissingSecret;
                                const x = switch (secret) {
                                    .dlog => |d| d.w,
                                    else => return error.MissingSecret,
                                };
                                // z = r + e * x
                                const ex = e.mul(x);
                                const z = r.add(ex);
                                s.challenge_opt = node_challenge;
                                s.response_opt = z;
                            }
                        },
                        .dh_tuple => |*d| {
                            if (!d.simulated) {
                                const r = d.randomness_opt orelse return error.ResponseFailed;
                                const e = challengeToScalar(node_challenge);
                                const prop = SigmaBoolean{ .prove_dh_tuple = d.proposition };
                                const secret = self.findSecret(prop) orelse return error.MissingSecret;
                                const x = switch (secret) {
                                    .dh_tuple => |dh| dh.w,
                                    else => return error.MissingSecret,
                                };
                                const ex = e.mul(x);
                                const z = r.add(ex);
                                d.challenge_opt = node_challenge;
                                d.response_opt = z;
                            }
                        },
                    }
                },
                .conjecture => |*conj| {
                    const parent_challenge = work.node.challenge() orelse return error.ChallengeFailed;

                    switch (conj.*) {
                        .cand => |*c| {
                            // AND: all children get same challenge as parent
                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    child.* = child.withChallenge(parent_challenge);
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                        .cor => |*c| {
                            // OR: simulated children already have challenges,
                            // real child gets parent XOR sum(simulated)
                            var simulated_xor = Challenge.zero;
                            var real_child: ?*UnprovenTree = null;

                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    if (child.simulated()) {
                                        const child_challenge = child.challenge() orelse return error.ChallengeFailed;
                                        simulated_xor = simulated_xor.xor(child_challenge);
                                    } else {
                                        real_child = child;
                                    }
                                }
                            }

                            if (real_child) |rc| {
                                const real_challenge = parent_challenge.xor(simulated_xor);
                                rc.* = rc.withChallenge(real_challenge);
                            }

                            // Push all children for processing
                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                        .cthreshold => |*c| {
                            // THRESHOLD: more complex, uses polynomial interpolation
                            // For now, treat similarly to OR
                            var simulated_xor = Challenge.zero;

                            for (c.children[0..c.child_count]) |*maybe_child| {
                                if (maybe_child.*) |*child| {
                                    if (child.simulated()) {
                                        const child_challenge = child.challenge() orelse return error.ChallengeFailed;
                                        simulated_xor = simulated_xor.xor(child_challenge);
                                    } else {
                                        // Real children share the remaining challenge
                                        const real_challenge = parent_challenge.xor(simulated_xor);
                                        child.* = child.withChallenge(real_challenge);
                                    }
                                    self.pushWork(.{ .node = child, .phase = .descend });
                                }
                            }
                        },
                    }
                },
            }
        }
    }

    // ========================================================================
    // Main Entry Point
    // ========================================================================

    /// Prove a SigmaBoolean proposition
    pub fn prove(self: *Prover, proposition: SigmaBoolean, message: []const u8) ProverError!Proof {
        // Handle trivial cases
        switch (proposition) {
            .trivial_true => {
                // TrivialTrue: empty proof
                return Proof{ .bytes = [_]u8{0} ** 1024, .len = 0 };
            },
            .trivial_false => {
                // TrivialFalse: cannot prove
                return error.RootNotReal;
            },
            else => {},
        }

        // Convert to UnprovenTree
        var tree = unproven_tree.convertToUnproven(proposition);
        self.tree = tree;

        // Step 1: Mark real nodes
        self.markReal(&tree);

        // Step 2: Check root is real
        if (tree.simulated()) {
            return error.RootNotReal;
        }

        // Step 3: Polish simulated (ensure proper counts)
        self.polishSimulated(&tree);

        // Steps 4-6: Compute commitments
        try self.simulateAndCommit(&tree);

        // Step 7-8: Compute root challenge via Fiat-Shamir
        const root_challenge = try self.computeRootChallenge(&tree, message);

        // Step 9: Compute responses
        try self.proving(&tree, root_challenge);

        // Serialize proof
        return self.serializeProof(&tree);
    }

    /// Serialize the proven tree to bytes
    fn serializeProof(self: *const Prover, tree: *const UnprovenTree) ProverError!Proof {
        var proof = Proof{ .bytes = [_]u8{0} ** 1024, .len = 0 };
        var pos: usize = 0;

        // Use iterative serialization
        var stack: [MAX_TREE_DEPTH]SerializeState = undefined;
        var sp: usize = 0;

        stack[sp] = .{ .node = tree, .child_idx = 0 };
        sp += 1;

        while (sp > 0) {
            sp -= 1;
            const state = stack[sp];

            switch (state.node.*) {
                .leaf => |leaf| {
                    switch (leaf) {
                        .schnorr => |s| {
                            // Write challenge (24 bytes) + response (32 bytes)
                            if (pos + SOUNDNESS_BYTES + 32 > proof.bytes.len) {
                                return error.BufferTooSmall;
                            }
                            if (s.challenge_opt) |ch| {
                                @memcpy(proof.bytes[pos .. pos + SOUNDNESS_BYTES], &ch.bytes);
                                pos += SOUNDNESS_BYTES;
                            }
                            // Response z = r + e*x (mod q)
                            if (s.response_opt) |z| {
                                const z_bytes = z.toBytes();
                                @memcpy(proof.bytes[pos .. pos + 32], &z_bytes);
                                pos += 32;
                            }
                        },
                        .dh_tuple => |d| {
                            if (pos + SOUNDNESS_BYTES + 32 > proof.bytes.len) {
                                return error.BufferTooSmall;
                            }
                            if (d.challenge_opt) |ch| {
                                @memcpy(proof.bytes[pos .. pos + SOUNDNESS_BYTES], &ch.bytes);
                                pos += SOUNDNESS_BYTES;
                            }
                            if (d.response_opt) |z| {
                                const z_bytes = z.toBytes();
                                @memcpy(proof.bytes[pos .. pos + 32], &z_bytes);
                                pos += 32;
                            }
                        },
                    }
                },
                .conjecture => |conj| {
                    // Write challenge for this node
                    if (pos + SOUNDNESS_BYTES > proof.bytes.len) {
                        return error.BufferTooSmall;
                    }

                    const node_challenge = state.node.challenge();
                    if (node_challenge) |ch| {
                        @memcpy(proof.bytes[pos .. pos + SOUNDNESS_BYTES], &ch.bytes);
                        pos += SOUNDNESS_BYTES;
                    }

                    // Push children
                    const child_count: u8 = switch (conj) {
                        .cand => |c| c.child_count,
                        .cor => |c| c.child_count,
                        .cthreshold => |c| c.child_count,
                    };

                    var i: usize = child_count;
                    while (i > 0) {
                        i -= 1;
                        const maybe_child = switch (conj) {
                            .cand => |c| c.children[i],
                            .cor => |c| c.children[i],
                            .cthreshold => |c| c.children[i],
                        };
                        if (maybe_child) |*child| {
                            if (sp >= MAX_TREE_DEPTH) return error.TreeTooDeep;
                            stack[sp] = .{ .node = child, .child_idx = 0 };
                            sp += 1;
                        }
                    }
                },
            }
        }

        proof.len = @intCast(pos);
        _ = self;
        return proof;
    }

    // ========================================================================
    // Work Stack Management
    // ========================================================================

    const WorkPhase = enum { descend, compute };

    const WorkItem = struct {
        node: *UnprovenTree,
        phase: WorkPhase,
    };

    const SerializeState = struct {
        node: *const UnprovenTree,
        child_idx: u8,
    };

    fn pushWork(self: *Prover, item: WorkItem) void {
        assert(self.work_sp < self.work_stack.len);
        self.work_stack[self.work_sp] = item;
        self.work_sp += 1;
    }

    fn popWork(self: *Prover) WorkItem {
        assert(self.work_sp > 0);
        self.work_sp -= 1;
        return self.work_stack[self.work_sp];
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 24-byte challenge to Scalar
fn challengeToScalar(challenge: Challenge) Scalar {
    // Zero-pad 24 bytes to 32 bytes (big-endian)
    var scalar_bytes: [32]u8 = [_]u8{0} ** 32;
    @memcpy(scalar_bytes[8..32], &challenge.bytes);

    // This should not fail since 192-bit < curve order
    return Scalar.fromBytes(scalar_bytes) catch unreachable;
}

// ============================================================================
// Tests
// ============================================================================

test "Prover: init with secrets" {
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 1;

    const dlog_input = try DlogProverInput.init(secret);
    const private = PrivateInput{ .dlog = dlog_input };

    const prover = Prover.init(&[_]PrivateInput{private});
    try std.testing.expectEqual(@as(u8, 1), prover.secret_count);
}

test "Prover: random scalar generation" {
    const prover_ptr = &Prover.init(&[_]PrivateInput{});
    var prover = prover_ptr.*;

    const s1 = try prover.randomScalar();
    const s2 = try prover.randomScalar();

    // Should be different (with overwhelming probability)
    try std.testing.expect(!std.mem.eql(u8, &s1.toBytes(), &s2.toBytes()));
}

test "Prover: random challenge generation" {
    const prover_ptr = &Prover.init(&[_]PrivateInput{});
    var prover = prover_ptr.*;

    const c1 = prover.randomChallenge();
    const c2 = prover.randomChallenge();

    try std.testing.expect(!c1.eql(c2));
}

test "Prover: markReal for ProveDlog with matching secret" {
    var secret: [32]u8 = [_]u8{0} ** 32;
    secret[31] = 42;

    const dlog_input = try DlogProverInput.init(secret);
    const pub_image = dlog_input.publicImage();

    const private = PrivateInput{ .dlog = dlog_input };
    var prover = Prover.init(&[_]PrivateInput{private});

    const prop = SigmaBoolean{ .prove_dlog = pub_image };
    var tree = unproven_tree.convertToUnproven(prop);

    // Initially simulated
    try std.testing.expect(tree.simulated());

    // After markReal, should be real
    prover.markReal(&tree);
    try std.testing.expect(tree.isReal());
}

test "Prover: markReal for ProveDlog without secret" {
    // Create a random public key we don't have the secret for
    const pk = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    const prop = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk) };
    var tree = unproven_tree.convertToUnproven(prop);

    var prover = Prover.init(&[_]PrivateInput{});
    prover.markReal(&tree);

    // Should remain simulated (no secret)
    try std.testing.expect(tree.simulated());
}

test "Prover: challengeToScalar" {
    const challenge = Challenge{ .bytes = [_]u8{0xFF} ** SOUNDNESS_BYTES };
    const scalar = challengeToScalar(challenge);

    // Top 8 bytes should be zero
    const bytes = scalar.toBytes();
    try std.testing.expect(std.mem.eql(u8, bytes[0..8], &[_]u8{0} ** 8));
    // Bottom 24 bytes should be all 0xFF
    try std.testing.expect(std.mem.eql(u8, bytes[8..32], &[_]u8{0xFF} ** 24));
}

test "Prover: xorshift128plus produces different values" {
    var prover = Prover.init(&[_]PrivateInput{});

    const v1 = prover.xorshift128plus();
    const v2 = prover.xorshift128plus();
    const v3 = prover.xorshift128plus();

    try std.testing.expect(v1 != v2);
    try std.testing.expect(v2 != v3);
    try std.testing.expect(v1 != v3);
}
