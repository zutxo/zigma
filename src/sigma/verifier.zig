//! Sigma Protocol Verifier
//!
//! Implements verification for Sigma protocol proofs including:
//! - ProveDlog (Schnorr signatures)
//! - ProveDHTuple (Chaum-Pedersen proofs)
//! - AND/OR/THRESHOLD connectives
//!
//! Verification Algorithm:
//! 1. Parse signature bytes, compute challenges via tree traversal
//! 2. For each leaf, compute commitment from challenge + response
//! 3. Serialize tree with commitments (Fiat-Shamir)
//! 4. Verify root challenge = H(tree_bytes || message)
//!
//! Reference: sigmastate/src/main/scala/sigmastate/interpreter/Interpreter.scala

const std = @import("std");
const assert = std.debug.assert;
const secp256k1 = @import("../crypto/secp256k1.zig");
const challenge_mod = @import("challenge.zig");
const sigma_tree = @import("sigma_tree.zig");
const schnorr = @import("schnorr.zig");

const Point = secp256k1.Point;
const Challenge = challenge_mod.Challenge;
const SigmaBoolean = sigma_tree.SigmaBoolean;
const ProveDlog = sigma_tree.ProveDlog;
const ProveDHTuple = sigma_tree.ProveDHTuple;
const SOUNDNESS_BYTES = challenge_mod.SOUNDNESS_BYTES;
const SCALAR_SIZE = challenge_mod.SCALAR_SIZE;
const GROUP_SIZE = challenge_mod.GROUP_SIZE;

// ============================================================================
// Verifier Errors
// ============================================================================

pub const VerifierError = error{
    /// Proof is empty for non-trivial proposition
    EmptyProof,
    /// Proof bytes insufficient for parsing
    InsufficientProofBytes,
    /// Challenge parsing failed
    InvalidChallenge,
    /// Response parsing failed
    InvalidResponse,
    /// Point decoding failed
    InvalidPoint,
    /// Commitment verification failed
    CommitmentMismatch,
    /// Root challenge doesn't match expected
    RootChallengeMismatch,
    /// Unsupported proposition type
    UnsupportedProposition,
    /// Buffer too small for tree serialization
    BufferTooSmall,
    /// Memory allocation failed
    OutOfMemory,
};

// ============================================================================
// Unchecked Proof Tree
// ============================================================================

/// Maximum proof tree depth
pub const MAX_PROOF_DEPTH: usize = 32;

/// Maximum children in AND/OR/THRESHOLD
pub const MAX_CHILDREN: usize = 16;

/// Unchecked Schnorr proof leaf
pub const UncheckedSchnorr = struct {
    proposition: ProveDlog,
    challenge: Challenge,
    response: [SCALAR_SIZE]u8,
    /// Computed commitment (filled in during verification)
    commitment: ?Point,
};

/// Unchecked DH tuple proof leaf
pub const UncheckedDHTuple = struct {
    proposition: ProveDHTuple,
    challenge: Challenge,
    response: [SCALAR_SIZE]u8,
    /// Computed commitments (filled in during verification)
    commitment_a: ?Point,
    commitment_b: ?Point,
};

/// Unchecked proof tree node
pub const UncheckedTree = union(enum) {
    /// Trivially true (no proof needed)
    trivial_true: void,
    /// Trivially false (invalid)
    trivial_false: void,
    /// Schnorr proof
    schnorr: UncheckedSchnorr,
    /// DH tuple proof
    dh_tuple: UncheckedDHTuple,
    /// AND node
    cand: struct {
        challenge: Challenge,
        children: []UncheckedTree,
    },
    /// OR node
    cor: struct {
        challenge: Challenge,
        children: []UncheckedTree,
    },
    /// THRESHOLD node
    cthreshold: struct {
        challenge: Challenge,
        k: u8,
        children: []UncheckedTree,
        /// Polynomial coefficients (n-k coefficients, each SOUNDNESS_BYTES)
        polynomial_coeffs: []const u8,
    },

    /// Get the challenge for this node
    pub fn getChallenge(self: UncheckedTree) Challenge {
        return switch (self) {
            .trivial_true, .trivial_false => Challenge.zero,
            .schnorr => |s| s.challenge,
            .dh_tuple => |d| d.challenge,
            .cand => |a| a.challenge,
            .cor => |o| o.challenge,
            .cthreshold => |t| t.challenge,
        };
    }
};

// ============================================================================
// Proof Parsing (Verifier Steps 1-3)
// ============================================================================

/// Proof reader for parsing signature bytes
pub const ProofReader = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) ProofReader {
        return .{ .data = data, .pos = 0 };
    }

    /// Read exactly n bytes
    pub fn read(self: *ProofReader, n: usize) VerifierError![]const u8 {
        if (self.pos + n > self.data.len) return error.InsufficientProofBytes;
        const slice = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    /// Read a challenge (24 bytes)
    pub fn readChallenge(self: *ProofReader) VerifierError!Challenge {
        const bytes = try self.read(SOUNDNESS_BYTES);
        return Challenge.fromSlice(bytes) catch error.InvalidChallenge;
    }

    /// Read a response (32 bytes scalar)
    pub fn readResponse(self: *ProofReader) VerifierError![SCALAR_SIZE]u8 {
        const bytes = try self.read(SCALAR_SIZE);
        var result: [SCALAR_SIZE]u8 = undefined;
        @memcpy(&result, bytes);
        return result;
    }

    /// Check if more data is available
    pub fn hasMore(self: ProofReader) bool {
        return self.pos < self.data.len;
    }
};

/// Parse proof and compute challenges for ProveDlog
/// Verifier Steps 1-3: Parse proof, distribute challenges, read responses
pub fn parseSchnorrProof(
    proposition: ProveDlog,
    reader: *ProofReader,
    challenge_opt: ?Challenge,
) VerifierError!UncheckedSchnorr {
    // Step 2: Get challenge (either from parent or read from proof)
    const challenge = challenge_opt orelse try reader.readChallenge();

    // Step 3: Read response z
    const response = try reader.readResponse();

    return UncheckedSchnorr{
        .proposition = proposition,
        .challenge = challenge,
        .response = response,
        .commitment = null, // Will be computed in Step 4
    };
}

/// Parse proof for an AND node
/// All children get the same challenge as the parent
pub fn parseAndProof(
    children: []const *const SigmaBoolean,
    reader: *ProofReader,
    challenge_opt: ?Challenge,
    allocator: std.mem.Allocator,
) VerifierError!UncheckedTree {
    const challenge = challenge_opt orelse try reader.readChallenge();

    var parsed_children = try allocator.alloc(UncheckedTree, children.len);
    errdefer allocator.free(parsed_children);

    // AND: all children get the same challenge
    for (children, 0..) |child, i| {
        parsed_children[i] = try parseProofTree(child.*, reader, challenge, allocator);
    }

    return UncheckedTree{
        .cand = .{
            .challenge = challenge,
            .children = parsed_children,
        },
    };
}

/// Parse proof for an OR node
/// Each child except the last has its challenge read from proof.
/// Last child's challenge = parent_challenge XOR (XOR of all other challenges)
pub fn parseOrProof(
    children: []const *const SigmaBoolean,
    reader: *ProofReader,
    challenge_opt: ?Challenge,
    allocator: std.mem.Allocator,
) VerifierError!UncheckedTree {
    const challenge = challenge_opt orelse try reader.readChallenge();

    if (children.len == 0) return error.UnsupportedProposition;

    var parsed_children = try allocator.alloc(UncheckedTree, children.len);
    errdefer allocator.free(parsed_children);

    // OR: read challenges for all but last, compute last via XOR
    var xored = challenge;

    for (0..children.len - 1) |i| {
        // Each child except last reads its own challenge
        parsed_children[i] = try parseProofTree(children[i].*, reader, null, allocator);
        xored = xored.xor(parsed_children[i].getChallenge());
    }

    // Last child's challenge is XOR of all others with parent
    const last_idx = children.len - 1;
    parsed_children[last_idx] = try parseProofTree(children[last_idx].*, reader, xored, allocator);

    return UncheckedTree{
        .cor = .{
            .challenge = challenge,
            .children = parsed_children,
        },
    };
}

/// Parse proof tree recursively
pub fn parseProofTree(
    prop: SigmaBoolean,
    reader: *ProofReader,
    challenge_opt: ?Challenge,
    allocator: std.mem.Allocator,
) VerifierError!UncheckedTree {
    return switch (prop) {
        .trivial_true => .trivial_true,
        .trivial_false => .trivial_false,
        .prove_dlog => |dlog| .{ .schnorr = try parseSchnorrProof(dlog, reader, challenge_opt) },
        .prove_dh_tuple => error.UnsupportedProposition, // TODO: Phase 6.5
        .cand => |and_node| try parseAndProof(and_node.children, reader, challenge_opt, allocator),
        .cor => |or_node| try parseOrProof(or_node.children, reader, challenge_opt, allocator),
        .cthreshold => error.UnsupportedProposition, // TODO: Phase 6.5
    };
}

// ============================================================================
// Commitment Computation (Verifier Step 4)
// ============================================================================

/// Compute commitment for a Schnorr proof leaf
/// a = g^z * h^(-e)
fn computeSchnorrCommitment(unchecked: *UncheckedSchnorr) VerifierError!void {
    const commitment = schnorr.computeCommitment(
        unchecked.proposition,
        unchecked.challenge,
        schnorr.SecondMessage{ .z = unchecked.response },
    ) catch return error.CommitmentMismatch;

    unchecked.commitment = commitment;
}

/// Compute commitments for all leaves in the tree
pub fn computeCommitments(tree: *UncheckedTree) VerifierError!void {
    switch (tree.*) {
        .trivial_true, .trivial_false => {},
        .schnorr => |*s| try computeSchnorrCommitment(s),
        .dh_tuple => return error.UnsupportedProposition,
        .cand => |*and_node| {
            for (and_node.children) |*child| {
                try computeCommitments(child);
            }
        },
        .cor => |*or_node| {
            for (or_node.children) |*child| {
                try computeCommitments(child);
            }
        },
        .cthreshold => return error.UnsupportedProposition,
    }
}

// ============================================================================
// Full Verification
// ============================================================================

/// Verify a signature against a SigmaBoolean proposition
/// Returns true if the signature is valid
pub fn verifySignature(
    proposition: SigmaBoolean,
    signature: []const u8,
    message: []const u8,
    allocator: std.mem.Allocator,
) VerifierError!bool {
    // Handle trivial propositions
    switch (proposition) {
        .trivial_true => return true,
        .trivial_false => return false,
        else => {},
    }

    // Non-trivial proposition requires a signature
    if (signature.len == 0) return error.EmptyProof;

    // Step 1-3: Parse proof and compute challenges
    var reader = ProofReader.init(signature);
    var tree = try parseProofTree(proposition, &reader, null, allocator);

    // Step 4: Compute commitments for all leaves
    try computeCommitments(&tree);

    // Step 5: Serialize tree for Fiat-Shamir
    var fs_buffer: [challenge_mod.MAX_FS_TREE_BYTES]u8 = undefined;
    const tree_bytes = try serializeForFiatShamir(&tree, &fs_buffer);

    // Step 6: Verify root challenge
    const expected_challenge = challenge_mod.computeChallenge(tree_bytes, message);
    const actual_challenge = tree.getChallenge();

    return expected_challenge.eql(actual_challenge);
}

// ============================================================================
// Fiat-Shamir Tree Serialization (for verification)
// ============================================================================

/// Serialize unchecked tree for Fiat-Shamir hash
/// Format matches FiatShamirTree.toBytes in Scala
fn serializeForFiatShamir(tree: *const UncheckedTree, buffer: []u8) VerifierError![]u8 {
    var pos: usize = 0;
    try serializeNodeForFiatShamir(tree, buffer, &pos);
    return buffer[0..pos];
}

fn serializeNodeForFiatShamir(tree: *const UncheckedTree, buffer: []u8, pos: *usize) VerifierError!void {
    switch (tree.*) {
        .trivial_true, .trivial_false => {
            // Trivial propositions shouldn't appear in proofs
            return error.UnsupportedProposition;
        },
        .schnorr => |s| {
            // Leaf: prefix + prop_len + prop_bytes + commit_len + commit_bytes
            if (pos.* + 100 > buffer.len) return error.BufferTooSmall;

            const commitment = s.commitment orelse return error.CommitmentMismatch;

            // Leaf prefix
            buffer[pos.*] = challenge_mod.LEAF_PREFIX;
            pos.* += 1;

            // Proposition bytes (ErgoTree format: 0x08cd || pk)
            const prop_len: i16 = 35;
            buffer[pos.*] = @intCast((prop_len >> 8) & 0xFF);
            buffer[pos.* + 1] = @intCast(prop_len & 0xFF);
            pos.* += 2;

            buffer[pos.*] = 0x08; // ErgoTree header v0
            buffer[pos.* + 1] = 0xcd; // SigmaProp constant opcode
            pos.* += 2;
            @memcpy(buffer[pos.* .. pos.* + 33], &s.proposition.public_key);
            pos.* += 33;

            // Commitment bytes (compressed point, 33 bytes)
            const commit_bytes = commitment.encode();
            const commit_len: i16 = 33;
            buffer[pos.*] = @intCast((commit_len >> 8) & 0xFF);
            buffer[pos.* + 1] = @intCast(commit_len & 0xFF);
            pos.* += 2;
            @memcpy(buffer[pos.* .. pos.* + 33], &commit_bytes);
            pos.* += 33;
        },
        .dh_tuple => return error.UnsupportedProposition,
        .cand => |and_node| {
            // Internal node: prefix + type + children_count + children
            if (pos.* + 10 > buffer.len) return error.BufferTooSmall;

            buffer[pos.*] = challenge_mod.INTERNAL_NODE_PREFIX;
            pos.* += 1;
            buffer[pos.*] = @intFromEnum(challenge_mod.ConjectureType.and_connective);
            pos.* += 1;

            const children_count: i16 = @intCast(and_node.children.len);
            buffer[pos.*] = @intCast((children_count >> 8) & 0xFF);
            buffer[pos.* + 1] = @intCast(children_count & 0xFF);
            pos.* += 2;

            for (and_node.children) |*child| {
                try serializeNodeForFiatShamir(child, buffer, pos);
            }
        },
        .cor => |or_node| {
            if (pos.* + 10 > buffer.len) return error.BufferTooSmall;

            buffer[pos.*] = challenge_mod.INTERNAL_NODE_PREFIX;
            pos.* += 1;
            buffer[pos.*] = @intFromEnum(challenge_mod.ConjectureType.or_connective);
            pos.* += 1;

            const children_count: i16 = @intCast(or_node.children.len);
            buffer[pos.*] = @intCast((children_count >> 8) & 0xFF);
            buffer[pos.* + 1] = @intCast(children_count & 0xFF);
            pos.* += 2;

            for (or_node.children) |*child| {
                try serializeNodeForFiatShamir(child, buffer, pos);
            }
        },
        .cthreshold => return error.UnsupportedProposition,
    }
}

// ============================================================================
// Tests
// ============================================================================

test "verifier: ProofReader reads correctly" {
    const data = [_]u8{ 1, 2, 3, 4, 5 };
    var reader = ProofReader.init(&data);

    const first = try reader.read(2);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2 }, first);

    const second = try reader.read(3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 4, 5 }, second);

    try std.testing.expect(!reader.hasMore());
    try std.testing.expectError(error.InsufficientProofBytes, reader.read(1));
}

test "verifier: trivial true returns true" {
    const result = try verifySignature(.trivial_true, &[_]u8{}, &[_]u8{}, std.testing.allocator);
    try std.testing.expect(result);
}

test "verifier: trivial false returns false" {
    const result = try verifySignature(.trivial_false, &[_]u8{}, &[_]u8{}, std.testing.allocator);
    try std.testing.expect(!result);
}

test "verifier: empty proof for non-trivial rejects" {
    const pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const prop = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk) };

    const result = verifySignature(prop, &[_]u8{}, &[_]u8{}, std.testing.allocator);
    try std.testing.expectError(error.EmptyProof, result);
}

test "verifier: UncheckedTree getChallenge" {
    const challenge = Challenge{ .bytes = [_]u8{0xAB} ** SOUNDNESS_BYTES };

    const pk = [_]u8{0x02} ++ [_]u8{0xCC} ** 32;
    const tree = UncheckedTree{
        .schnorr = .{
            .proposition = ProveDlog{ .public_key = pk },
            .challenge = challenge,
            .response = [_]u8{0} ** SCALAR_SIZE,
            .commitment = null,
        },
    };

    try std.testing.expect(tree.getChallenge().eql(challenge));
}

test "verifier: parseSchnorrProof reads challenge and response" {
    // Build a minimal proof: challenge (24 bytes) + response (32 bytes)
    var proof_bytes: [56]u8 = undefined;
    @memset(proof_bytes[0..24], 0x11); // challenge
    @memset(proof_bytes[24..56], 0x22); // response

    var reader = ProofReader.init(&proof_bytes);
    const pk = [_]u8{0x02} ++ [_]u8{0xAA} ** 32;
    const dlog = ProveDlog.init(pk);

    const result = try parseSchnorrProof(dlog, &reader, null);

    try std.testing.expectEqual(@as(u8, 0x11), result.challenge.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x22), result.response[0]);
}

test "verifier: AND node distributes same challenge to all children" {
    // For AND node with 2 children, only need response bytes (challenge inherited)
    // Structure: parent_challenge + child1_response + child2_response
    var proof_bytes: [88]u8 = undefined; // 24 + 32 + 32
    @memset(proof_bytes[0..24], 0xAA); // parent challenge
    @memset(proof_bytes[24..56], 0xBB); // child 1 response
    @memset(proof_bytes[56..88], 0xCC); // child 2 response

    const pk1 = [_]u8{0x02} ++ [_]u8{0x11} ** 32;
    const pk2 = [_]u8{0x02} ++ [_]u8{0x22} ** 32;
    const child1 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk1) };
    const child2 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk2) };
    const children = [_]*const SigmaBoolean{ &child1, &child2 };

    var reader = ProofReader.init(&proof_bytes);
    const result = try parseAndProof(&children, &reader, null, std.testing.allocator);
    defer std.testing.allocator.free(result.cand.children);

    // Both children should have the same challenge (parent's)
    const parent_challenge = result.getChallenge();
    try std.testing.expect(result.cand.children[0].getChallenge().eql(parent_challenge));
    try std.testing.expect(result.cand.children[1].getChallenge().eql(parent_challenge));
}

test "verifier: OR node XORs challenges correctly" {
    // For OR node: parent_challenge + child1_challenge + child1_response + child2_response
    // child2_challenge = parent XOR child1 (not read, computed)
    var proof_bytes: [112]u8 = undefined; // 24 + 24 + 32 + 32
    @memset(proof_bytes[0..24], 0xFF); // parent challenge (all 1s)
    @memset(proof_bytes[24..48], 0x0F); // child 1 challenge
    @memset(proof_bytes[48..80], 0xAA); // child 1 response
    @memset(proof_bytes[80..112], 0xBB); // child 2 response

    const pk1 = [_]u8{0x02} ++ [_]u8{0x11} ** 32;
    const pk2 = [_]u8{0x02} ++ [_]u8{0x22} ** 32;
    const child1 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk1) };
    const child2 = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk2) };
    const children = [_]*const SigmaBoolean{ &child1, &child2 };

    var reader = ProofReader.init(&proof_bytes);
    const result = try parseOrProof(&children, &reader, null, std.testing.allocator);
    defer std.testing.allocator.free(result.cor.children);

    const parent = result.getChallenge();
    const c1 = result.cor.children[0].getChallenge();
    const c2 = result.cor.children[1].getChallenge();

    // parent = c1 XOR c2
    try std.testing.expect(parent.eql(c1.xor(c2)));
}

// ============================================================================
// Conformance Tests (from sigmastate-interpreter SigningSpecification.scala)
// ============================================================================

/// Convert hex string to bytes
fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(hex.len * 100);
    var result: [hex.len / 2]u8 = undefined;
    for (0..hex.len / 2) |i| {
        result[i] = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch unreachable;
    }
    return result;
}

test "conformance: simple ProveDlog signature parsing" {
    // Test vector from sigmastate-interpreter SigningSpecification.scala
    // msg: 1dc01772ee0171f5f614c673e3c7fa1107a8cf727bdf5a6dadb379e93c0d1d00
    // pk: 03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8fb093fa597d8b93deb7b1
    // signature: bcb866ba434d5c77869ddcbc3f09ddd62dd2d2539bf99076674d1ae0c32338ea95581fdc18a3b66789904938ac641eba1a66d234070207a2

    const signature = comptime hexToBytes("bcb866ba434d5c77869ddcbc3f09ddd62dd2d2539bf99076674d1ae0c32338ea95581fdc18a3b66789904938ac641eba1a66d234070207a2");
    const pk = comptime hexToBytes("03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8fb093fa597d8b93deb7b1");

    // Parse the signature
    var reader = ProofReader.init(&signature);

    // Challenge is first 24 bytes
    const challenge = try reader.readChallenge();
    try std.testing.expectEqual(@as(u8, 0xbc), challenge.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xb8), challenge.bytes[1]);

    // Response is next 32 bytes
    const response = try reader.readResponse();
    try std.testing.expectEqual(@as(u8, 0x67), response[0]); // First byte of response
    try std.testing.expectEqual(@as(u8, 0xa2), response[31]); // Last byte

    // Verify we consumed all bytes
    try std.testing.expect(!reader.hasMore());

    // Verify the public key is valid
    _ = secp256k1.Point.decode(&pk) catch |e| {
        std.debug.print("Failed to decode pk: {}\n", .{e});
        return error.InvalidPoint;
    };
}

test "conformance: AND signature structure" {
    // AND signature from SigningSpecification.scala:
    // sk1 pk: 03cb0d49e4eae7e57059a3da8ac52626d26fc11330af8fb093fa597d8b93deb7b1
    // sk2 pk: 0295e7e5a54ea4c881f00ca6b889ff4c4ef2db98e0d6c5efa02bb5f0012b06a2f4
    // signature: 9b2ebb226be42df67817e9c56541de061997c3ea84e7e72dbb69edb7318d7bb525f9c16ccb1adc0ede4700a046d0a4ab1e239245460c1ba45e5637f7a2d4cc4cc460e5895125be73a2ca16091db2dcf51d3028043c2b9340

    const signature = comptime hexToBytes("9b2ebb226be42df67817e9c56541de061997c3ea84e7e72dbb69edb7318d7bb525f9c16ccb1adc0ede4700a046d0a4ab1e239245460c1ba45e5637f7a2d4cc4cc460e5895125be73a2ca16091db2dcf51d3028043c2b9340");

    // AND signature structure: challenge(24) + response1(32) + response2(32) = 88 bytes
    try std.testing.expectEqual(@as(usize, 88), signature.len);

    var reader = ProofReader.init(&signature);

    // Root challenge
    const challenge = try reader.readChallenge();
    try std.testing.expectEqual(@as(u8, 0x9b), challenge.bytes[0]);

    // Response 1
    const response1 = try reader.readResponse();
    try std.testing.expectEqual(@as(u8, 0xbb), response1[0]);

    // Response 2
    const response2 = try reader.readResponse();
    try std.testing.expectEqual(@as(u8, 0x5e), response2[0]);

    try std.testing.expect(!reader.hasMore());
}

test "conformance: OR signature structure" {
    // OR signature from SigningSpecification.scala
    // signature: ec94d2d5ef0e1e638237f53fd883c339f9771941f70020742a7dc85130aaee535c61321aa1e1367befb500256567b3e6f9c7a3720baa75ba6056305d7595748a93f23f9fc0eb9c1aaabc24acc4197030834d76d3c95ede60c5b59b4b306cd787d010e8217f34677d046646778877c669

    const signature = comptime hexToBytes("ec94d2d5ef0e1e638237f53fd883c339f9771941f70020742a7dc85130aaee535c61321aa1e1367befb500256567b3e6f9c7a3720baa75ba6056305d7595748a93f23f9fc0eb9c1aaabc24acc4197030834d76d3c95ede60c5b59b4b306cd787d010e8217f34677d046646778877c669");

    // OR signature structure: challenge(24) + child1_challenge(24) + response1(32) + response2(32) = 112 bytes
    try std.testing.expectEqual(@as(usize, 112), signature.len);

    var reader = ProofReader.init(&signature);

    // Root challenge
    const root_challenge = try reader.readChallenge();
    try std.testing.expectEqual(@as(u8, 0xec), root_challenge.bytes[0]);

    // Child 1 challenge
    const child1_challenge = try reader.readChallenge();
    try std.testing.expectEqual(@as(u8, 0x2a), child1_challenge.bytes[0]);

    // Response 1
    const response1 = try reader.readResponse();
    try std.testing.expectEqual(@as(u8, 0xf9), response1[0]);

    // Response 2
    const response2 = try reader.readResponse();
    try std.testing.expectEqual(@as(u8, 0x83), response2[0]);

    try std.testing.expect(!reader.hasMore());

    // Verify XOR property: child2_challenge = root XOR child1
    const child2_challenge = root_challenge.xor(child1_challenge);
    // This computed challenge is what would be used for child2
    try std.testing.expect(!child2_challenge.isZero());
}
