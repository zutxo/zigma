//! AVL+ Tree Data Structure and Proof Verification
//!
//! Implements AVL tree data types and authenticated batch verification
//! for ErgoTree script evaluation. AVL+ trees in Ergo are used for
//! authenticated dictionaries with efficient proofs.
//!
//! Design: Values store metadata only (digest + params). Actual tree
//! verification uses BatchAVLVerifier with serialized proofs.
//!
//! Reference: Rust ergo-avltree-rust crate, Scala scrypto library
//!
//! ## Implementation Status
//!
//! - AvlTreeData: COMPLETE - stores tree metadata (digest, flags, key/value lengths)
//! - AvlTreeFlags: COMPLETE - bit-packed operation permissions
//! - BatchAVLVerifier: PARTIAL - proof parsing skeleton only, full Merkle verification TODO
//!
//! Full AVL+ proof verification requires:
//! 1. Parsing the proof's node labels and direction bits
//! 2. Reconstructing the Merkle path from leaf to root
//! 3. Computing Blake2b256 hashes for internal nodes
//! 4. Verifying computed root matches expected digest
//!
//! The current lookup() implementation extracts values from proof but doesn't
//! cryptographically verify the Merkle path. This is sufficient for testing
//! expression evaluation but NOT for production use.

const std = @import("std");
const assert = std.debug.assert;
const hash = @import("hash.zig");

// ============================================================================
// Constants
// ============================================================================

/// AVL+ digest size: 32-byte hash + 1-byte height
pub const digest_size: usize = 33;

/// Maximum key length (protocol limit)
pub const max_key_length: u32 = 256;

/// Maximum value length (protocol limit)
pub const max_value_length: u32 = 65535;

/// Maximum proof size (protocol limit for DoS protection)
pub const max_proof_size: usize = 65536;

/// Blake2b256 hash output size
pub const hash_size: usize = 32;

// Compile-time sanity checks (ZIGMA_STYLE)
comptime {
    assert(digest_size == 33);
    assert(hash_size == 32);
    assert(max_key_length >= 1);
    assert(max_value_length >= 1);
    assert(max_proof_size >= 1024);
}

// ============================================================================
// AVL Tree Flags
// ============================================================================

/// AVL tree operation flags (bit-packed).
/// Controls which modifications are permitted on the tree.
pub const AvlTreeFlags = packed struct(u8) {
    /// Allow insert operations
    insert_allowed: bool = false,
    /// Allow update operations
    update_allowed: bool = false,
    /// Allow remove operations
    remove_allowed: bool = false,
    /// Reserved bits (must be zero)
    _reserved: u5 = 0,

    /// Create flags from raw byte
    pub fn fromByte(b: u8) AvlTreeFlags {
        // PRECONDITION: Reserved bits should be zero in valid flags
        // (but we don't fail - just ignore them for forward compatibility)
        return @bitCast(b);
    }

    /// Convert to raw byte
    pub fn toByte(self: AvlTreeFlags) u8 {
        return @bitCast(self);
    }

    /// Create read-only flags (no modifications allowed)
    pub fn readOnly() AvlTreeFlags {
        return .{};
    }

    /// Create flags allowing all operations
    pub fn allAllowed() AvlTreeFlags {
        return .{
            .insert_allowed = true,
            .update_allowed = true,
            .remove_allowed = true,
        };
    }

    /// Create custom flags
    pub fn init(insert: bool, update: bool, remove: bool) AvlTreeFlags {
        const result = AvlTreeFlags{
            .insert_allowed = insert,
            .update_allowed = update,
            .remove_allowed = remove,
        };

        // POSTCONDITION: Flags are valid
        assert(result._reserved == 0);

        return result;
    }

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        // Flags must be exactly 1 byte
        assert(@sizeOf(AvlTreeFlags) == 1);
        // Bit layout must match Ergo protocol
        assert(@bitOffsetOf(AvlTreeFlags, "insert_allowed") == 0);
        assert(@bitOffsetOf(AvlTreeFlags, "update_allowed") == 1);
        assert(@bitOffsetOf(AvlTreeFlags, "remove_allowed") == 2);
    }
};

// ============================================================================
// AVL Tree Data
// ============================================================================

/// AVL+ tree metadata for authenticated dictionary operations.
/// Stores only the root digest and tree parameters, not the full tree.
///
/// Format matches Ergo protocol:
/// - digest: 33 bytes (32-byte Blake2b hash + 1-byte height)
/// - tree_flags: 1 byte (insert/update/remove permissions)
/// - key_length: 4 bytes (all keys must be this length)
/// - value_length_opt: 0 or 4 bytes (if present, all values must be this length)
pub const AvlTreeData = struct {
    /// Authenticated tree digest: Blake2b256 root hash + tree height
    digest: [digest_size]u8,

    /// Allowed tree operations
    tree_flags: AvlTreeFlags,

    /// Fixed key length for all entries (in bytes)
    key_length: u32,

    /// Optional fixed value length (None means variable-length values)
    value_length_opt: ?u32,

    /// Create an AvlTreeData with validation
    pub fn init(
        digest: [digest_size]u8,
        tree_flags: AvlTreeFlags,
        key_length: u32,
        value_length_opt: ?u32,
    ) error{InvalidParameter}!AvlTreeData {
        // PRECONDITION: Key length must be valid
        if (key_length == 0 or key_length > max_key_length) {
            return error.InvalidParameter;
        }

        // PRECONDITION: Value length must be valid if present
        if (value_length_opt) |vl| {
            if (vl > max_value_length) {
                return error.InvalidParameter;
            }
        }

        const result = AvlTreeData{
            .digest = digest,
            .tree_flags = tree_flags,
            .key_length = key_length,
            .value_length_opt = value_length_opt,
        };

        // POSTCONDITION: Result is valid
        assert(result.key_length > 0);
        assert(result.key_length <= max_key_length);

        return result;
    }

    /// Get the tree height from digest (last byte)
    pub fn height(self: *const AvlTreeData) u8 {
        return self.digest[hash_size];
    }

    /// Get just the root hash (first 32 bytes of digest)
    pub fn rootHash(self: *const AvlTreeData) *const [hash_size]u8 {
        return self.digest[0..hash_size];
    }

    /// Create a copy with updated digest
    pub fn withDigest(self: AvlTreeData, new_digest: [digest_size]u8) AvlTreeData {
        var result = self;
        result.digest = new_digest;
        return result;
    }

    /// Create a copy with updated flags
    pub fn withFlags(self: AvlTreeData, new_flags: AvlTreeFlags) AvlTreeData {
        var result = self;
        result.tree_flags = new_flags;
        return result;
    }

    /// Check if insert is allowed
    pub fn isInsertAllowed(self: *const AvlTreeData) bool {
        return self.tree_flags.insert_allowed;
    }

    /// Check if update is allowed
    pub fn isUpdateAllowed(self: *const AvlTreeData) bool {
        return self.tree_flags.update_allowed;
    }

    /// Check if remove is allowed
    pub fn isRemoveAllowed(self: *const AvlTreeData) bool {
        return self.tree_flags.remove_allowed;
    }

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        // AvlTreeData must be reasonably sized for stack allocation
        assert(@sizeOf(AvlTreeData) <= 64);
        // Must be able to hold all fields
        assert(@sizeOf(AvlTreeData) >= digest_size + 1 + 4 + 4);
    }
};

// ============================================================================
// AVL Tree Operations
// ============================================================================

/// Operation type for batch verification
pub const Operation = enum(u8) {
    lookup = 0x01,
    insert = 0x02,
    update = 0x03,
    remove = 0x04,
    insert_or_update = 0x05,
};

/// Result of a lookup operation
pub const LookupResult = union(enum) {
    /// Key found, value returned
    found: []const u8,
    /// Key not found
    not_found: void,
    /// Verification failed
    verification_failed: void,
};

// ============================================================================
// Proof Format Constants
// ============================================================================

/// Proof encoding markers (from scorex/ergo-avltree-rust)
/// Bytes -1, 0, 1 reserved for balance values
const ProofMarker = struct {
    /// Leaf node marker in packaged proof
    pub const leaf: u8 = 2;
    /// Internal node label marker (followed by 32-byte hash)
    pub const label: u8 = 3;
    /// End of tree marker
    pub const end_of_tree: u8 = 4;
};

// ============================================================================
// AVL Node Types
// ============================================================================

/// AVL tree node type for proof verification
/// Reconstructed from serialized proof data
pub const AvlNode = union(enum) {
    /// Leaf node with key-value pair
    leaf: struct {
        key: []const u8,
        value: []const u8,
        next_leaf_key: []const u8, // For range proofs
    },
    /// Internal node with label and children
    internal: struct {
        balance: i8, // -1, 0, or 1
        left_label: [hash_size]u8,
        right_label: [hash_size]u8,
    },
    /// Label-only node (pruned subtree)
    label_only: [hash_size]u8,

    /// Compute the Blake2b256 label for this node
    pub fn computeLabel(self: AvlNode, key_length: usize) [hash_size]u8 {
        var hasher = hash.Blake2b256Hasher.init();

        switch (self) {
            .leaf => |leaf| {
                // Leaf serialization: prefix(1) + key + value_len + value + next_key
                hasher.update(&[_]u8{1}); // Leaf prefix
                hasher.update(leaf.key);
                // Variable-length value: 2-byte length prefix
                const len_bytes: [2]u8 = .{
                    @truncate(leaf.value.len >> 8),
                    @truncate(leaf.value.len),
                };
                hasher.update(&len_bytes);
                hasher.update(leaf.value);
                hasher.update(leaf.next_leaf_key);
            },
            .internal => |internal| {
                // Internal serialization: prefix(0) + balance + key_len + left + right
                hasher.update(&[_]u8{0}); // Internal prefix
                hasher.update(&[_]u8{@bitCast(internal.balance)});
                // Key length as single byte (protocol limit)
                hasher.update(&[_]u8{@truncate(key_length)});
                hasher.update(&internal.left_label);
                hasher.update(&internal.right_label);
            },
            .label_only => |label| {
                // Label-only nodes already have their hash
                return label;
            },
        }

        return hasher.finalize();
    }
};

// ============================================================================
// Batch AVL Verifier
// ============================================================================

/// Verifies AVL+ tree operations using serialized proofs.
///
/// Implementation based on scorex/ergo-avltree-rust BatchAVLVerifier.
/// Proof format: post-order tree encoding + direction bits
///
/// Verification algorithm:
/// 1. Parse proof to reconstruct tree structure (using node stack)
/// 2. Verify computed root hash matches expected digest
/// 3. Navigate tree using direction bits for each operation
/// 4. Return lookup results or update digest for modifications
pub const BatchAVLVerifier = struct {
    /// Expected digest from tree metadata
    starting_digest: [digest_size]u8,

    /// Current computed digest (updated after operations)
    current_digest: [digest_size]u8,

    /// Proof data bytes
    proof: []const u8,

    /// Current position in tree encoding portion
    tree_pos: usize,

    /// Position where direction bits start
    directions_start: usize,

    /// Current bit position in direction bits
    directions_bit_pos: usize,

    /// Tree parameters
    key_length: usize,
    value_length_opt: ?usize,

    /// Tree height from digest
    tree_height: u8,

    /// Arena for allocating results
    arena: *std.heap.ArenaAllocator,

    /// Stack for tree reconstruction (max height 255)
    node_stack: [256][hash_size]u8,
    stack_top: u8,

    /// Found leaf value (if any) during traversal
    found_value: ?[]const u8,

    pub const VerifyError = error{
        InvalidProof,
        ProofExhausted,
        DigestMismatch,
        OutOfMemory,
        InvalidKeyLength,
        InvalidValueLength,
        StackOverflow,
        InvalidNodeType,
    };

    /// Initialize verifier with starting digest and proof
    pub fn init(
        starting_digest: [digest_size]u8,
        proof: []const u8,
        key_length: usize,
        value_length_opt: ?usize,
        arena: *std.heap.ArenaAllocator,
    ) error{InvalidParameter}!BatchAVLVerifier {
        // PRECONDITION: Key length must be valid
        if (key_length == 0 or key_length > max_key_length) {
            return error.InvalidParameter;
        }

        // PRECONDITION: Value length must be valid if specified
        if (value_length_opt) |vl| {
            if (vl > max_value_length) {
                return error.InvalidParameter;
            }
        }

        // PRECONDITION: Proof size must be reasonable
        if (proof.len > max_proof_size) {
            return error.InvalidParameter;
        }

        // Extract tree height from digest (last byte)
        const tree_height = starting_digest[hash_size];

        var result = BatchAVLVerifier{
            .starting_digest = starting_digest,
            .current_digest = starting_digest,
            .proof = proof,
            .tree_pos = 0,
            .directions_start = 0,
            .directions_bit_pos = 0,
            .key_length = key_length,
            .value_length_opt = value_length_opt,
            .tree_height = tree_height,
            .arena = arena,
            .node_stack = undefined,
            .stack_top = 0,
            .found_value = null,
        };

        // Find where tree encoding ends and direction bits start
        result.directions_start = result.findDirectionsStart() catch 0;

        // POSTCONDITION: Verifier is initialized with valid state
        assert(result.key_length > 0);
        assert(result.tree_pos == 0);

        return result;
    }

    /// Perform a lookup operation and return the result
    pub fn lookup(self: *BatchAVLVerifier, key: []const u8) VerifyError!LookupResult {
        // PRECONDITION: Key must match expected length
        if (key.len != self.key_length) {
            return error.InvalidKeyLength;
        }

        // PRECONDITION: Verifier must have valid state
        assert(self.key_length > 0);
        assert(self.key_length <= max_key_length);

        // Reset state for new operation
        self.tree_pos = 0;
        self.stack_top = 0;
        self.found_value = null;

        // Parse proof and search for key
        const root_label = self.reconstructAndSearch(key) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => .verification_failed,
            };
        };

        // Verify computed root matches expected digest
        if (!std.mem.eql(u8, &root_label, self.starting_digest[0..hash_size])) {
            return .verification_failed;
        }

        // Return result based on whether key was found
        if (self.found_value) |value| {
            // Copy value to arena for caller
            const result = self.arena.allocator().alloc(u8, value.len) catch return error.OutOfMemory;
            @memcpy(result, value);
            return .{ .found = result };
        }

        return .not_found;
    }

    /// Perform an insert operation and update the digest
    pub fn insert(self: *BatchAVLVerifier, key: []const u8, value: []const u8) VerifyError!void {
        // PRECONDITION: Key must match expected length
        if (key.len != self.key_length) {
            return error.InvalidKeyLength;
        }

        // PRECONDITION: Value must match expected length if fixed
        if (self.value_length_opt) |vl| {
            if (value.len != vl) {
                return error.InvalidValueLength;
            }
        }

        // For insert, we need to verify the proof structure and compute new digest
        // This requires parsing the proof, verifying old root, simulating insert,
        // and computing the new root hash.
        //
        // Simplified implementation: trust proof structure, extract new digest
        const new_digest = self.verifyModification(key, value, .insert) catch {
            return error.InvalidProof;
        };

        self.current_digest = new_digest;
        self.starting_digest = new_digest;
    }

    /// Perform an update operation
    pub fn update(self: *BatchAVLVerifier, key: []const u8, value: []const u8) VerifyError!void {
        if (key.len != self.key_length) return error.InvalidKeyLength;
        if (self.value_length_opt) |vl| {
            if (value.len != vl) return error.InvalidValueLength;
        }

        const new_digest = self.verifyModification(key, value, .update) catch {
            return error.InvalidProof;
        };

        self.current_digest = new_digest;
        self.starting_digest = new_digest;
    }

    /// Perform a remove operation and update the digest
    pub fn remove(self: *BatchAVLVerifier, key: []const u8) VerifyError!void {
        if (key.len != self.key_length) {
            return error.InvalidKeyLength;
        }

        const new_digest = self.verifyModification(key, &.{}, .remove) catch {
            return error.InvalidProof;
        };

        self.current_digest = new_digest;
        self.starting_digest = new_digest;
    }

    /// Get the current digest after operations
    pub fn digest(self: *const BatchAVLVerifier) ?[digest_size]u8 {
        return self.current_digest;
    }

    // ========================================================================
    // Internal: Tree reconstruction and verification
    // ========================================================================

    /// Find where the direction bits start in the proof
    fn findDirectionsStart(self: *BatchAVLVerifier) VerifyError!usize {
        var pos: usize = 0;

        while (pos < self.proof.len) {
            const marker = self.proof[pos];
            pos += 1;

            if (marker == ProofMarker.end_of_tree) {
                return pos;
            } else if (marker == ProofMarker.label) {
                // Skip 32-byte hash
                pos += hash_size;
            } else if (marker == ProofMarker.leaf) {
                // Skip leaf: key + value + next_key
                pos += self.key_length; // key
                if (self.value_length_opt) |vl| {
                    pos += vl; // fixed-length value
                } else {
                    if (pos + 2 > self.proof.len) return error.ProofExhausted;
                    const vlen = std.mem.readInt(u16, self.proof[pos..][0..2], .big);
                    pos += 2 + vlen;
                }
                pos += self.key_length; // next_leaf_key
            } else {
                // Balance byte (-1, 0, 1 encoded as 0xFF, 0x00, 0x01)
                // Internal node: balance only, children come from stack
            }

            if (pos > self.proof.len) return error.ProofExhausted;
        }

        return self.proof.len;
    }

    /// Reconstruct tree from proof and search for key
    /// Returns the computed root label
    fn reconstructAndSearch(self: *BatchAVLVerifier, search_key: []const u8) VerifyError![hash_size]u8 {
        // Parse proof in post-order, building tree on stack
        while (self.tree_pos < self.directions_start) {
            const marker = self.proof[self.tree_pos];
            self.tree_pos += 1;

            if (marker == ProofMarker.end_of_tree) {
                break;
            } else if (marker == ProofMarker.label) {
                // Label-only node: push hash to stack
                if (self.tree_pos + hash_size > self.proof.len) {
                    return error.ProofExhausted;
                }
                try self.pushLabel(self.proof[self.tree_pos..][0..hash_size]);
                self.tree_pos += hash_size;
            } else if (marker == ProofMarker.leaf) {
                // Leaf node: parse and compute label
                const leaf_data = try self.parseLeaf();

                // Check if this is the key we're looking for
                if (std.mem.eql(u8, leaf_data.key, search_key)) {
                    self.found_value = leaf_data.value;
                }

                // Compute leaf label and push
                const node = AvlNode{
                    .leaf = .{
                        .key = leaf_data.key,
                        .value = leaf_data.value,
                        .next_leaf_key = leaf_data.next_leaf_key,
                    },
                };
                const label = node.computeLabel(self.key_length);
                try self.pushLabel(&label);
            } else {
                // Internal node: pop two children, compute label, push
                const balance = signedFromByte(marker);
                if (balance < -1 or balance > 1) {
                    return error.InvalidNodeType;
                }

                // Pop right then left (post-order)
                const right_label = try self.popLabel();
                const left_label = try self.popLabel();

                const node = AvlNode{
                    .internal = .{
                        .balance = balance,
                        .left_label = left_label,
                        .right_label = right_label,
                    },
                };
                const label = node.computeLabel(self.key_length);
                try self.pushLabel(&label);
            }
        }

        // Stack should have exactly one element: the root
        if (self.stack_top != 1) {
            return error.InvalidProof;
        }

        return self.node_stack[0];
    }

    fn parseLeaf(self: *BatchAVLVerifier) VerifyError!struct {
        key: []const u8,
        value: []const u8,
        next_leaf_key: []const u8,
    } {
        const start = self.tree_pos;

        // Key
        if (start + self.key_length > self.proof.len) return error.ProofExhausted;
        const key = self.proof[start..][0..self.key_length];
        self.tree_pos += self.key_length;

        // Value
        const value_len = if (self.value_length_opt) |vl| vl else blk: {
            if (self.tree_pos + 2 > self.proof.len) return error.ProofExhausted;
            const len = std.mem.readInt(u16, self.proof[self.tree_pos..][0..2], .big);
            self.tree_pos += 2;
            break :blk @as(usize, len);
        };

        if (self.tree_pos + value_len > self.proof.len) return error.ProofExhausted;
        const value = self.proof[self.tree_pos..][0..value_len];
        self.tree_pos += value_len;

        // Next leaf key
        if (self.tree_pos + self.key_length > self.proof.len) return error.ProofExhausted;
        const next_key = self.proof[self.tree_pos..][0..self.key_length];
        self.tree_pos += self.key_length;

        return .{ .key = key, .value = value, .next_leaf_key = next_key };
    }

    fn pushLabel(self: *BatchAVLVerifier, label: *const [hash_size]u8) VerifyError!void {
        if (self.stack_top >= 255) return error.StackOverflow;
        @memcpy(&self.node_stack[self.stack_top], label);
        self.stack_top += 1;
    }

    fn popLabel(self: *BatchAVLVerifier) VerifyError![hash_size]u8 {
        if (self.stack_top == 0) return error.InvalidProof;
        self.stack_top -= 1;
        return self.node_stack[self.stack_top];
    }

    fn verifyModification(
        self: *BatchAVLVerifier,
        key: []const u8,
        value: []const u8,
        op: Operation,
    ) VerifyError![digest_size]u8 {
        _ = key;
        _ = value;
        _ = op;

        // For modifications, we need to:
        // 1. Verify old tree structure
        // 2. Apply modification (insert/update/remove)
        // 3. Recompute Merkle path hashes
        // 4. Construct new digest
        //
        // Full implementation requires:
        // - Direction bit navigation to find insertion point
        // - AVL rebalancing simulation
        // - Height tracking and update
        //
        // Simplified: extract new digest from proof tail
        // This trusts the proof but doesn't cryptographically verify it.

        // Look for new digest at end of proof (after direction bits)
        // Format: ... direction_bits ... new_digest(33 bytes)
        if (self.proof.len < digest_size) {
            return error.InvalidProof;
        }

        const digest_start = self.proof.len - digest_size;
        var new_digest: [digest_size]u8 = undefined;
        @memcpy(&new_digest, self.proof[digest_start..][0..digest_size]);

        return new_digest;
    }

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        // BatchAVLVerifier size check (stack is large)
        assert(@sizeOf(BatchAVLVerifier) <= 9000); // 256 * 32 + overhead
    }
};

/// Convert balance byte to signed (-1, 0, 1)
fn signedFromByte(b: u8) i8 {
    return @bitCast(b);
}

// ============================================================================
// Tests
// ============================================================================

test "avl_tree: AvlTreeFlags bit layout" {
    // Test insert-only
    const insert_only = AvlTreeFlags.init(true, false, false);
    try std.testing.expectEqual(@as(u8, 0x01), insert_only.toByte());
    try std.testing.expect(insert_only.insert_allowed);
    try std.testing.expect(!insert_only.update_allowed);
    try std.testing.expect(!insert_only.remove_allowed);

    // Test update-only
    const update_only = AvlTreeFlags.init(false, true, false);
    try std.testing.expectEqual(@as(u8, 0x02), update_only.toByte());

    // Test remove-only
    const remove_only = AvlTreeFlags.init(false, false, true);
    try std.testing.expectEqual(@as(u8, 0x04), remove_only.toByte());

    // Test all allowed
    const all = AvlTreeFlags.allAllowed();
    try std.testing.expectEqual(@as(u8, 0x07), all.toByte());

    // Test read-only
    const ro = AvlTreeFlags.readOnly();
    try std.testing.expectEqual(@as(u8, 0x00), ro.toByte());
}

test "avl_tree: AvlTreeFlags fromByte roundtrip" {
    const cases = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    for (cases) |b| {
        const flags = AvlTreeFlags.fromByte(b);
        try std.testing.expectEqual(b, flags.toByte());
    }
}

test "avl_tree: AvlTreeData creation" {
    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0x42);
    digest[hash_size] = 5; // height = 5

    const tree = try AvlTreeData.init(
        digest,
        AvlTreeFlags.init(true, true, false),
        32, // key_length
        null, // variable value length
    );

    try std.testing.expectEqual(@as(u8, 5), tree.height());
    try std.testing.expectEqual(@as(u32, 32), tree.key_length);
    try std.testing.expectEqual(@as(?u32, null), tree.value_length_opt);
    try std.testing.expect(tree.isInsertAllowed());
    try std.testing.expect(tree.isUpdateAllowed());
    try std.testing.expect(!tree.isRemoveAllowed());
}

test "avl_tree: AvlTreeData rejects invalid key_length" {
    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0);

    // key_length = 0
    try std.testing.expectError(
        error.InvalidParameter,
        AvlTreeData.init(digest, AvlTreeFlags.readOnly(), 0, null),
    );

    // key_length > max
    try std.testing.expectError(
        error.InvalidParameter,
        AvlTreeData.init(digest, AvlTreeFlags.readOnly(), max_key_length + 1, null),
    );
}

test "avl_tree: AvlTreeData rejects invalid value_length" {
    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0);

    // value_length > max
    try std.testing.expectError(
        error.InvalidParameter,
        AvlTreeData.init(digest, AvlTreeFlags.readOnly(), 32, max_value_length + 1),
    );
}

test "avl_tree: AvlTreeData withDigest" {
    var digest1: [digest_size]u8 = undefined;
    @memset(&digest1, 0x11);

    var digest2: [digest_size]u8 = undefined;
    @memset(&digest2, 0x22);

    const tree1 = try AvlTreeData.init(digest1, AvlTreeFlags.readOnly(), 32, null);
    const tree2 = tree1.withDigest(digest2);

    // Original unchanged
    try std.testing.expectEqual(@as(u8, 0x11), tree1.digest[0]);
    // New has updated digest
    try std.testing.expectEqual(@as(u8, 0x22), tree2.digest[0]);
    // Other fields preserved
    try std.testing.expectEqual(tree1.key_length, tree2.key_length);
}

test "avl_tree: AvlTreeData withFlags" {
    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0);

    const tree1 = try AvlTreeData.init(digest, AvlTreeFlags.readOnly(), 32, null);
    const tree2 = tree1.withFlags(AvlTreeFlags.allAllowed());

    // Original unchanged
    try std.testing.expect(!tree1.isInsertAllowed());
    // New has updated flags
    try std.testing.expect(tree2.isInsertAllowed());
    try std.testing.expect(tree2.isUpdateAllowed());
    try std.testing.expect(tree2.isRemoveAllowed());
}

test "avl_tree: digest components" {
    var digest: [digest_size]u8 = undefined;
    // First 32 bytes: root hash
    for (0..hash_size) |i| {
        digest[i] = @intCast(i);
    }
    // Last byte: height
    digest[hash_size] = 42;

    const tree = try AvlTreeData.init(digest, AvlTreeFlags.readOnly(), 32, null);

    try std.testing.expectEqual(@as(u8, 42), tree.height());

    const root = tree.rootHash();
    for (0..hash_size) |i| {
        try std.testing.expectEqual(@as(u8, @intCast(i)), root[i]);
    }
}

test "avl_tree: BatchAVLVerifier initialization" {
    const backing_allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();

    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0);

    const proof = [_]u8{ 0x00, 0x01, 0x00 };

    const verifier = try BatchAVLVerifier.init(
        digest,
        &proof,
        32, // key_length
        null, // variable value length
        &arena,
    );

    try std.testing.expectEqual(@as(usize, 32), verifier.key_length);
    try std.testing.expectEqual(@as(?usize, null), verifier.value_length_opt);
    try std.testing.expectEqual(@as(usize, 0), verifier.tree_pos);
}

test "avl_tree: BatchAVLVerifier rejects invalid params" {
    const backing_allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();

    var digest: [digest_size]u8 = undefined;
    @memset(&digest, 0);

    const proof = [_]u8{0x00};

    // key_length = 0
    try std.testing.expectError(
        error.InvalidParameter,
        BatchAVLVerifier.init(digest, &proof, 0, null, &arena),
    );

    // key_length > max
    try std.testing.expectError(
        error.InvalidParameter,
        BatchAVLVerifier.init(digest, &proof, max_key_length + 1, null, &arena),
    );
}
