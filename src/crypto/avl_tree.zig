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
// Batch AVL Verifier
// ============================================================================

/// Verifies AVL+ tree operations using serialized proofs.
/// This is a lightweight verifier - it doesn't store the tree,
/// only verifies that operations match the provided proof.
pub const BatchAVLVerifier = struct {
    /// Current digest (updated after each verified operation)
    current_digest: [digest_size]u8,

    /// Proof data (remaining bytes to consume)
    proof: []const u8,
    proof_pos: usize,

    /// Tree parameters
    key_length: usize,
    value_length_opt: ?usize,

    /// Arena for allocating results
    arena: *std.heap.ArenaAllocator,

    pub const VerifyError = error{
        InvalidProof,
        ProofExhausted,
        DigestMismatch,
        OutOfMemory,
        InvalidKeyLength,
        InvalidValueLength,
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

        const result = BatchAVLVerifier{
            .current_digest = starting_digest,
            .proof = proof,
            .proof_pos = 0,
            .key_length = key_length,
            .value_length_opt = value_length_opt,
            .arena = arena,
        };

        // POSTCONDITION: Verifier is initialized with valid state
        assert(result.key_length > 0);
        assert(result.proof_pos == 0);

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

        // Read proof node bytes
        const node_proof = self.readProofBytes() catch return .verification_failed;
        if (node_proof.len == 0) {
            return .verification_failed;
        }

        // First byte indicates if key was found
        const found_flag = node_proof[0];

        if (found_flag == 0) {
            // Key not found - proof shows absence
            // Verify the proof (simplified - full implementation would verify Merkle path)
            return .not_found;
        }

        // Key found - remaining bytes are the value
        const value_start: usize = 1;
        const value_len = if (self.value_length_opt) |vl|
            vl
        else blk: {
            // Variable length: read length prefix
            if (node_proof.len < value_start + 2) {
                return .verification_failed;
            }
            const len = std.mem.readInt(u16, node_proof[value_start..][0..2], .big);
            break :blk @as(usize, len);
        };

        const value_offset = if (self.value_length_opt != null) value_start else value_start + 2;
        if (node_proof.len < value_offset + value_len) {
            return .verification_failed;
        }

        // Copy value to arena
        const value = self.arena.allocator().alloc(u8, value_len) catch return error.OutOfMemory;
        @memcpy(value, node_proof[value_offset..][0..value_len]);

        return .{ .found = value };
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

        // Read and verify proof, update digest
        const new_digest = self.verifyModification(key, value, .insert) catch {
            return error.InvalidProof;
        };

        self.current_digest = new_digest;
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
    }

    /// Get the current digest after operations
    pub fn digest(self: *const BatchAVLVerifier) ?[digest_size]u8 {
        // Return current digest if proof was consumed successfully
        if (self.proof_pos <= self.proof.len) {
            return self.current_digest;
        }
        return null;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn readProofBytes(self: *BatchAVLVerifier) error{ProofExhausted}![]const u8 {
        if (self.proof_pos >= self.proof.len) {
            return error.ProofExhausted;
        }

        // Read length (2 bytes big-endian)
        if (self.proof_pos + 2 > self.proof.len) {
            return error.ProofExhausted;
        }

        const len = std.mem.readInt(u16, self.proof[self.proof_pos..][0..2], .big);
        self.proof_pos += 2;

        if (self.proof_pos + len > self.proof.len) {
            return error.ProofExhausted;
        }

        const result = self.proof[self.proof_pos..][0..len];
        self.proof_pos += len;

        return result;
    }

    fn verifyModification(
        self: *BatchAVLVerifier,
        key: []const u8,
        value: []const u8,
        op: Operation,
    ) error{InvalidProof}![digest_size]u8 {
        _ = key;
        _ = value;
        _ = op;

        // Read expected new digest from proof
        if (self.proof_pos + digest_size > self.proof.len) {
            return error.InvalidProof;
        }

        var new_digest: [digest_size]u8 = undefined;
        @memcpy(&new_digest, self.proof[self.proof_pos..][0..digest_size]);
        self.proof_pos += digest_size;

        // Full verification would:
        // 1. Parse the proof structure (Merkle path + node data)
        // 2. Verify old digest matches computed root
        // 3. Apply operation to get new root
        // 4. Verify new digest matches computed new root
        //
        // For now, we trust the proof structure and just extract the new digest.
        // This is a placeholder - real implementation needs full AVL+ verification.

        return new_digest;
    }

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        // BatchAVLVerifier must be reasonably sized
        assert(@sizeOf(BatchAVLVerifier) <= 128);
    }
};

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
    try std.testing.expectEqual(@as(usize, 0), verifier.proof_pos);
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
