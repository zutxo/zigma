//! UTXO Lookup Interface
//!
//! Provides an interface for resolving box IDs to box data.
//! Supports both in-memory (for testing/pre-parsed) and HTTP-based sources.

const std = @import("std");
const context = @import("../interpreter/context.zig");
const vlq = @import("../serialization/vlq.zig");
const hash = @import("../crypto/hash.zig");
const transaction = @import("transaction.zig");

pub const BoxView = context.BoxView;
pub const Token = context.Token;
pub const Output = transaction.Output;

/// Maximum boxes in memory UTXO set
pub const MAX_BOXES: u16 = 4096;

// ============================================================================
// UTXO Lookup Result
// ============================================================================

/// Result of a UTXO lookup operation
pub const UtxoLookupResult = union(enum) {
    /// Box found
    found: BoxView,
    /// Box not found (not in UTXO set)
    not_found: void,
    /// Lookup error
    err: UtxoError,

    /// Check if lookup was successful
    pub fn isFound(self: UtxoLookupResult) bool {
        return self == .found;
    }

    /// Get box if found, null otherwise
    pub fn box(self: UtxoLookupResult) ?BoxView {
        return switch (self) {
            .found => |b| b,
            else => null,
        };
    }
};

/// UTXO lookup errors
pub const UtxoError = error{
    /// Network error during lookup
    NetworkError,
    /// Invalid box ID format
    InvalidBoxId,
    /// Box data parsing failed
    ParseError,
    /// Lookup timeout
    Timeout,
    /// Internal error
    InternalError,
};

// ============================================================================
// UTXO Source Interface
// ============================================================================

/// Generic UTXO source interface.
/// Allows pluggable implementations (memory, HTTP, database).
pub const UtxoSource = struct {
    /// Implementation-specific context
    ctx: *anyopaque,
    /// Lookup function pointer
    lookupFn: *const fn (ctx: *anyopaque, box_id: *const [32]u8) UtxoLookupResult,

    /// Lookup a box by its ID
    pub fn lookup(self: *const UtxoSource, box_id: *const [32]u8) UtxoLookupResult {
        return self.lookupFn(self.ctx, box_id);
    }

    /// Lookup multiple boxes (convenience method)
    pub fn lookupMany(
        self: *const UtxoSource,
        box_ids: []const [32]u8,
        results: []UtxoLookupResult,
    ) void {
        std.debug.assert(results.len >= box_ids.len);
        for (box_ids, 0..) |box_id, i| {
            results[i] = self.lookup(&box_id);
        }
    }
};

// ============================================================================
// Memory UTXO Set
// ============================================================================

/// In-memory UTXO set for testing and pre-parsed block data.
/// Uses linear search (efficient for small sets, no hash map overhead).
pub const MemoryUtxoSet = struct {
    /// Boxes in the set
    boxes: []const BoxView,
    /// Pre-computed box IDs (for lookup)
    box_ids: []const [32]u8,
    /// Number of lookups performed (for stats)
    lookup_count: u64,
    /// Number of successful lookups
    hit_count: u64,

    /// Create from arrays of boxes and their IDs
    pub fn init(boxes: []const BoxView, box_ids: []const [32]u8) MemoryUtxoSet {
        std.debug.assert(boxes.len == box_ids.len);
        return .{
            .boxes = boxes,
            .box_ids = box_ids,
            .lookup_count = 0,
            .hit_count = 0,
        };
    }

    /// Lookup box by ID (linear search)
    pub fn lookup(self: *MemoryUtxoSet, box_id: *const [32]u8) UtxoLookupResult {
        self.lookup_count += 1;

        for (self.box_ids, 0..) |id, i| {
            if (std.mem.eql(u8, &id, box_id)) {
                self.hit_count += 1;
                return .{ .found = self.boxes[i] };
            }
        }
        return .not_found;
    }

    /// Get as generic UtxoSource
    pub fn asSource(self: *MemoryUtxoSet) UtxoSource {
        return .{
            .ctx = @ptrCast(self),
            .lookupFn = &memoryLookupWrapper,
        };
    }

    /// Get hit rate (0.0 - 1.0)
    pub fn hitRate(self: *const MemoryUtxoSet) f64 {
        if (self.lookup_count == 0) return 0.0;
        return @as(f64, @floatFromInt(self.hit_count)) / @as(f64, @floatFromInt(self.lookup_count));
    }

    /// Reset statistics
    pub fn resetStats(self: *MemoryUtxoSet) void {
        self.lookup_count = 0;
        self.hit_count = 0;
    }
};

/// Wrapper function for MemoryUtxoSet lookup
fn memoryLookupWrapper(ctx: *anyopaque, box_id: *const [32]u8) UtxoLookupResult {
    const self: *MemoryUtxoSet = @ptrCast(@alignCast(ctx));
    return self.lookup(box_id);
}

// ============================================================================
// Pre-allocated UTXO Storage
// ============================================================================

/// Pre-allocated storage for building a MemoryUtxoSet.
/// Used when parsing block data to collect UTXO boxes.
pub const UtxoStorage = struct {
    /// Box storage
    boxes: [MAX_BOXES]BoxView,
    /// Box ID storage
    box_ids: [MAX_BOXES][32]u8,
    /// Current count
    count: u16,
    /// Token storage for all boxes (limited to 16384 total)
    tokens: [16384]Token,
    token_count: u32,
    /// Byte arena for proposition bytes and registers
    byte_arena: [256 * 1024]u8,
    byte_pos: usize,

    /// Initialize empty storage
    pub fn init() UtxoStorage {
        return .{
            .boxes = undefined,
            .box_ids = undefined,
            .count = 0,
            .tokens = undefined,
            .token_count = 0,
            .byte_arena = undefined,
            .byte_pos = 0,
        };
    }

    /// Reset for reuse
    pub fn reset(self: *UtxoStorage) void {
        self.count = 0;
        self.token_count = 0;
        self.byte_pos = 0;
    }

    /// Allocate bytes from arena
    pub fn allocBytes(self: *UtxoStorage, len: usize) ![]u8 {
        if (self.byte_pos + len > self.byte_arena.len) {
            return error.ArenaFull;
        }
        const slice = self.byte_arena[self.byte_pos .. self.byte_pos + len];
        self.byte_pos += len;
        return slice;
    }

    /// Allocate tokens
    pub fn allocTokens(self: *UtxoStorage, count: usize) ![]Token {
        if (self.token_count + count > self.tokens.len) {
            return error.TooManyTokens;
        }
        const start = self.token_count;
        self.token_count += @intCast(count);
        return self.tokens[start .. start + count];
    }

    /// Add a box with its ID
    pub fn addBox(self: *UtxoStorage, box_id: [32]u8, box: BoxView) !void {
        if (self.count >= MAX_BOXES) {
            return error.TooManyBoxes;
        }
        self.box_ids[self.count] = box_id;
        self.boxes[self.count] = box;
        self.count += 1;
    }

    /// Get boxes slice
    pub fn getBoxes(self: *const UtxoStorage) []const BoxView {
        return self.boxes[0..self.count];
    }

    /// Get box IDs slice
    pub fn getBoxIds(self: *const UtxoStorage) []const [32]u8 {
        return self.box_ids[0..self.count];
    }

    /// Create MemoryUtxoSet from this storage
    pub fn toUtxoSet(self: *const UtxoStorage) MemoryUtxoSet {
        return MemoryUtxoSet.init(self.getBoxes(), self.getBoxIds());
    }
};

// ============================================================================
// Box ID Computation
// ============================================================================

/// Maximum size for box serialization buffer
pub const MAX_BOX_BYTES: usize = 8192;

/// Compute box ID from output data according to Ergo protocol.
/// Box ID = Blake2b256(serialize(value, ergoTree, creationHeight, tokens, registers, txId, index))
///
/// Reference: ErgoBox.scala:72-73 - `lazy val id: BoxId = ADKey @@@ Blake2b256.hash(bytes)`
pub fn computeBoxId(output: *const Output, tx_id: *const [32]u8, output_index: u16) [32]u8 {
    var buf: [MAX_BOX_BYTES]u8 = undefined;
    var pos: usize = 0;

    // 1. Value as unsigned VLQ
    var vlq_buf: [vlq.max_vlq_bytes]u8 = undefined;
    const value_len = vlq.encodeU64(@bitCast(output.value), &vlq_buf);
    @memcpy(buf[pos .. pos + value_len], vlq_buf[0..value_len]);
    pos += value_len;

    // 2. ErgoTree with VLQ length prefix
    const tree_len = vlq.encodeU64(output.ergo_tree.len, &vlq_buf);
    @memcpy(buf[pos .. pos + tree_len], vlq_buf[0..tree_len]);
    pos += tree_len;
    @memcpy(buf[pos .. pos + output.ergo_tree.len], output.ergo_tree);
    pos += output.ergo_tree.len;

    // 3. CreationHeight as unsigned VLQ
    const height_len = vlq.encodeU64(output.creation_height, &vlq_buf);
    @memcpy(buf[pos .. pos + height_len], vlq_buf[0..height_len]);
    pos += height_len;

    // 4. Token count (1 byte)
    buf[pos] = @intCast(output.tokens.len);
    pos += 1;

    // 5. Tokens: each is (tokenId[32] + VLQ amount)
    for (output.tokens) |token| {
        @memcpy(buf[pos .. pos + 32], &token.id);
        pos += 32;
        const amount_len = vlq.encodeU64(@bitCast(token.amount), &vlq_buf);
        @memcpy(buf[pos .. pos + amount_len], vlq_buf[0..amount_len]);
        pos += amount_len;
    }

    // 6. Register count (non-null registers from R4-R9)
    var reg_count: u8 = 0;
    for (output.registers) |reg| {
        if (reg != null) reg_count += 1;
    }
    buf[pos] = reg_count;
    pos += 1;

    // 7. Registers: serialized bytes for each non-null register
    for (output.registers) |reg| {
        if (reg) |reg_bytes| {
            @memcpy(buf[pos .. pos + reg_bytes.len], reg_bytes);
            pos += reg_bytes.len;
        }
    }

    // 8. Transaction ID (32 bytes)
    @memcpy(buf[pos .. pos + 32], tx_id);
    pos += 32;

    // 9. Box index as 2-byte big-endian (UShort)
    std.mem.writeInt(u16, buf[pos..][0..2], output_index, .big);
    pos += 2;

    // Hash the serialized bytes
    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(buf[0..pos]);
    return hasher.finalize();
}

/// Compute box ID from BoxView and transaction reference.
/// Used for existing boxes that have all fields populated.
pub fn computeBoxIdFromView(
    box: *const BoxView,
    tx_id: *const [32]u8,
    box_index: u16,
) [32]u8 {
    var buf: [MAX_BOX_BYTES]u8 = undefined;
    var pos: usize = 0;

    // 1. Value as unsigned VLQ
    var vlq_buf: [vlq.max_vlq_bytes]u8 = undefined;
    const value_len = vlq.encodeU64(@bitCast(box.value), &vlq_buf);
    @memcpy(buf[pos .. pos + value_len], vlq_buf[0..value_len]);
    pos += value_len;

    // 2. Proposition bytes with VLQ length prefix
    const prop_len = vlq.encodeU64(box.proposition_bytes.len, &vlq_buf);
    @memcpy(buf[pos .. pos + prop_len], vlq_buf[0..prop_len]);
    pos += prop_len;
    @memcpy(buf[pos .. pos + box.proposition_bytes.len], box.proposition_bytes);
    pos += box.proposition_bytes.len;

    // 3. CreationHeight as unsigned VLQ
    const height_len = vlq.encodeU64(box.creation_height, &vlq_buf);
    @memcpy(buf[pos .. pos + height_len], vlq_buf[0..height_len]);
    pos += height_len;

    // 4. Token count
    buf[pos] = @intCast(box.tokens.len);
    pos += 1;

    // 5. Tokens
    for (box.tokens) |token| {
        @memcpy(buf[pos .. pos + 32], &token.id);
        pos += 32;
        const amount_len = vlq.encodeU64(@bitCast(token.amount), &vlq_buf);
        @memcpy(buf[pos .. pos + amount_len], vlq_buf[0..amount_len]);
        pos += amount_len;
    }

    // 6. Register count
    var reg_count: u8 = 0;
    for (box.registers) |reg| {
        if (reg != null) reg_count += 1;
    }
    buf[pos] = reg_count;
    pos += 1;

    // 7. Registers
    for (box.registers) |reg| {
        if (reg) |reg_bytes| {
            @memcpy(buf[pos .. pos + reg_bytes.len], reg_bytes);
            pos += reg_bytes.len;
        }
    }

    // 8. Transaction ID
    @memcpy(buf[pos .. pos + 32], tx_id);
    pos += 32;

    // 9. Box index
    std.mem.writeInt(u16, buf[pos..][0..2], box_index, .big);
    pos += 2;

    var hasher = hash.Blake2b256Hasher.init();
    hasher.update(buf[0..pos]);
    return hasher.finalize();
}

// ============================================================================
// Tests
// ============================================================================

test "utxo: computeBoxId produces deterministic output" {
    const ergo_tree = [_]u8{ 0x00, 0x08, 0xcd }; // Example minimal ErgoTree
    const output = Output.init(1000000, &ergo_tree, 100);
    const tx_id = [_]u8{0xAB} ** 32;

    const id1 = computeBoxId(&output, &tx_id, 0);
    const id2 = computeBoxId(&output, &tx_id, 0);

    try std.testing.expectEqualSlices(u8, &id1, &id2);

    // Different index should produce different ID
    const id3 = computeBoxId(&output, &tx_id, 1);
    try std.testing.expect(!std.mem.eql(u8, &id1, &id3));
}

test "utxo: MemoryUtxoSet lookup found" {
    var box_ids = [_][32]u8{
        [_]u8{0xAA} ** 32,
        [_]u8{0xBB} ** 32,
        [_]u8{0xCC} ** 32,
    };

    var boxes: [3]BoxView = undefined;
    for (&boxes, 0..) |*box, i| {
        box.* = std.mem.zeroes(BoxView);
        box.value = @intCast(i * 1000);
    }

    var utxo_set = MemoryUtxoSet.init(&boxes, &box_ids);

    // Lookup existing box
    const search_id = [_]u8{0xBB} ** 32;
    const result = utxo_set.lookup(&search_id);

    try std.testing.expect(result.isFound());
    try std.testing.expectEqual(@as(i64, 1000), result.box().?.value);
}

test "utxo: MemoryUtxoSet lookup not found" {
    var box_ids = [_][32]u8{
        [_]u8{0xAA} ** 32,
    };
    var boxes = [_]BoxView{std.mem.zeroes(BoxView)};

    var utxo_set = MemoryUtxoSet.init(&boxes, &box_ids);

    // Lookup non-existing box
    const search_id = [_]u8{0xFF} ** 32;
    const result = utxo_set.lookup(&search_id);

    try std.testing.expect(!result.isFound());
    try std.testing.expect(result == .not_found);
}

test "utxo: MemoryUtxoSet hit rate" {
    var box_ids = [_][32]u8{[_]u8{0xAA} ** 32};
    var boxes = [_]BoxView{std.mem.zeroes(BoxView)};

    var utxo_set = MemoryUtxoSet.init(&boxes, &box_ids);

    // 1 hit, 1 miss
    const hit_id = [_]u8{0xAA} ** 32;
    const miss_id = [_]u8{0xFF} ** 32;
    _ = utxo_set.lookup(&hit_id);
    _ = utxo_set.lookup(&miss_id);

    try std.testing.expectEqual(@as(f64, 0.5), utxo_set.hitRate());
}

test "utxo: UtxoSource interface" {
    var box_ids = [_][32]u8{[_]u8{0xAA} ** 32};
    var boxes = [_]BoxView{std.mem.zeroes(BoxView)};

    var utxo_set = MemoryUtxoSet.init(&boxes, &box_ids);
    const source = utxo_set.asSource();

    // Use through interface
    const search_id = [_]u8{0xAA} ** 32;
    const result = source.lookup(&search_id);

    try std.testing.expect(result.isFound());
}

test "utxo: UtxoStorage add and retrieve" {
    var storage = UtxoStorage.init();

    const box_id = [_]u8{0xDE} ** 32;
    var box = std.mem.zeroes(BoxView);
    box.value = 12345;

    try storage.addBox(box_id, box);

    try std.testing.expectEqual(@as(u16, 1), storage.count);
    try std.testing.expectEqual(@as(i64, 12345), storage.getBoxes()[0].value);
}

test "utxo: UtxoStorage reset" {
    var storage = UtxoStorage.init();
    storage.count = 10;
    storage.byte_pos = 5000;

    storage.reset();

    try std.testing.expectEqual(@as(u16, 0), storage.count);
    try std.testing.expectEqual(@as(usize, 0), storage.byte_pos);
}
