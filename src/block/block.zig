//! Block Types
//!
//! Data structures for Ergo blocks including header, extension, and transactions.

const std = @import("std");
const context = @import("../interpreter/context.zig");
const transaction = @import("transaction.zig");

pub const HeaderView = context.HeaderView;
pub const Transaction = transaction.Transaction;

/// Maximum transactions per block
pub const MAX_TRANSACTIONS: u16 = 512;

/// Maximum extension entries
pub const MAX_EXTENSIONS: u16 = 256;

/// Maximum extension key size
pub const MAX_EXTENSION_KEY: u8 = 32;

/// Maximum extension value size
pub const MAX_EXTENSION_VALUE: u32 = 65536;

// ============================================================================
// Block Extension
// ============================================================================

/// Block extension key-value pair.
/// Used for soft-fork parameters and voting.
pub const Extension = struct {
    /// Key bytes (up to 32)
    key: [MAX_EXTENSION_KEY]u8,
    /// Actual key length
    key_len: u8,
    /// Value bytes (variable length, stored externally)
    value: []const u8,

    /// Create from key and value
    pub fn init(key: []const u8, value: []const u8) !Extension {
        if (key.len > MAX_EXTENSION_KEY) {
            return error.KeyTooLarge;
        }
        var ext = Extension{
            .key = [_]u8{0} ** MAX_EXTENSION_KEY,
            .key_len = @intCast(key.len),
            .value = value,
        };
        @memcpy(ext.key[0..key.len], key);
        return ext;
    }

    /// Get key as slice
    pub fn keySlice(self: *const Extension) []const u8 {
        return self.key[0..self.key_len];
    }
};

// ============================================================================
// Block
// ============================================================================

/// Full block for verification.
/// Contains header, transactions, extension, and optional AD proofs.
pub const Block = struct {
    /// Block header (reuses existing HeaderView)
    header: HeaderView,
    /// Block transactions
    transactions: []const Transaction,
    /// Extension section (soft-fork parameters)
    extension: []const Extension,
    /// AD proofs (for lite nodes, optional)
    ad_proofs: ?[]const u8,

    /// Create block with header and transactions
    pub fn init(header: HeaderView, transactions: []const Transaction) Block {
        return .{
            .header = header,
            .transactions = transactions,
            .extension = &[_]Extension{},
            .ad_proofs = null,
        };
    }

    /// Get block height
    pub fn height(self: *const Block) u32 {
        return self.header.height;
    }

    /// Get block ID (header ID)
    pub fn id(self: *const Block) [32]u8 {
        return self.header.id;
    }

    /// Get parent block ID
    pub fn parentId(self: *const Block) [32]u8 {
        return self.header.parent_id;
    }

    /// Get transaction count
    pub fn transactionCount(self: *const Block) usize {
        return self.transactions.len;
    }

    /// Get transactions root from header
    pub fn transactionsRoot(self: *const Block) [32]u8 {
        return self.header.transactions_root;
    }

    /// Get state root from header
    pub fn stateRoot(self: *const Block) [44]u8 {
        return self.header.state_root;
    }

    /// Check if block has extension data
    pub fn hasExtension(self: *const Block) bool {
        return self.extension.len > 0;
    }

    /// Check if block has AD proofs
    pub fn hasAdProofs(self: *const Block) bool {
        return self.ad_proofs != null;
    }

    /// Calculate total input count across all transactions
    pub fn totalInputCount(self: *const Block) usize {
        var count: usize = 0;
        for (self.transactions) |tx| {
            count += tx.inputs.len;
        }
        return count;
    }

    /// Calculate total output count across all transactions
    pub fn totalOutputCount(self: *const Block) usize {
        var count: usize = 0;
        for (self.transactions) |tx| {
            count += tx.outputs.len;
        }
        return count;
    }
};

// ============================================================================
// Pre-allocated Block Storage
// ============================================================================

/// Pre-allocated storage for parsing blocks without dynamic allocation.
pub const BlockStorage = struct {
    /// Transaction storage (one per block)
    transactions: [MAX_TRANSACTIONS]Transaction,
    tx_count: u16,
    /// Extension storage
    extensions: [MAX_EXTENSIONS]Extension,
    ext_count: u16,
    /// Transaction sub-storage for parsing individual txs
    tx_storage: transaction.TransactionStorage,
    /// Extension value arena
    ext_arena: [64 * 1024]u8,
    ext_pos: usize,
    /// AD proofs storage
    ad_proofs: [256 * 1024]u8,
    ad_proofs_len: usize,

    /// Initialize empty storage (WARNING: may overflow stack for large structs)
    pub fn init() BlockStorage {
        return .{
            .transactions = undefined,
            .tx_count = 0,
            .extensions = undefined,
            .ext_count = 0,
            .tx_storage = transaction.TransactionStorage.init(),
            .ext_arena = undefined,
            .ext_pos = 0,
            .ad_proofs = undefined,
            .ad_proofs_len = 0,
        };
    }

    /// Initialize in-place (avoids stack overflow for large struct)
    pub fn initInPlace(self: *BlockStorage) void {
        self.tx_count = 0;
        self.ext_count = 0;
        self.tx_storage.initInPlace();
        self.ext_pos = 0;
        self.ad_proofs_len = 0;
    }

    /// Reset for reuse
    pub fn reset(self: *BlockStorage) void {
        self.tx_count = 0;
        self.ext_count = 0;
        self.tx_storage.reset();
        self.ext_pos = 0;
        self.ad_proofs_len = 0;
    }

    /// Allocate bytes for extension value
    pub fn allocExtBytes(self: *BlockStorage, len: usize) ![]u8 {
        if (self.ext_pos + len > self.ext_arena.len) {
            return error.ArenaFull;
        }
        const slice = self.ext_arena[self.ext_pos .. self.ext_pos + len];
        self.ext_pos += len;
        return slice;
    }

    /// Add transaction
    pub fn addTransaction(self: *BlockStorage, tx: Transaction) !void {
        if (self.tx_count >= MAX_TRANSACTIONS) {
            return error.TooManyTransactions;
        }
        self.transactions[self.tx_count] = tx;
        self.tx_count += 1;
    }

    /// Add extension
    pub fn addExtension(self: *BlockStorage, ext: Extension) !void {
        if (self.ext_count >= MAX_EXTENSIONS) {
            return error.TooManyExtensions;
        }
        self.extensions[self.ext_count] = ext;
        self.ext_count += 1;
    }

    /// Get transactions slice
    pub fn getTransactions(self: *const BlockStorage) []const Transaction {
        return self.transactions[0..self.tx_count];
    }

    /// Get extensions slice
    pub fn getExtensions(self: *const BlockStorage) []const Extension {
        return self.extensions[0..self.ext_count];
    }

    /// Get AD proofs slice (if any)
    pub fn getAdProofs(self: *const BlockStorage) ?[]const u8 {
        if (self.ad_proofs_len == 0) return null;
        return self.ad_proofs[0..self.ad_proofs_len];
    }

    /// Set AD proofs
    pub fn setAdProofs(self: *BlockStorage, data: []const u8) !void {
        if (data.len > self.ad_proofs.len) {
            return error.AdProofsTooLarge;
        }
        @memcpy(self.ad_proofs[0..data.len], data);
        self.ad_proofs_len = data.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "block: Extension creation" {
    const key = "test_key";
    const value = "test_value";
    const ext = try Extension.init(key, value);

    try std.testing.expectEqualSlices(u8, key, ext.keySlice());
    try std.testing.expectEqualSlices(u8, value, ext.value);
}

test "block: Extension rejects large key" {
    const large_key = [_]u8{'x'} ** (MAX_EXTENSION_KEY + 1);
    try std.testing.expectError(error.KeyTooLarge, Extension.init(&large_key, "value"));
}

test "block: Block creation" {
    var header = std.mem.zeroes(HeaderView);
    header.height = 100000;
    header.version = 2;

    const blk = Block.init(header, &[_]Transaction{});

    try std.testing.expectEqual(@as(u32, 100000), blk.height());
    try std.testing.expectEqual(@as(usize, 0), blk.transactionCount());
    try std.testing.expect(!blk.hasExtension());
    try std.testing.expect(!blk.hasAdProofs());
}

test "block: BlockStorage reset" {
    var storage = BlockStorage.init();
    storage.tx_count = 10;
    storage.ext_count = 5;
    storage.ext_pos = 1000;

    storage.reset();

    try std.testing.expectEqual(@as(u16, 0), storage.tx_count);
    try std.testing.expectEqual(@as(u16, 0), storage.ext_count);
    try std.testing.expectEqual(@as(usize, 0), storage.ext_pos);
}
