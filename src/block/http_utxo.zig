//! HTTP-based UTXO Source
//!
//! Fetches UTXOs from an Ergo node's REST API.
//! Implements the UtxoSource interface for use with BlockVerifier.

const std = @import("std");
const http = @import("http.zig");
const utxo = @import("utxo.zig");
const json_parser = @import("json_parser.zig");

pub const ErgoNodeClient = http.ErgoNodeClient;
pub const UtxoSource = utxo.UtxoSource;
pub const UtxoLookupResult = utxo.UtxoLookupResult;
pub const UtxoError = utxo.UtxoError;
pub const BoxView = utxo.BoxView;
pub const Token = utxo.Token;

// ============================================================================
// Single Box Storage (lightweight, for one box at a time)
// ============================================================================

/// Lightweight storage for parsing boxes from JSON.
/// Sized for a typical block's worth of input boxes (~50 boxes).
/// Much smaller than UtxoStorage (~32KB vs ~2MB).
pub const SingleBoxStorage = struct {
    /// Byte arena for proposition bytes and registers
    byte_arena: [32 * 1024]u8, // 32KB for ergoTree bytes and registers
    byte_pos: usize,
    /// Token storage (max 256 tokens across all boxes)
    tokens: [256]Token,
    token_count: u32,

    pub fn init() SingleBoxStorage {
        return .{
            .byte_arena = undefined,
            .byte_pos = 0,
            .tokens = undefined,
            .token_count = 0,
        };
    }

    pub fn initInPlace(self: *SingleBoxStorage) void {
        self.byte_pos = 0;
        self.token_count = 0;
    }

    pub fn reset(self: *SingleBoxStorage) void {
        self.byte_pos = 0;
        self.token_count = 0;
    }

    pub fn allocBytes(self: *SingleBoxStorage, len: usize) ![]u8 {
        if (self.byte_pos + len > self.byte_arena.len) {
            return error.ArenaFull;
        }
        const slice = self.byte_arena[self.byte_pos .. self.byte_pos + len];
        self.byte_pos += len;
        return slice;
    }

    pub fn allocTokens(self: *SingleBoxStorage, count: usize) ![]Token {
        if (self.token_count + count > self.tokens.len) {
            return error.TooManyTokens;
        }
        const start = self.token_count;
        self.token_count += @intCast(count);
        return self.tokens[start .. start + count];
    }
};

// ============================================================================
// HTTP UTXO Source
// ============================================================================

/// HTTP-based UTXO source that fetches from Ergo node API.
pub const HttpUtxoSource = struct {
    /// HTTP client for node communication
    client: *ErgoNodeClient,
    /// Allocator for JSON parsing
    allocator: std.mem.Allocator,
    /// Lightweight storage for parsing one box at a time
    storage: SingleBoxStorage,
    /// Cache misses (HTTP fetches)
    misses: u64,
    /// Fetch errors
    errors: u64,

    /// Initialize HTTP UTXO source (WARNING: may overflow stack)
    pub fn init(client: *ErgoNodeClient, allocator: std.mem.Allocator) HttpUtxoSource {
        return HttpUtxoSource{
            .client = client,
            .allocator = allocator,
            .storage = SingleBoxStorage.init(),
            .misses = 0,
            .errors = 0,
        };
    }

    /// Initialize in-place (avoids stack overflow for large struct)
    pub fn initInPlace(self: *HttpUtxoSource, client: *ErgoNodeClient, allocator: std.mem.Allocator) void {
        self.client = client;
        self.allocator = allocator;
        self.storage.initInPlace();
        self.misses = 0;
        self.errors = 0;
    }

    /// Deinitialize (no-op, no heap allocations)
    pub fn deinit(self: *HttpUtxoSource) void {
        _ = self;
    }

    /// Reset storage (for new block)
    pub fn reset(self: *HttpUtxoSource) void {
        self.storage.reset();
    }

    /// Lookup a box by ID (fetches via HTTP)
    pub fn lookup(self: *HttpUtxoSource, box_id: *const [32]u8) UtxoLookupResult {
        self.misses += 1;
        return self.fetchBox(box_id);
    }

    /// Get as generic UtxoSource interface
    pub fn asSource(self: *HttpUtxoSource) UtxoSource {
        return .{
            .ctx = @ptrCast(self),
            .lookupFn = &httpLookupWrapper,
        };
    }

    /// Get statistics
    pub fn getStats(self: *const HttpUtxoSource) struct {
        misses: u64,
        errors: u64,
    } {
        return .{
            .misses = self.misses,
            .errors = self.errors,
        };
    }

    // ========================================================================
    // HTTP Fetch
    // ========================================================================

    /// Fetch box from node (uses /blockchain/box/byId for historical boxes)
    fn fetchBox(self: *HttpUtxoSource, box_id: *const [32]u8) UtxoLookupResult {
        // Fetch from node using blockchain API (includes spent boxes)
        const json = self.client.getBoxById(box_id) catch |err| {
            self.errors += 1;
            return switch (err) {
                http.HttpError.NotFound => .not_found,
                http.HttpError.Timeout => .{ .err = UtxoError.Timeout },
                else => .{ .err = UtxoError.NetworkError },
            };
        };

        // Parse JSON response (storage accumulates - only reset at block boundaries)
        const box = json_parser.parseBoxJsonSimple(json, &self.storage, self.allocator) catch {
            self.errors += 1;
            return .{ .err = UtxoError.ParseError };
        };

        return .{ .found = box };
    }
};

/// Wrapper function for UtxoSource interface
fn httpLookupWrapper(ctx: *anyopaque, box_id: *const [32]u8) UtxoLookupResult {
    const self: *HttpUtxoSource = @ptrCast(@alignCast(ctx));
    return self.lookup(box_id);
}

// ============================================================================
// Tests
// ============================================================================

test "http_utxo: HttpUtxoSource init" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    const source = HttpUtxoSource.init(&client, std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 0), source.misses);
    try std.testing.expectEqual(@as(u64, 0), source.errors);
}

test "http_utxo: HttpUtxoSource reset" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    var source = HttpUtxoSource.init(&client, std.testing.allocator);
    defer source.deinit();

    source.misses = 5;

    source.reset();

    // Stats are not reset, only storage
    try std.testing.expectEqual(@as(u64, 5), source.misses);
}

test "http_utxo: asSource interface" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    var source = HttpUtxoSource.init(&client, std.testing.allocator);
    defer source.deinit();

    const utxo_source = source.asSource();

    // Verify interface is valid - check ctx is not null
    try std.testing.expect(@intFromPtr(utxo_source.ctx) != 0);
}

test "http_utxo: stats calculation" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    var source = HttpUtxoSource.init(&client, std.testing.allocator);
    defer source.deinit();

    source.misses = 10;
    source.errors = 2;

    const stats = source.getStats();

    try std.testing.expectEqual(@as(u64, 10), stats.misses);
    try std.testing.expectEqual(@as(u64, 2), stats.errors);
}

test "http_utxo: SingleBoxStorage" {
    var storage = SingleBoxStorage.init();

    // Test byte allocation
    const bytes = try storage.allocBytes(100);
    try std.testing.expectEqual(@as(usize, 100), bytes.len);

    // Test token allocation
    const tokens = try storage.allocTokens(5);
    try std.testing.expectEqual(@as(usize, 5), tokens.len);

    // Test reset
    storage.reset();
    try std.testing.expectEqual(@as(usize, 0), storage.byte_pos);
    try std.testing.expectEqual(@as(u32, 0), storage.token_count);
}
