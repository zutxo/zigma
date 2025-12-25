//! Ergo Node HTTP Client
//!
//! Fetches blocks and UTXOs from an Ergo node's REST API.
//! Uses pre-allocated buffers for responses (no dynamic allocation in hot path).

const std = @import("std");

/// Maximum response size (1MB)
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Default timeout in milliseconds
pub const DEFAULT_TIMEOUT_MS: u32 = 30_000;

// ============================================================================
// HTTP Client Errors
// ============================================================================

pub const HttpError = error{
    /// Failed to connect to node
    ConnectionFailed,
    /// Request timed out
    Timeout,
    /// Invalid response from server
    InvalidResponse,
    /// Resource not found (404)
    NotFound,
    /// Server error (5xx)
    ServerError,
    /// Response too large
    ResponseTooLarge,
    /// URL parsing failed
    InvalidUrl,
    /// Network error
    NetworkError,
};

// ============================================================================
// Ergo Node Client
// ============================================================================

/// HTTP client for Ergo node REST API.
/// Manages connection and response buffering.
pub const ErgoNodeClient = struct {
    /// Node base URL (e.g., "http://localhost:9052")
    base_url: []const u8,

    /// Pre-allocated response buffer
    response_buffer: [MAX_RESPONSE_SIZE]u8,

    /// Length of last response
    response_len: usize,

    /// Request timeout in milliseconds
    timeout_ms: u32,

    /// Number of requests made
    request_count: u64,

    /// Number of successful requests
    success_count: u64,

    /// Last error encountered
    last_error: ?HttpError,

    /// Initialize client with node URL
    pub fn init(base_url: []const u8) ErgoNodeClient {
        return .{
            .base_url = base_url,
            .response_buffer = undefined,
            .response_len = 0,
            .timeout_ms = DEFAULT_TIMEOUT_MS,
            .request_count = 0,
            .success_count = 0,
            .last_error = null,
        };
    }

    /// Set request timeout
    pub fn setTimeout(self: *ErgoNodeClient, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    /// Get last response as slice
    pub fn getResponse(self: *const ErgoNodeClient) []const u8 {
        return self.response_buffer[0..self.response_len];
    }

    /// Get client statistics
    pub fn getStats(self: *const ErgoNodeClient) struct {
        requests: u64,
        successes: u64,
        failures: u64,
    } {
        return .{
            .requests = self.request_count,
            .successes = self.success_count,
            .failures = self.request_count - self.success_count,
        };
    }

    // ========================================================================
    // Block API
    // ========================================================================

    /// Fetch block by header ID (hex string)
    pub fn getBlockById(self: *ErgoNodeClient, header_id: *const [32]u8) HttpError![]const u8 {
        var path_buf: [128]u8 = undefined;
        const hex = std.fmt.bytesToHex(header_id.*, .lower);
        const path = std.fmt.bufPrint(&path_buf, "/blocks/{s}", .{hex}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    /// Fetch block at specific height
    pub fn getBlockAtHeight(self: *ErgoNodeClient, height: u32) HttpError![]const u8 {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/blocks/at/{d}", .{height}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    /// Fetch block headers at height (returns array of header IDs)
    pub fn getHeaderIdsAtHeight(self: *ErgoNodeClient, height: u32) HttpError![]const u8 {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/blocks/at/{d}", .{height}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    /// Fetch latest block
    pub fn getLatestBlock(self: *ErgoNodeClient) HttpError![]const u8 {
        return self.get("/blocks/lastHeaders/1");
    }

    // ========================================================================
    // UTXO API
    // ========================================================================

    /// Fetch UTXO by box ID (hex string)
    pub fn getUtxoById(self: *ErgoNodeClient, box_id: *const [32]u8) HttpError![]const u8 {
        var path_buf: [128]u8 = undefined;
        const hex = std.fmt.bytesToHex(box_id.*, .lower);
        const path = std.fmt.bufPrint(&path_buf, "/utxo/byId/{s}", .{hex}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    /// Fetch UTXOs by address
    pub fn getUtxosByAddress(self: *ErgoNodeClient, address: []const u8) HttpError![]const u8 {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/blockchain/box/byAddress/{s}", .{address}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    // ========================================================================
    // Transaction API
    // ========================================================================

    /// Fetch transaction by ID
    pub fn getTransactionById(self: *ErgoNodeClient, tx_id: *const [32]u8) HttpError![]const u8 {
        var path_buf: [128]u8 = undefined;
        const hex = std.fmt.bytesToHex(tx_id.*, .lower);
        const path = std.fmt.bufPrint(&path_buf, "/blockchain/transaction/byId/{s}", .{hex}) catch
            return HttpError.InvalidUrl;
        return self.get(path);
    }

    // ========================================================================
    // Node Info API
    // ========================================================================

    /// Get node info (includes current height)
    pub fn getNodeInfo(self: *ErgoNodeClient) HttpError![]const u8 {
        return self.get("/info");
    }

    // ========================================================================
    // HTTP Implementation
    // ========================================================================

    /// Perform HTTP GET request
    fn get(self: *ErgoNodeClient, path: []const u8) HttpError![]const u8 {
        self.request_count += 1;
        self.last_error = null;

        // Build full URL
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "{s}{s}", .{ self.base_url, path }) catch
            return HttpError.InvalidUrl;

        // Use Zig's standard HTTP client
        var client = std.http.Client{ .allocator = std.heap.page_allocator };
        defer client.deinit();

        // Parse URI
        const uri = std.Uri.parse(url) catch {
            self.last_error = HttpError.InvalidUrl;
            return HttpError.InvalidUrl;
        };

        // Open connection
        var req = client.open(.GET, uri, .{
            .server_header_buffer = &[_]u8{},
        }) catch {
            self.last_error = HttpError.ConnectionFailed;
            return HttpError.ConnectionFailed;
        };
        defer req.deinit();

        // Send request
        req.send() catch {
            self.last_error = HttpError.NetworkError;
            return HttpError.NetworkError;
        };

        // Wait for response
        req.wait() catch {
            self.last_error = HttpError.Timeout;
            return HttpError.Timeout;
        };

        // Check status code
        const status = req.response.status;
        if (status == .not_found) {
            self.last_error = HttpError.NotFound;
            return HttpError.NotFound;
        }

        if (@intFromEnum(status) >= 500) {
            self.last_error = HttpError.ServerError;
            return HttpError.ServerError;
        }

        if (@intFromEnum(status) >= 400) {
            self.last_error = HttpError.InvalidResponse;
            return HttpError.InvalidResponse;
        }

        // Read response body
        var reader = req.reader();
        self.response_len = reader.readAll(&self.response_buffer) catch {
            self.last_error = HttpError.ResponseTooLarge;
            return HttpError.ResponseTooLarge;
        };

        self.success_count += 1;
        return self.response_buffer[0..self.response_len];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "http: ErgoNodeClient init" {
    const client = ErgoNodeClient.init("http://localhost:9052");
    try std.testing.expectEqualStrings("http://localhost:9052", client.base_url);
    try std.testing.expectEqual(@as(u32, DEFAULT_TIMEOUT_MS), client.timeout_ms);
    try std.testing.expectEqual(@as(u64, 0), client.request_count);
}

test "http: ErgoNodeClient setTimeout" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    client.setTimeout(5000);
    try std.testing.expectEqual(@as(u32, 5000), client.timeout_ms);
}

test "http: ErgoNodeClient stats" {
    var client = ErgoNodeClient.init("http://localhost:9052");
    client.request_count = 10;
    client.success_count = 8;

    const stats = client.getStats();
    try std.testing.expectEqual(@as(u64, 10), stats.requests);
    try std.testing.expectEqual(@as(u64, 8), stats.successes);
    try std.testing.expectEqual(@as(u64, 2), stats.failures);
}
