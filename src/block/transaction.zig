//! Transaction Types
//!
//! Data structures for Ergo transactions with spending proofs.
//! Designed for data-oriented processing with pre-allocated storage.

const std = @import("std");
const context = @import("../interpreter/context.zig");
const vlq = @import("../serialization/vlq.zig");

pub const Token = context.Token;

/// Maximum proof size per Ergo protocol (1KB)
pub const MAX_PROOF_SIZE: u16 = 1024;

/// Maximum inputs per transaction
pub const MAX_INPUTS: u16 = 256;

/// Maximum outputs per transaction
pub const MAX_OUTPUTS: u16 = 256;

/// Maximum data inputs per transaction
pub const MAX_DATA_INPUTS: u16 = 256;

/// Maximum tokens per box
pub const MAX_TOKENS: u16 = 256;

/// Maximum context extension variables
pub const MAX_EXTENSION_VARS: u16 = 256;

// ============================================================================
// Spending Proof
// ============================================================================

/// Spending proof for a transaction input.
/// Contains the serialized sigma proof bytes.
pub const SpendingProof = struct {
    /// Proof bytes (up to 1KB per Ergo protocol)
    bytes: [MAX_PROOF_SIZE]u8,
    /// Actual length of proof
    len: u16,

    /// Create empty proof
    pub fn empty() SpendingProof {
        return .{
            .bytes = [_]u8{0} ** MAX_PROOF_SIZE,
            .len = 0,
        };
    }

    /// Create from slice
    pub fn fromSlice(data: []const u8) !SpendingProof {
        if (data.len > MAX_PROOF_SIZE) {
            return error.ProofTooLarge;
        }
        var result = SpendingProof.empty();
        @memcpy(result.bytes[0..data.len], data);
        result.len = @intCast(data.len);
        return result;
    }

    /// Get proof as slice
    pub fn slice(self: *const SpendingProof) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Check if proof is empty (trivial proposition)
    pub fn isEmpty(self: *const SpendingProof) bool {
        return self.len == 0;
    }
};

// ============================================================================
// Context Extension
// ============================================================================

/// Context extension for a transaction input.
/// Contains key-value pairs passed to script evaluation.
pub const ContextExtension = struct {
    /// Extension values indexed by variable ID (0-255)
    values: [MAX_EXTENSION_VARS]?ExtensionValue,
    /// Count of populated values
    count: u16,

    pub const ExtensionValue = struct {
        /// Value bytes (serialized)
        data: []const u8,
        /// Type code
        type_code: u8,
    };

    /// Create empty extension
    pub fn empty() ContextExtension {
        return .{
            .values = [_]?ExtensionValue{null} ** MAX_EXTENSION_VARS,
            .count = 0,
        };
    }

    /// Get value by variable ID
    pub fn get(self: *const ContextExtension, var_id: u8) ?ExtensionValue {
        return self.values[var_id];
    }

    /// Set value by variable ID
    pub fn set(self: *ContextExtension, var_id: u8, value: ExtensionValue) void {
        if (self.values[var_id] == null) {
            self.count += 1;
        }
        self.values[var_id] = value;
    }
};

// ============================================================================
// Transaction Input
// ============================================================================

/// Transaction input: a reference to a box being spent with its proof.
pub const Input = struct {
    /// Box ID being spent (Blake2b256 hash)
    box_id: [32]u8,
    /// Spending proof (sigma protocol proof)
    spending_proof: SpendingProof,
    /// Context extension (additional values for script evaluation)
    extension: ContextExtension,

    /// Create from box ID and proof
    pub fn init(box_id: [32]u8, proof: SpendingProof) Input {
        return .{
            .box_id = box_id,
            .spending_proof = proof,
            .extension = ContextExtension.empty(),
        };
    }

    /// Create from box ID only (no proof yet)
    pub fn fromBoxId(box_id: [32]u8) Input {
        return .{
            .box_id = box_id,
            .spending_proof = SpendingProof.empty(),
            .extension = ContextExtension.empty(),
        };
    }
};

// ============================================================================
// Transaction Output
// ============================================================================

/// Transaction output: a new box being created.
pub const Output = struct {
    /// Value in nanoERGs
    value: i64,
    /// ErgoTree bytes (proposition/script)
    ergo_tree: []const u8,
    /// Creation height (block height when this tx is included)
    creation_height: u32,
    /// Tokens (id, amount) pairs
    tokens: []const Token,
    /// Additional registers R4-R9 (serialized values)
    registers: [6]?[]const u8,

    /// Create minimal output
    pub fn init(value: i64, ergo_tree: []const u8, creation_height: u32) Output {
        return .{
            .value = value,
            .ergo_tree = ergo_tree,
            .creation_height = creation_height,
            .tokens = &[_]Token{},
            .registers = [_]?[]const u8{null} ** 6,
        };
    }

    /// Get register by index (4-9 -> 0-5)
    pub fn getRegister(self: *const Output, reg_idx: u8) ?[]const u8 {
        if (reg_idx < 4 or reg_idx > 9) return null;
        return self.registers[reg_idx - 4];
    }

    /// Check if output has tokens
    pub fn hasTokens(self: *const Output) bool {
        return self.tokens.len > 0;
    }

    /// Get total token count
    pub fn tokenCount(self: *const Output) usize {
        return self.tokens.len;
    }
};

// ============================================================================
// Transaction
// ============================================================================

/// Signed transaction with inputs, outputs, and proofs.
pub const Transaction = struct {
    /// Transaction ID (Blake2b256 of unsigned tx bytes)
    id: [32]u8,
    /// Inputs with spending proofs
    inputs: []const Input,
    /// Data inputs (box IDs for read-only access)
    data_inputs: []const [32]u8,
    /// Outputs (new boxes)
    outputs: []const Output,
    /// Transaction size in bytes (for cost calculation)
    size: u32,

    /// Create transaction with basic fields
    pub fn init(
        id: [32]u8,
        inputs: []const Input,
        outputs: []const Output,
    ) Transaction {
        return .{
            .id = id,
            .inputs = inputs,
            .data_inputs = &[_][32]u8{},
            .outputs = outputs,
            .size = 0,
        };
    }

    /// Get number of inputs
    pub fn inputCount(self: *const Transaction) usize {
        return self.inputs.len;
    }

    /// Get number of outputs
    pub fn outputCount(self: *const Transaction) usize {
        return self.outputs.len;
    }

    /// Get number of data inputs
    pub fn dataInputCount(self: *const Transaction) usize {
        return self.data_inputs.len;
    }

    /// Check if transaction has data inputs
    pub fn hasDataInputs(self: *const Transaction) bool {
        return self.data_inputs.len > 0;
    }

    /// Calculate total output value
    pub fn totalOutputValue(self: *const Transaction) i64 {
        var total: i64 = 0;
        for (self.outputs) |out| {
            total = std.math.add(i64, total, out.value) catch return std.math.maxInt(i64);
        }
        return total;
    }

    /// Maximum size of bytes-to-sign buffer
    pub const MAX_BYTES_TO_SIGN: usize = 256 * 1024;

    /// Serialize transaction to bytes for signing (unsigned transaction format).
    /// This is the message that gets signed/verified in Ergo transactions.
    ///
    /// Format (Scala reference: ErgoLikeTransactionSerializer):
    /// - u16 BE: input count
    /// - For each input: box_id (32) + proof_size (u16 BE=0) + ext_count (u16 BE) + ext entries
    /// - u16 BE: data input count
    /// - For each data input: box_id (32)
    /// - VLQ: distinct token ID count
    /// - For each distinct token: token_id (32)
    /// - u16 BE: output count
    /// - For each output: value (u64 BE) + ergoTree + creation_height (VLQ) + tokens + registers
    ///
    /// Returns the number of bytes written, or error if buffer too small.
    pub fn bytesToSign(self: *const Transaction, buf: []u8) !usize {
        var pos: usize = 0;

        // Helper to write bytes
        const writeBytes = struct {
            fn f(b: []u8, p: *usize, data: []const u8) !void {
                if (p.* + data.len > b.len) return error.BufferTooSmall;
                @memcpy(b[p.* .. p.* + data.len], data);
                p.* += data.len;
            }
        }.f;

        // Helper to write VLQ
        const writeVLQ = struct {
            fn f(b: []u8, p: *usize, v: u64) !void {
                if (p.* + vlq.max_vlq_bytes > b.len) return error.BufferTooSmall;
                const written = vlq.encodeU64(v, b[p.*..][0..vlq.max_vlq_bytes]);
                p.* += written;
            }
        }.f;

        // 1. Input count (VLQ)
        try writeVLQ(buf, &pos, self.inputs.len);

        // For each input: box_id + proof_size (0) + extension
        for (self.inputs) |input| {
            // Box ID (32 bytes)
            try writeBytes(buf, &pos, &input.box_id);
            // Proof size = 0 for unsigned tx (VLQ)
            try writeVLQ(buf, &pos, 0);
            // Context extension: count (u8) + entries
            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = @intCast(input.extension.count);
            pos += 1;

            // Write extension entries (key byte + serialized value)
            for (input.extension.values, 0..) |maybe_val, var_id| {
                if (maybe_val) |val| {
                    // Key is variable ID (1 byte)
                    if (pos + 1 > buf.len) return error.BufferTooSmall;
                    buf[pos] = @intCast(var_id);
                    pos += 1;
                    // Value is already serialized bytes (with type prefix)
                    try writeBytes(buf, &pos, val.data);
                }
            }
        }

        // 2. Data input count (VLQ) + box IDs
        try writeVLQ(buf, &pos, self.data_inputs.len);
        for (self.data_inputs) |di| {
            try writeBytes(buf, &pos, &di);
        }

        // 3. Collect distinct token IDs from all outputs
        // Max 256 unique tokens per transaction (8KB on stack vs 128KB before)
        const max_distinct_tokens = 256;
        var distinct_tokens: [max_distinct_tokens][32]u8 = undefined;
        var distinct_count: u32 = 0;

        for (self.outputs) |output| {
            for (output.tokens) |token| {
                // Check if already in distinct list
                var found = false;
                for (distinct_tokens[0..distinct_count]) |dt| {
                    if (std.mem.eql(u8, &dt, &token.id)) {
                        found = true;
                        break;
                    }
                }
                if (!found and distinct_count < max_distinct_tokens) {
                    distinct_tokens[distinct_count] = token.id;
                    distinct_count += 1;
                }
            }
        }

        // Token count as VLQ
        try writeVLQ(buf, &pos, distinct_count);
        for (distinct_tokens[0..distinct_count]) |dt| {
            try writeBytes(buf, &pos, &dt);
        }

        // 4. Output count (VLQ) + serialized outputs
        try writeVLQ(buf, &pos, self.outputs.len);
        for (self.outputs) |output| {
            // Value as VLQ (unsigned, Scala uses putULong which is VLQ)
            try writeVLQ(buf, &pos, @bitCast(output.value));

            // ErgoTree: raw bytes (self-delimiting via header)
            try writeBytes(buf, &pos, output.ergo_tree);

            // Creation height as VLQ
            try writeVLQ(buf, &pos, output.creation_height);

            // Tokens: count (1 byte) + (index VLQ, amount VLQ) pairs
            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = @intCast(output.tokens.len);
            pos += 1;

            for (output.tokens) |token| {
                // Find token index in distinct list
                var token_idx: u32 = 0;
                for (distinct_tokens[0..distinct_count], 0..) |dt, idx| {
                    if (std.mem.eql(u8, &dt, &token.id)) {
                        token_idx = @intCast(idx);
                        break;
                    }
                }
                // Token index as VLQ
                try writeVLQ(buf, &pos, token_idx);
                // Token amount as VLQ
                try writeVLQ(buf, &pos, @bitCast(token.amount));
            }

            // Registers: count (1 byte) + serialized values (raw bytes)
            var reg_count: u8 = 0;
            for (output.registers) |reg| {
                if (reg != null) reg_count += 1;
            }

            if (pos + 1 > buf.len) return error.BufferTooSmall;
            buf[pos] = reg_count;
            pos += 1;

            for (output.registers) |maybe_reg| {
                if (maybe_reg) |reg| {
                    // Register value is already serialized - write raw bytes
                    try writeBytes(buf, &pos, reg);
                }
            }
        }

        return pos;
    }
};

// ============================================================================
// Pre-allocated Storage
// ============================================================================

/// Pre-allocated storage for parsing transactions without dynamic allocation.
/// Use for batch processing to avoid per-transaction allocations.
pub const TransactionStorage = struct {
    /// Input storage
    inputs: [MAX_INPUTS]Input,
    input_count: u16,
    /// Output storage
    outputs: [MAX_OUTPUTS]Output,
    output_count: u16,
    /// Data input storage
    data_inputs: [MAX_DATA_INPUTS][32]u8,
    data_input_count: u16,
    /// Token storage for all outputs (limited to 4096 total)
    tokens: [4096]Token,
    token_count: u16,
    /// Byte storage for ErgoTree and registers
    byte_arena: [64 * 1024]u8,
    byte_pos: usize,

    /// Initialize empty storage (WARNING: may overflow stack for large structs)
    pub fn init() TransactionStorage {
        return .{
            .inputs = undefined,
            .input_count = 0,
            .outputs = undefined,
            .output_count = 0,
            .data_inputs = undefined,
            .data_input_count = 0,
            .tokens = undefined,
            .token_count = 0,
            .byte_arena = undefined,
            .byte_pos = 0,
        };
    }

    /// Initialize in-place (avoids stack overflow for large struct)
    pub fn initInPlace(self: *TransactionStorage) void {
        self.input_count = 0;
        self.output_count = 0;
        self.data_input_count = 0;
        self.token_count = 0;
        self.byte_pos = 0;
    }

    /// Reset for reuse
    pub fn reset(self: *TransactionStorage) void {
        self.input_count = 0;
        self.output_count = 0;
        self.data_input_count = 0;
        self.token_count = 0;
        self.byte_pos = 0;
    }

    /// Allocate bytes from arena
    pub fn allocBytes(self: *TransactionStorage, len: usize) ![]u8 {
        if (self.byte_pos + len > self.byte_arena.len) {
            return error.ArenaFull;
        }
        const slice = self.byte_arena[self.byte_pos .. self.byte_pos + len];
        self.byte_pos += len;
        return slice;
    }

    /// Add input
    pub fn addInput(self: *TransactionStorage, input: Input) !*Input {
        if (self.input_count >= MAX_INPUTS) {
            return error.TooManyInputs;
        }
        self.inputs[self.input_count] = input;
        const ptr = &self.inputs[self.input_count];
        self.input_count += 1;
        return ptr;
    }

    /// Get inputs slice
    pub fn getInputs(self: *const TransactionStorage) []const Input {
        return self.inputs[0..self.input_count];
    }

    /// Get outputs slice
    pub fn getOutputs(self: *const TransactionStorage) []const Output {
        return self.outputs[0..self.output_count];
    }

    /// Get data inputs slice
    pub fn getDataInputs(self: *const TransactionStorage) []const [32]u8 {
        return self.data_inputs[0..self.data_input_count];
    }
};

// ============================================================================
// Tests
// ============================================================================

test "transaction: SpendingProof empty" {
    const proof = SpendingProof.empty();
    try std.testing.expect(proof.isEmpty());
    try std.testing.expectEqual(@as(u16, 0), proof.len);
}

test "transaction: SpendingProof fromSlice" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const proof = try SpendingProof.fromSlice(&data);
    try std.testing.expectEqual(@as(u16, 4), proof.len);
    try std.testing.expectEqualSlices(u8, &data, proof.slice());
}

test "transaction: SpendingProof rejects too large" {
    const large = [_]u8{0} ** (MAX_PROOF_SIZE + 1);
    try std.testing.expectError(error.ProofTooLarge, SpendingProof.fromSlice(&large));
}

test "transaction: Input creation" {
    var box_id: [32]u8 = undefined;
    @memset(&box_id, 0xAB);

    const input = Input.fromBoxId(box_id);
    try std.testing.expectEqualSlices(u8, &box_id, &input.box_id);
    try std.testing.expect(input.spending_proof.isEmpty());
}

test "transaction: Output creation" {
    const ergo_tree = [_]u8{ 0x00, 0x08, 0xcd };
    const output = Output.init(1000000, &ergo_tree, 500000);
    try std.testing.expectEqual(@as(i64, 1000000), output.value);
    try std.testing.expectEqual(@as(u32, 500000), output.creation_height);
    try std.testing.expect(!output.hasTokens());
}

test "transaction: Transaction totalOutputValue" {
    const ergo_tree = [_]u8{0x00};
    const outputs = [_]Output{
        Output.init(1000, &ergo_tree, 100),
        Output.init(2000, &ergo_tree, 100),
        Output.init(3000, &ergo_tree, 100),
    };
    var id: [32]u8 = undefined;
    @memset(&id, 0);

    const tx = Transaction.init(id, &[_]Input{}, &outputs);
    try std.testing.expectEqual(@as(i64, 6000), tx.totalOutputValue());
}

test "transaction: TransactionStorage reset" {
    var storage = TransactionStorage.init();
    storage.input_count = 10;
    storage.output_count = 5;
    storage.byte_pos = 1000;

    storage.reset();

    try std.testing.expectEqual(@as(u16, 0), storage.input_count);
    try std.testing.expectEqual(@as(u16, 0), storage.output_count);
    try std.testing.expectEqual(@as(usize, 0), storage.byte_pos);
}

test "transaction: TransactionStorage allocBytes" {
    var storage = TransactionStorage.init();

    const slice1 = try storage.allocBytes(100);
    try std.testing.expectEqual(@as(usize, 100), slice1.len);

    const slice2 = try storage.allocBytes(200);
    try std.testing.expectEqual(@as(usize, 200), slice2.len);

    try std.testing.expectEqual(@as(usize, 300), storage.byte_pos);
}
