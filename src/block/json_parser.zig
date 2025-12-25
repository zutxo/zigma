//! JSON Parser for Ergo Blocks and Transactions
//!
//! Parses JSON responses from Ergo node API into block/transaction structures.
//! Uses pre-allocated storage to avoid dynamic allocation.

const std = @import("std");
const transaction = @import("transaction.zig");
const block_mod = @import("block.zig");
const utxo_mod = @import("utxo.zig");
const context = @import("../interpreter/context.zig");

pub const Transaction = transaction.Transaction;
pub const Input = transaction.Input;
pub const Output = transaction.Output;
pub const SpendingProof = transaction.SpendingProof;
pub const TransactionStorage = transaction.TransactionStorage;
pub const Block = block_mod.Block;
pub const BlockStorage = block_mod.BlockStorage;
pub const Extension = block_mod.Extension;
pub const BoxView = context.BoxView;
pub const HeaderView = context.HeaderView;
pub const Token = context.Token;
pub const UtxoStorage = utxo_mod.UtxoStorage;

// ============================================================================
// Parse Errors
// ============================================================================

pub const ParseError = error{
    /// JSON syntax error
    JsonSyntaxError,
    /// Missing required field
    MissingField,
    /// Invalid field type
    InvalidFieldType,
    /// Invalid hex string
    InvalidHex,
    /// Storage full
    StorageFull,
    /// Value out of range
    ValueOutOfRange,
    /// Allocator failure
    OutOfMemory,
};

// ============================================================================
// Hex Utilities
// ============================================================================

/// Parse hex string to fixed-size byte array
pub fn parseHex(comptime N: usize, hex: []const u8) ParseError![N]u8 {
    if (hex.len != N * 2) return ParseError.InvalidHex;

    var result: [N]u8 = undefined;
    for (0..N) |i| {
        const high = hexDigit(hex[i * 2]) orelse return ParseError.InvalidHex;
        const low = hexDigit(hex[i * 2 + 1]) orelse return ParseError.InvalidHex;
        result[i] = (high << 4) | low;
    }
    return result;
}

/// Parse hex string to dynamic byte slice (into provided buffer)
pub fn parseHexDynamic(hex: []const u8, buffer: []u8) ParseError![]u8 {
    if (hex.len % 2 != 0) return ParseError.InvalidHex;
    const len = hex.len / 2;
    if (len > buffer.len) return ParseError.StorageFull;

    for (0..len) |i| {
        const high = hexDigit(hex[i * 2]) orelse return ParseError.InvalidHex;
        const low = hexDigit(hex[i * 2 + 1]) orelse return ParseError.InvalidHex;
        buffer[i] = (high << 4) | low;
    }
    return buffer[0..len];
}

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ============================================================================
// JSON Value Helpers
// ============================================================================

/// Get string field from JSON object
fn getString(obj: std.json.Value, field: []const u8) ?[]const u8 {
    return switch (obj) {
        .object => |map| {
            if (map.get(field)) |val| {
                return switch (val) {
                    .string => |s| s,
                    else => null,
                };
            }
            return null;
        },
        else => null,
    };
}

/// Get integer field from JSON object
fn getInt(comptime T: type, obj: std.json.Value, field: []const u8) ?T {
    return switch (obj) {
        .object => |map| {
            if (map.get(field)) |val| {
                return switch (val) {
                    .integer => |i| std.math.cast(T, i),
                    else => null,
                };
            }
            return null;
        },
        else => null,
    };
}

/// Get array field from JSON object
fn getArray(obj: std.json.Value, field: []const u8) ?[]std.json.Value {
    return switch (obj) {
        .object => |map| {
            if (map.get(field)) |val| {
                return switch (val) {
                    .array => |a| a.items,
                    else => null,
                };
            }
            return null;
        },
        else => null,
    };
}

/// Get object field from JSON object
fn getObject(obj: std.json.Value, field: []const u8) ?std.json.Value {
    return switch (obj) {
        .object => |map| map.get(field),
        else => null,
    };
}

// ============================================================================
// Block Parsing
// ============================================================================

/// Parse block JSON into Block structure using pre-allocated storage
pub fn parseBlockJson(
    json_bytes: []const u8,
    storage: *BlockStorage,
    allocator: std.mem.Allocator,
) ParseError!Block {
    storage.reset();

    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_bytes,
        .{},
    ) catch return ParseError.JsonSyntaxError;
    defer parsed.deinit();

    return parseBlockValue(parsed.value, storage);
}

/// Parse block from JSON value
fn parseBlockValue(value: std.json.Value, storage: *BlockStorage) ParseError!Block {
    // Parse header
    const header_obj = getObject(value, "header") orelse return ParseError.MissingField;
    const header = try parseHeaderValue(header_obj);

    // Parse transactions
    // API returns "blockTransactions" object with "transactions" array inside
    // Or direct "transactions" array (test format)
    const txs_array = blk: {
        if (getObject(value, "blockTransactions")) |bt_obj| {
            if (getArray(bt_obj, "transactions")) |txs| {
                break :blk txs;
            }
        }
        if (getArray(value, "transactions")) |txs| {
            break :blk txs;
        }
        return ParseError.MissingField;
    };

    for (txs_array) |tx_val| {
        const tx = try parseTransactionValue(tx_val, &storage.tx_storage);
        storage.addTransaction(tx) catch return ParseError.StorageFull;
    }

    // Parse extension (optional)
    if (getObject(value, "extension")) |ext_obj| {
        if (getArray(ext_obj, "fields")) |fields| {
            for (fields) |field_val| {
                if (getArray(field_val, "")) |pair| {
                    if (pair.len >= 2) {
                        const key = getString(pair[0], "") orelse continue;
                        const val = getString(pair[1], "") orelse continue;
                        const val_bytes = storage.allocExtBytes(val.len / 2) catch continue;
                        _ = parseHexDynamic(val, val_bytes) catch continue;
                        const ext = Extension.init(key, val_bytes) catch continue;
                        storage.addExtension(ext) catch break;
                    }
                }
            }
        }
    }

    // Parse AD proofs (optional)
    if (getString(value, "adProofs")) |ad_hex| {
        var ad_buf: [256 * 1024]u8 = undefined;
        if (parseHexDynamic(ad_hex, &ad_buf)) |ad_bytes| {
            storage.setAdProofs(ad_bytes) catch {};
        } else |_| {}
    }

    return Block{
        .header = header,
        .transactions = storage.getTransactions(),
        .extension = storage.getExtensions(),
        .ad_proofs = storage.getAdProofs(),
    };
}

// ============================================================================
// Header Parsing
// ============================================================================

/// Parse header from JSON value
fn parseHeaderValue(value: std.json.Value) ParseError!HeaderView {
    var header = std.mem.zeroes(HeaderView);

    // Required fields
    if (getString(value, "id")) |id_hex| {
        header.id = try parseHex(32, id_hex);
    } else return ParseError.MissingField;

    if (getString(value, "parentId")) |parent_hex| {
        header.parent_id = try parseHex(32, parent_hex);
    } else return ParseError.MissingField;

    header.version = getInt(u8, value, "version") orelse 0;
    header.height = getInt(u32, value, "height") orelse return ParseError.MissingField;
    header.timestamp = getInt(u64, value, "timestamp") orelse 0;
    header.n_bits = getInt(u64, value, "nBits") orelse 0;

    // Merkle roots
    if (getString(value, "transactionsRoot")) |root_hex| {
        header.transactions_root = try parseHex(32, root_hex);
    }
    if (getString(value, "adProofsRoot")) |root_hex| {
        header.ad_proofs_root = try parseHex(32, root_hex);
    }
    if (getString(value, "stateRoot")) |root_hex| {
        if (root_hex.len == 88) { // 44 bytes = 88 hex chars
            header.state_root = try parseHex(44, root_hex);
        }
    }
    if (getString(value, "extensionRoot")) |root_hex| {
        header.extension_root = try parseHex(32, root_hex);
    }

    // Mining fields
    if (getString(value, "powSolutions")) |_| {
        // Parse from nested object if present
        if (getObject(value, "powSolutions")) |pow| {
            if (getString(pow, "pk")) |pk_hex| {
                if (pk_hex.len == 66) {
                    header.miner_pk = try parseHex(33, pk_hex);
                }
            }
            if (getString(pow, "n")) |n_hex| {
                if (n_hex.len == 16) {
                    header.pow_nonce = try parseHex(8, n_hex);
                }
            }
        }
    }

    // Votes
    if (getString(value, "votes")) |votes_hex| {
        if (votes_hex.len == 6) {
            header.votes = try parseHex(3, votes_hex);
        }
    }

    return header;
}

// ============================================================================
// Transaction Parsing
// ============================================================================

/// Parse transaction from JSON value
fn parseTransactionValue(value: std.json.Value, storage: *TransactionStorage) ParseError!Transaction {
    storage.reset();

    // Transaction ID
    var tx_id: [32]u8 = undefined;
    if (getString(value, "id")) |id_hex| {
        tx_id = try parseHex(32, id_hex);
    } else return ParseError.MissingField;

    // Inputs
    if (getArray(value, "inputs")) |inputs| {
        for (inputs) |input_val| {
            const input = try parseInputValue(input_val, storage);
            _ = storage.addInput(input) catch return ParseError.StorageFull;
        }
    }

    // Data inputs
    if (getArray(value, "dataInputs")) |data_inputs| {
        for (data_inputs) |di_val| {
            if (getString(di_val, "boxId")) |box_id_hex| {
                const box_id = try parseHex(32, box_id_hex);
                if (storage.data_input_count < transaction.MAX_DATA_INPUTS) {
                    storage.data_inputs[storage.data_input_count] = box_id;
                    storage.data_input_count += 1;
                }
            }
        }
    }

    // Outputs
    if (getArray(value, "outputs")) |outputs| {
        for (outputs) |output_val| {
            const output = try parseOutputValue(output_val, storage);
            if (storage.output_count < transaction.MAX_OUTPUTS) {
                storage.outputs[storage.output_count] = output;
                storage.output_count += 1;
            }
        }
    }

    // Size (optional)
    const size = getInt(u32, value, "size") orelse 0;

    return Transaction{
        .id = tx_id,
        .inputs = storage.getInputs(),
        .data_inputs = storage.getDataInputs(),
        .outputs = storage.getOutputs(),
        .size = size,
    };
}

/// Parse input from JSON value
fn parseInputValue(value: std.json.Value, storage: *TransactionStorage) ParseError!Input {
    _ = storage;

    // Box ID
    var box_id: [32]u8 = undefined;
    if (getString(value, "boxId")) |box_id_hex| {
        box_id = try parseHex(32, box_id_hex);
    } else return ParseError.MissingField;

    // Spending proof
    var proof = SpendingProof.empty();
    if (getObject(value, "spendingProof")) |proof_obj| {
        if (getString(proof_obj, "proofBytes")) |proof_hex| {
            var proof_buf: [transaction.MAX_PROOF_SIZE]u8 = undefined;
            if (parseHexDynamic(proof_hex, &proof_buf)) |bytes| {
                proof = SpendingProof.fromSlice(bytes) catch SpendingProof.empty();
            } else |_| {}
        }
    }

    return Input{
        .box_id = box_id,
        .spending_proof = proof,
        .extension = transaction.ContextExtension.empty(),
    };
}

/// Parse output from JSON value
fn parseOutputValue(value: std.json.Value, storage: *TransactionStorage) ParseError!Output {
    // Value
    const val = getInt(i64, value, "value") orelse return ParseError.MissingField;

    // ErgoTree
    var ergo_tree: []const u8 = &[_]u8{};
    if (getString(value, "ergoTree")) |tree_hex| {
        const tree_bytes = storage.allocBytes(tree_hex.len / 2) catch return ParseError.StorageFull;
        ergo_tree = parseHexDynamic(tree_hex, tree_bytes) catch return ParseError.InvalidHex;
    }

    // Creation height
    const creation_height = getInt(u32, value, "creationHeight") orelse 0;

    // Tokens
    var tokens: []const Token = &[_]Token{};
    if (getArray(value, "assets")) |assets| {
        const token_start = storage.token_count;
        for (assets) |asset| {
            if (storage.token_count >= 4096) break; // TransactionStorage.tokens limit
            if (getString(asset, "tokenId")) |token_id_hex| {
                const token_id = parseHex(32, token_id_hex) catch continue;
                const amount = getInt(i64, asset, "amount") orelse continue;
                storage.tokens[storage.token_count] = Token{ .id = token_id, .amount = amount };
                storage.token_count += 1;
            }
        }
        tokens = storage.tokens[token_start..storage.token_count];
    }

    // Registers (R4-R9)
    var registers: [6]?[]const u8 = [_]?[]const u8{null} ** 6;
    if (getObject(value, "additionalRegisters")) |regs_obj| {
        inline for (4..10) |r| {
            const reg_name = comptime std.fmt.comptimePrint("R{d}", .{r});
            if (getString(regs_obj, reg_name)) |reg_hex| {
                if (storage.allocBytes(reg_hex.len / 2)) |reg_bytes| {
                    registers[r - 4] = parseHexDynamic(reg_hex, reg_bytes) catch null;
                } else |_| {
                    // Storage full, skip this register
                }
            }
        }
    }

    return Output{
        .value = val,
        .ergo_tree = ergo_tree,
        .creation_height = creation_height,
        .tokens = tokens,
        .registers = registers,
    };
}

// ============================================================================
// Box Parsing (for UTXO lookup)
// ============================================================================

/// Generic storage interface for box parsing
fn BoxStorageInterface(comptime T: type) type {
    return struct {
        pub fn allocBytes(storage: *T, len: usize) ![]u8 {
            return storage.allocBytes(len);
        }
        pub fn allocTokens(storage: *T, count: usize) ![]context.Token {
            return storage.allocTokens(count);
        }
    };
}

/// Parse box from JSON into BoxView using pre-allocated storage
pub fn parseBoxJson(
    json_bytes: []const u8,
    storage: *UtxoStorage,
    allocator: std.mem.Allocator,
) ParseError!BoxView {
    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_bytes,
        .{},
    ) catch return ParseError.JsonSyntaxError;
    defer parsed.deinit();

    return parseBoxValueGeneric(UtxoStorage, parsed.value, storage);
}

/// Parse box from JSON using lightweight SingleBoxStorage
pub fn parseBoxJsonSimple(
    json_bytes: []const u8,
    storage: anytype,
    allocator: std.mem.Allocator,
) ParseError!BoxView {
    var parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json_bytes,
        .{},
    ) catch return ParseError.JsonSyntaxError;
    defer parsed.deinit();

    return parseBoxValueGeneric(@TypeOf(storage.*), parsed.value, storage);
}

/// Parse box from JSON value (generic over storage type)
fn parseBoxValueGeneric(comptime Storage: type, value: std.json.Value, storage: *Storage) ParseError!BoxView {
    var box = std.mem.zeroes(BoxView);

    // Box ID
    if (getString(value, "boxId")) |id_hex| {
        box.id = try parseHex(32, id_hex);
    } else return ParseError.MissingField;

    // Value
    box.value = getInt(i64, value, "value") orelse return ParseError.MissingField;

    // ErgoTree
    if (getString(value, "ergoTree")) |tree_hex| {
        const tree_bytes = storage.allocBytes(tree_hex.len / 2) catch return ParseError.StorageFull;
        box.proposition_bytes = parseHexDynamic(tree_hex, tree_bytes) catch return ParseError.InvalidHex;
    }

    // Creation info
    box.creation_height = getInt(u32, value, "creationHeight") orelse 0;
    if (getString(value, "transactionId")) |tx_id_hex| {
        box.tx_id = try parseHex(32, tx_id_hex);
    }
    box.index = getInt(u16, value, "index") orelse 0;

    // Tokens
    if (getArray(value, "assets")) |assets| {
        const token_slice = storage.allocTokens(assets.len) catch return ParseError.StorageFull;
        for (assets, 0..) |asset, i| {
            if (getString(asset, "tokenId")) |token_id_hex| {
                token_slice[i].id = parseHex(32, token_id_hex) catch continue;
                token_slice[i].amount = getInt(i64, asset, "amount") orelse 0;
            }
        }
        box.tokens = token_slice;
    }

    // Registers (R4-R9)
    if (getObject(value, "additionalRegisters")) |regs_obj| {
        inline for (4..10) |r| {
            const reg_name = comptime std.fmt.comptimePrint("R{d}", .{r});
            if (getString(regs_obj, reg_name)) |reg_hex| {
                if (storage.allocBytes(reg_hex.len / 2)) |reg_bytes| {
                    box.registers[r - 4] = parseHexDynamic(reg_hex, reg_bytes) catch null;
                } else |_| {
                    // Storage full, skip this register
                }
            }
        }
    }

    return box;
}

// ============================================================================
// Tests
// ============================================================================

test "json_parser: parseHex 32 bytes" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const result = try parseHex(32, hex);
    try std.testing.expectEqual(@as(u8, 0x01), result[0]);
    try std.testing.expectEqual(@as(u8, 0xef), result[31]);
}

test "json_parser: parseHex rejects wrong length" {
    const hex = "0123"; // 2 bytes, not 32
    try std.testing.expectError(ParseError.InvalidHex, parseHex(32, hex));
}

test "json_parser: parseHex rejects invalid chars" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdXX";
    try std.testing.expectError(ParseError.InvalidHex, parseHex(32, hex));
}

test "json_parser: parseHexDynamic" {
    var buffer: [4]u8 = undefined;
    const result = try parseHexDynamic("deadbeef", &buffer);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, result);
}
