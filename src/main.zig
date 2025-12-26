const std = @import("std");
const zigma = @import("root.zig");

const Evaluator = zigma.evaluator.Evaluator;
const Context = zigma.context.Context;
const ExprTree = zigma.expr_serializer.ExprTree;
const ErgoTree = zigma.ergotree_serializer.ErgoTree;
const ergotree = zigma.ergotree_serializer;
const Value = zigma.data_serializer.Value;
const TypePool = zigma.TypePool;
const BumpAllocator = zigma.memory.BumpAllocator;
const hash = zigma.hash;

// Sigma protocol imports
const pipeline = zigma.pipeline;
const sigma_tree = zigma.sigma_tree;
const private_input = zigma.private_input;
const prover_mod = zigma.prover;
const SigmaBoolean = sigma_tree.SigmaBoolean;
const ProveDlog = sigma_tree.ProveDlog;
const PrivateInput = private_input.PrivateInput;
const DlogProverInput = private_input.DlogProverInput;
const Prover = prover_mod.Prover;

// Block verification imports
const block_mod = zigma.block;
const BlockVerifier = block_mod.BlockVerifier;
const Block = block_mod.Block;
const ErgoNodeClient = block_mod.ErgoNodeClient;
const json_parser = block_mod.json_parser;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "version")) {
        try printVersion();
    } else if (std.mem.eql(u8, command, "eval")) {
        if (args.len < 3) {
            std.debug.print("Error: eval requires ErgoTree hex argument\n", .{});
            printUsage();
            return;
        }
        try evalCommand(args[2], args[3..]);
    } else if (std.mem.eql(u8, command, "deserialize")) {
        if (args.len < 3) {
            std.debug.print("Error: deserialize requires hex argument\n", .{});
            printUsage();
            return;
        }
        try deserializeCommand(args[2], args[3..], allocator);
    } else if (std.mem.eql(u8, command, "hash")) {
        if (args.len < 4) {
            std.debug.print("Error: hash requires <algorithm> <hex> arguments\n", .{});
            printUsage();
            return;
        }
        try hashCommand(args[2], args[3]);
    } else if (std.mem.eql(u8, command, "eval-scenario")) {
        if (args.len < 3) {
            std.debug.print("Error: eval-scenario requires <file.json> argument\n", .{});
            printUsage();
            return;
        }
        try evalScenarioCommand(args[2], allocator);
    } else if (std.mem.eql(u8, command, "sign-tx")) {
        if (args.len < 3) {
            std.debug.print("Error: sign-tx requires <file.json> argument\n", .{});
            printUsage();
            return;
        }
        try signTxCommand(args[2], args[3..], allocator);
    } else if (std.mem.eql(u8, command, "verify-tx")) {
        if (args.len < 3) {
            std.debug.print("Error: verify-tx requires <file.json> argument\n", .{});
            printUsage();
            return;
        }
        try verifyTxCommand(args[2], args[3..], allocator);
    } else if (std.mem.eql(u8, command, "verify-block")) {
        if (args.len < 3) {
            std.debug.print("Error: verify-block requires <source> argument\n", .{});
            printUsage();
            return;
        }
        try verifyBlockCommand(args[2], args[3..], allocator);
    } else if (std.mem.eql(u8, command, "scan-testnet")) {
        try scanTestnetCommand(args[2..], allocator);
    } else if (std.mem.eql(u8, command, "prove")) {
        if (args.len < 3) {
            std.debug.print("Error: prove requires <public_key_hex> argument\n", .{});
            printUsage();
            return;
        }
        try proveCommand(args[2], args[3..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        if (args.len < 3) {
            std.debug.print("Error: verify requires <public_key_hex> argument\n", .{});
            printUsage();
            return;
        }
        try verifyCommand(args[2], args[3..]);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        std.debug.print("Error: Unknown command '{s}'\n", .{command});
        printUsage();
    }
}

fn printVersion() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("zigma 0.1.0\n", .{});
    try stdout.print("ErgoTree interpreter in Zig\n", .{});
}

fn printUsage() void {
    const stderr = std.io.getStdErr().writer();
    stderr.print(
        \\Usage: zigma <command> [options]
        \\
        \\Commands:
        \\  version                 Print version information
        \\  eval <hex>              Evaluate ErgoTree (hex-encoded)
        \\    --height=<n>          Block height for context (default: 1000000)
        \\  eval-scenario <file>    Evaluate scenario from JSON file
        \\  sign-tx <file>          Sign transaction inputs from JSON file
        \\    --secrets=<hex,...>   Comma-separated secret keys (32 bytes each)
        \\    --message=<hex>       Transaction bytes to sign (hex)
        \\  verify-tx <file>        Verify transaction proofs from JSON file
        \\    --message=<hex>       Transaction bytes that were signed (hex)
        \\  verify-block <source>   Verify all transactions in a block
        \\    <source>              JSON file path, --height=N, or --id=<hex>
        \\    --node=<url>          Node URL (default: http://localhost:9052)
        \\    -v, --verbose         Show per-transaction results
        \\    --cost-limit=<n>      Cost limit per tx (default: 10000000)
        \\  scan-testnet            Scan testnet blocks to find verification failures
        \\    --node=<url>          Node URL (default: http://localhost:9052)
        \\    --count=<n>           Number of blocks to scan (default: 100)
        \\    --from=<height>       Start from height (default: current tip)
        \\    --continue            Continue past first failure
        \\    -v, --verbose         Show per-block details
        \\  deserialize <hex>       Deserialize and display ErgoTree
        \\  hash <algorithm> <hex>  Compute hash (blake2b256, sha256)
        \\  prove <pk_hex>          Generate Schnorr proof for ProveDlog
        \\    --secret=<hex>        Secret key (32 bytes hex)
        \\    --message=<hex>       Message to sign (hex)
        \\  verify <pk_hex>         Verify Schnorr proof for ProveDlog
        \\    --proof=<hex>         Proof bytes (hex)
        \\    --message=<hex>       Message that was signed (hex)
        \\  help                    Show this help message
        \\
        \\Examples:
        \\  zigma version
        \\  zigma eval 00d191a37300 --height=500000
        \\  zigma eval-scenario scenario.json
        \\  zigma sign-tx tx.json --secrets=abc...,def... --message=deadbeef
        \\  zigma verify-tx tx.json --message=deadbeef
        \\  zigma verify-block block.json
        \\  zigma verify-block --height=500000 --node=http://localhost:9052
        \\  zigma deserialize 00d191a37300
        \\  zigma hash blake2b256 616263
        \\  zigma prove 03... --secret=abc123... --message=deadbeef
        \\  zigma verify 03... --proof=abc... --message=deadbeef
        \\
    , .{}) catch {};
}

fn evalCommand(hex: []const u8, extra_args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse optional height argument
    var height: u32 = 1000000;
    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--height=")) {
            const height_str = arg["--height=".len..];
            height = std.fmt.parseInt(u32, height_str, 10) catch {
                std.debug.print("Error: Invalid height value\n", .{});
                return;
            };
        }
    }

    // Decode hex
    var bytes: [4096]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&bytes, hex) catch {
        std.debug.print("Error: Invalid hex string\n", .{});
        return;
    };

    // Parse ErgoTree
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(4096).init();
    ergotree.deserialize(&tree, decoded, &arena) catch |err| {
        try stdout.print("{{\n  \"error\": \"parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };

    // Create context with a dummy input box
    const inputs = [_]zigma.context.BoxView{zigma.context.testBox()};
    const ctx = Context.forHeight(height, &inputs);

    // Evaluate
    var eval = Evaluator.init(&tree.expr_tree, &ctx);
    const eval_result = eval.evaluate();

    // Output JitCost (raw cost units, 10x BlockCost)
    const jit_cost = eval.cost_used;

    if (eval_result) |raw_value| {
        // Reduce trivial SigmaProps to booleans for script result
        const value = reduceSigmaPropIfTrivial(raw_value);
        try stdout.print("{{\n  \"success\": true,\n  \"result\": {{", .{});
        try stdout.print("\n    \"type\": \"{s}\",", .{valueTypeName(value)});
        try stdout.print("\n    \"value\": ", .{});
        try printValueJson(value, stdout);
        try stdout.print("\n  }},\n  \"cost\": {}\n}}\n", .{jit_cost});
    } else |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"{s}\",\n  \"cost\": {}\n}}\n", .{ @errorName(err), jit_cost });
    }
}

fn deserializeCommand(hex: []const u8, _: []const []const u8, _: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Decode hex
    var bytes: [4096]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&bytes, hex) catch {
        std.debug.print("Error: Invalid hex string\n", .{});
        return;
    };

    // Parse ErgoTree
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(4096).init();
    ergotree.deserialize(&tree, decoded, &arena) catch |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };

    try stdout.print("{{\n  \"success\": true,\n", .{});
    try stdout.print("  \"header\": {{\n", .{});
    try stdout.print("    \"version\": {},\n", .{@intFromEnum(tree.header.version)});
    try stdout.print("    \"has_size\": {},\n", .{tree.header.has_size});
    try stdout.print("    \"constant_segregation\": {}\n", .{tree.header.constant_segregation});
    try stdout.print("  }},\n", .{});
    try stdout.print("  \"node_count\": {},\n", .{tree.expr_tree.node_count});
    try stdout.print("  \"constant_count\": {}\n", .{tree.constant_count});
    try stdout.print("}}\n", .{});
}

fn valueTypeName(value: Value) []const u8 {
    return switch (value) {
        .unit => "SUnit",
        .boolean => "SBoolean",
        .byte => "SByte",
        .short => "SShort",
        .int => "SInt",
        .long => "SLong",
        .big_int => "SBigInt",
        .unsigned_big_int => "SUnsignedBigInt",
        .group_element => "SGroupElement",
        .sigma_prop => "SSigmaProp",
        .coll_byte => "Coll[Byte]",
        .coll => "Coll[_]",
        .option => "Option[_]",
        .box => "SBox",
        .header => "SHeader",
        .pre_header => "SPreHeader",
        .avl_tree => "SAvlTree",
        .tuple => "Tuple",
        .box_coll => "Coll[Box]",
        .token_coll => "Coll[(Coll[Byte], Long)]",
        .hash32 => "Coll[Byte]",
        .soft_fork_placeholder => "SoftForkPlaceholder",
        .func_ref => "SFunc",
    };
}

fn evalScenarioCommand(path: []const u8, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Read the JSON file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"file_open_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };
    defer file.close();

    const json_content = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"file_read_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };
    defer allocator.free(json_content);

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_content, .{}) catch |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"json_parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Extract height from version_context
    var height: u32 = 1000000;
    if (root.object.get("version_context")) |vc| {
        if (vc.object.get("height")) |h| {
            height = @intCast(h.integer);
        }
    }

    // Get transaction object
    const tx = root.object.get("transaction") orelse {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"missing_transaction\"\n}}\n", .{});
        return;
    };

    // Parse inputs
    const inputs_json = tx.object.get("inputs") orelse {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"missing_inputs\"\n}}\n", .{});
        return;
    };

    // Build BoxViews from JSON
    var inputs: [256]zigma.context.BoxView = undefined;
    var input_count: usize = 0;

    // Token storage (pre-allocated)
    var all_tokens: [256 * 10]zigma.context.Token = undefined;
    var token_idx: usize = 0;

    // Proposition bytes storage (pre-allocated)
    var prop_bytes_storage: [256 * 512]u8 = undefined;
    var prop_bytes_idx: usize = 0;

    // Register storage (pre-allocated)
    var register_storage: [256 * 6 * 256]u8 = undefined;
    var register_idx: usize = 0;

    for (inputs_json.array.items) |input_obj| {
        if (input_count >= 256) break;

        const box = parseBoxFromJson(
            input_obj,
            &all_tokens,
            &token_idx,
            &prop_bytes_storage,
            &prop_bytes_idx,
            &register_storage,
            &register_idx,
        ) catch |err| {
            try stdout.print("{{\n  \"success\": false,\n  \"error\": \"box_parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
            return;
        };

        inputs[input_count] = box;
        input_count += 1;
    }

    if (input_count == 0) {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"no_inputs\"\n}}\n", .{});
        return;
    }

    // Parse outputs
    var outputs: [256]zigma.context.BoxView = undefined;
    var output_count: usize = 0;

    if (tx.object.get("outputs")) |outputs_json| {
        for (outputs_json.array.items) |output_obj| {
            if (output_count >= 256) break;

            const box = parseBoxFromJson(
                output_obj,
                &all_tokens,
                &token_idx,
                &prop_bytes_storage,
                &prop_bytes_idx,
                &register_storage,
                &register_idx,
            ) catch |err| {
                try stdout.print("{{\n  \"success\": false,\n  \"error\": \"output_parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
                return;
            };

            outputs[output_count] = box;
            output_count += 1;
        }
    }

    // Parse data_inputs
    var data_inputs: [256]zigma.context.BoxView = undefined;
    var data_input_count: usize = 0;

    if (tx.object.get("data_inputs")) |data_inputs_json| {
        for (data_inputs_json.array.items) |di_obj| {
            if (data_input_count >= 256) break;

            const box = parseBoxFromJson(
                di_obj,
                &all_tokens,
                &token_idx,
                &prop_bytes_storage,
                &prop_bytes_idx,
                &register_storage,
                &register_idx,
            ) catch |err| {
                try stdout.print("{{\n  \"success\": false,\n  \"error\": \"data_input_parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
                return;
            };

            data_inputs[data_input_count] = box;
            data_input_count += 1;
        }
    }

    // Get ErgoTree from first input
    const first_input = inputs_json.array.items[0];
    const ergotree_hex = first_input.object.get("ergotree_hex") orelse {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"missing_ergotree_hex\"\n}}\n", .{});
        return;
    };

    // Decode ErgoTree hex
    var tree_bytes: [4096]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&tree_bytes, ergotree_hex.string) catch {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"invalid_ergotree_hex\"\n}}\n", .{});
        return;
    };

    // Parse ErgoTree
    var type_pool = TypePool.init();
    var tree = ErgoTree.init(&type_pool);
    var arena = BumpAllocator(4096).init();
    ergotree.deserialize(&tree, decoded, &arena) catch |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"parse_error\",\n  \"message\": \"{s}\"\n}}\n", .{@errorName(err)});
        return;
    };

    // Build context with full transaction
    const ctx = Context{
        .inputs = inputs[0..input_count],
        .outputs = outputs[0..output_count],
        .data_inputs = data_inputs[0..data_input_count],
        .self_index = 0,
        .height = height,
        .headers = &[_]zigma.context.HeaderView{},
        .pre_header = .{
            .version = 2,
            .parent_id = [_]u8{0} ** 32,
            .timestamp = 0,
            .n_bits = 0,
            .height = height,
            .miner_pk = [_]u8{0} ** 33,
            .votes = [_]u8{0} ** 3,
        },
        .context_vars = [_]?[]const u8{null} ** zigma.context.max_context_vars,
        .extension_cache = null,
    };

    // Evaluate
    var eval = Evaluator.init(&tree.expr_tree, &ctx);
    const eval_result = eval.evaluate();

    // Output result
    const jit_cost = eval.cost_used;

    if (eval_result) |raw_value| {
        const value = reduceSigmaPropIfTrivial(raw_value);
        try stdout.print("{{\n  \"success\": true,\n  \"result\": {{", .{});
        try stdout.print("\n    \"type\": \"{s}\",", .{valueTypeName(value)});
        try stdout.print("\n    \"value\": ", .{});
        try printValueJson(value, stdout);
        try stdout.print("\n  }},\n  \"cost\": {}\n}}\n", .{jit_cost});
    } else |err| {
        try stdout.print("{{\n  \"success\": false,\n  \"error\": \"{s}\",\n  \"cost\": {}\n}}\n", .{ @errorName(err), jit_cost });
    }
}

fn parseBoxFromJson(
    obj: std.json.Value,
    all_tokens: *[256 * 10]zigma.context.Token,
    token_idx: *usize,
    prop_bytes_storage: *[256 * 512]u8,
    prop_bytes_idx: *usize,
    register_storage: *[256 * 6 * 256]u8,
    register_idx: *usize,
) !zigma.context.BoxView {
    var box: zigma.context.BoxView = undefined;

    // Parse box_id (32 bytes hex)
    if (obj.object.get("box_id")) |id_val| {
        _ = std.fmt.hexToBytes(&box.id, id_val.string) catch {
            box.id = [_]u8{0} ** 32;
        };
    } else {
        box.id = [_]u8{0} ** 32;
    }

    // Parse value (string to i64)
    if (obj.object.get("value")) |val| {
        box.value = switch (val) {
            .string => |s| std.fmt.parseInt(i64, s, 10) catch 0,
            .integer => |i| i,
            else => 0,
        };
    } else {
        box.value = 0;
    }

    // Parse creation_height
    if (obj.object.get("creation_height")) |ch| {
        box.creation_height = @intCast(ch.integer);
    } else {
        box.creation_height = 1;
    }

    // Parse ergotree_hex for proposition_bytes
    if (obj.object.get("ergotree_hex")) |hex| {
        const start = prop_bytes_idx.*;
        const decoded = std.fmt.hexToBytes(prop_bytes_storage[start..], hex.string) catch {
            // Default to TrueLeaf on parse error
            box.proposition_bytes = &[_]u8{ 0x00, 0x7F };
            return box;
        };
        box.proposition_bytes = decoded;
        prop_bytes_idx.* += decoded.len;
    } else {
        box.proposition_bytes = &[_]u8{ 0x00, 0x7F }; // TrueLeaf default
    }

    // Parse tokens
    const token_start = token_idx.*;
    if (obj.object.get("tokens")) |tokens_arr| {
        for (tokens_arr.array.items) |token_obj| {
            if (token_idx.* >= all_tokens.len) break;

            var token: zigma.context.Token = undefined;

            if (token_obj.object.get("id")) |id| {
                _ = std.fmt.hexToBytes(&token.id, id.string) catch {
                    token.id = [_]u8{0} ** 32;
                };
            } else {
                token.id = [_]u8{0} ** 32;
            }

            if (token_obj.object.get("amount")) |amt| {
                token.amount = switch (amt) {
                    .string => |s| std.fmt.parseInt(i64, s, 10) catch 0,
                    .integer => |i| i,
                    else => 0,
                };
            } else {
                token.amount = 0;
            }

            all_tokens[token_idx.*] = token;
            token_idx.* += 1;
        }
    }
    box.tokens = all_tokens[token_start..token_idx.*];

    // Parse tx_id (default to zeros)
    box.tx_id = [_]u8{0} ** 32;
    box.index = 0;

    // Parse registers (R4-R9 can be hex strings or {type_name, value} objects)
    box.registers = [_]?[]const u8{null} ** 6;
    if (obj.object.get("registers")) |regs| {
        const reg_names = [6][]const u8{ "R4", "R5", "R6", "R7", "R8", "R9" };
        for (reg_names, 0..) |reg_name, idx| {
            if (regs.object.get(reg_name)) |reg_val| {
                const start = register_idx.*;
                switch (reg_val) {
                    .string => |hex_str| {
                        // Hex-encoded register value
                        if (std.fmt.hexToBytes(register_storage[start..], hex_str)) |decoded| {
                            box.registers[idx] = decoded;
                            register_idx.* += decoded.len;
                        } else |_| {}
                    },
                    .object => |obj_map| {
                        // Structured register {type_name, value}
                        if (obj_map.get("type_name")) |type_name_val| {
                            const type_name = type_name_val.string;
                            const value_field = obj_map.get("value");
                            const encoded = encodeRegisterValue(type_name, value_field, register_storage[start..]);
                            if (encoded.len > 0) {
                                box.registers[idx] = register_storage[start .. start + encoded.len];
                                register_idx.* += encoded.len;
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    return box;
}

/// Encode a register value from JSON to binary format.
/// Returns the encoded bytes (slice of output buffer).
fn encodeRegisterValue(type_name: []const u8, value_opt: ?std.json.Value, output: []u8) []u8 {
    if (value_opt == null) return output[0..0];
    const value = value_opt.?;

    // Type codes from Ergo serialization
    const SByte: u8 = 0x01;
    const SShort: u8 = 0x02;
    const SInt: u8 = 0x04;
    const SLong: u8 = 0x05;
    const SGroupElement: u8 = 0x07;
    const SSigmaProp: u8 = 0x08;
    const SCollByte: u8 = 0x0C; // Coll[Byte] = 0x0C (12)

    // Simple integer types with VLQ ZigZag encoding
    if (std.mem.eql(u8, type_name, "SByte")) {
        const v: i8 = switch (value) {
            .integer => |i| @truncate(i),
            else => return output[0..0],
        };
        output[0] = SByte;
        const zigzag: u8 = @bitCast((v << 1) ^ (v >> 7));
        output[1] = zigzag;
        return output[0..2];
    }

    if (std.mem.eql(u8, type_name, "SShort")) {
        const v: i16 = switch (value) {
            .integer => |i| @truncate(i),
            else => return output[0..0],
        };
        output[0] = SShort;
        const zigzag: u16 = @bitCast(@as(i16, v << 1) ^ @as(i16, v >> 15));
        // VLQ encode
        var len: usize = 1;
        var val = zigzag;
        while (val >= 0x80) : (val >>= 7) {
            output[len] = @truncate((val & 0x7F) | 0x80);
            len += 1;
        }
        output[len] = @truncate(val);
        return output[0 .. len + 1];
    }

    if (std.mem.eql(u8, type_name, "SInt")) {
        const v: i32 = switch (value) {
            .integer => |i| @truncate(i),
            else => return output[0..0],
        };
        output[0] = SInt;
        const zigzag: u32 = @bitCast(@as(i32, v << 1) ^ @as(i32, v >> 31));
        // VLQ encode
        var len: usize = 1;
        var val = zigzag;
        while (val >= 0x80) : (val >>= 7) {
            output[len] = @truncate((val & 0x7F) | 0x80);
            len += 1;
        }
        output[len] = @truncate(val);
        return output[0 .. len + 1];
    }

    if (std.mem.eql(u8, type_name, "SLong")) {
        const v: i64 = switch (value) {
            .integer => |i| i,
            else => return output[0..0],
        };
        output[0] = SLong;
        const zigzag: u64 = @bitCast(@as(i64, v << 1) ^ @as(i64, v >> 63));
        // VLQ encode
        var len: usize = 1;
        var val = zigzag;
        while (val >= 0x80) : (val >>= 7) {
            output[len] = @truncate((val & 0x7F) | 0x80);
            len += 1;
        }
        output[len] = @truncate(val);
        return output[0 .. len + 1];
    }

    if (std.mem.eql(u8, type_name, "SBoolean")) {
        const hex_str = switch (value) {
            .string => |s| s,
            .bool => |b| return blk: {
                output[0] = 0x01; // SBoolean type code
                output[1] = if (b) 0x01 else 0x00;
                break :blk output[0..2];
            },
            else => return output[0..0],
        };
        // Hex-encoded boolean
        const decoded = std.fmt.hexToBytes(output[0..], hex_str) catch return output[0..0];
        return decoded;
    }

    // SGroupElement - 33 bytes compressed EC point
    if (std.mem.eql(u8, type_name, "SGroupElement")) {
        const hex_str = switch (value) {
            .string => |s| s,
            else => return output[0..0],
        };
        output[0] = SGroupElement;
        const decoded = std.fmt.hexToBytes(output[1..], hex_str) catch return output[0..0];
        return output[0 .. 1 + decoded.len];
    }

    // SSigmaProp - hex-encoded sigma proposition
    if (std.mem.eql(u8, type_name, "SSigmaProp")) {
        const hex_str = switch (value) {
            .string => |s| s,
            else => return output[0..0],
        };
        output[0] = SSigmaProp;
        const decoded = std.fmt.hexToBytes(output[1..], hex_str) catch return output[0..0];
        return output[0 .. 1 + decoded.len];
    }

    // Coll[Byte] / SColl[SByte] from hex string
    if (std.mem.eql(u8, type_name, "SColl[SByte]") or std.mem.eql(u8, type_name, "Coll[SByte]") or std.mem.eql(u8, type_name, "Coll[Byte]")) {
        const hex_str = switch (value) {
            .string => |s| s,
            else => return output[0..0],
        };
        // Decode hex first to get length
        var temp_buf: [1024]u8 = undefined;
        const decoded = std.fmt.hexToBytes(&temp_buf, hex_str) catch return output[0..0];
        const coll_len = decoded.len;

        output[0] = SCollByte;
        // VLQ encode length
        var pos: usize = 1;
        var len_val = coll_len;
        while (len_val >= 0x80) : (len_val >>= 7) {
            output[pos] = @truncate((len_val & 0x7F) | 0x80);
            pos += 1;
        }
        output[pos] = @truncate(len_val);
        pos += 1;
        // Copy bytes
        @memcpy(output[pos .. pos + coll_len], decoded);
        return output[0 .. pos + coll_len];
    }

    // Unsupported type
    return output[0..0];
}

fn hashCommand(algorithm: []const u8, hex: []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    // Decode hex input
    var input_bytes: [4096]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&input_bytes, hex) catch {
        try stdout.print("{{\"error\": \"invalid_hex\"}}\n", .{});
        return;
    };

    if (std.mem.eql(u8, algorithm, "blake2b256")) {
        const result = hash.blake2b256(decoded);
        try stdout.print("{{\"success\": true, \"result\": \"", .{});
        for (result) |b| {
            try stdout.print("{x:0>2}", .{b});
        }
        try stdout.print("\"}}\n", .{});
    } else if (std.mem.eql(u8, algorithm, "sha256")) {
        const result = hash.sha256(decoded);
        try stdout.print("{{\"success\": true, \"result\": \"", .{});
        for (result) |b| {
            try stdout.print("{x:0>2}", .{b});
        }
        try stdout.print("\"}}\n", .{});
    } else {
        try stdout.print("{{\"error\": \"unknown_algorithm\", \"message\": \"{s}\"}}\n", .{algorithm});
    }
}

/// Reduce SigmaProp to boolean if trivial.
/// Returns the reduced value (boolean) or original (non-trivial SigmaProp).
fn reduceSigmaPropIfTrivial(value: Value) Value {
    switch (value) {
        .sigma_prop => |sp| {
            if (sp.data.len >= 1) {
                // Trivial proposition markers:
                // From BoolToSigmaProp result: 0x01 = true, 0x00 = false
                // From constant serialization: 0xD3 (211) = TrivialPropTrue, 0xD2 (210) = TrivialPropFalse
                if (sp.data[0] == 0x01 or sp.data[0] == 0xD3) return .{ .boolean = true };
                if (sp.data[0] == 0x00 or sp.data[0] == 0xD2) return .{ .boolean = false };
            }
            return value; // Non-trivial, keep as SigmaProp
        },
        else => return value,
    }
}

fn printValueJson(value: Value, writer: anytype) !void {
    switch (value) {
        .boolean => |b| try writer.print("{}", .{b}),
        .byte => |b| try writer.print("{}", .{b}),
        .short => |s| try writer.print("{}", .{s}),
        .int => |i| try writer.print("{}", .{i}),
        .long => |l| try writer.print("{}", .{l}),
        .unit => try writer.print("null", .{}),
        .sigma_prop => try writer.print("\"<SigmaProp>\"", .{}),
        .group_element => try writer.print("\"<GroupElement>\"", .{}),
        .big_int => try writer.print("\"<BigInt>\"", .{}),
        .coll_byte => |bytes| {
            try writer.print("\"", .{});
            for (bytes) |b| {
                try writer.print("{x:0>2}", .{b});
            }
            try writer.print("\"", .{});
        },
        .coll => try writer.print("\"<Collection>\"", .{}),
        .option => |opt| {
            // null_value_idx is typically std.math.maxInt(u16)
            if (opt.value_idx == std.math.maxInt(u16)) {
                try writer.print("null", .{});
            } else {
                try writer.print("\"<Some>\"", .{});
            }
        },
        .box => try writer.print("\"<Box>\"", .{}),
        .header => try writer.print("\"<Header>\"", .{}),
        .pre_header => try writer.print("\"<PreHeader>\"", .{}),
        .avl_tree => try writer.print("\"<AvlTree>\"", .{}),
        .tuple => try writer.print("\"<Tuple>\"", .{}),
        .unsigned_big_int => try writer.print("\"<UnsignedBigInt>\"", .{}),
        .box_coll => try writer.print("\"<BoxCollection>\"", .{}),
        .token_coll => try writer.print("\"<TokenCollection>\"", .{}),
        .hash32 => |h| {
            try writer.print("\"", .{});
            for (h) |b| {
                try writer.print("{x:0>2}", .{b});
            }
            try writer.print("\"", .{});
        },
        .soft_fork_placeholder => try writer.print("\"<SoftForkPlaceholder>\"", .{}),
        .func_ref => try writer.print("\"<Function>\"", .{}),
    }
}

// ============================================================================
// Sigma Protocol Commands
// ============================================================================

/// Prove command: Generate a Schnorr proof for a ProveDlog proposition
/// Usage: zigma prove <pk_hex> --secret=<hex> --message=<hex>
fn proveCommand(pk_hex: []const u8, extra_args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse required arguments
    var secret_hex: ?[]const u8 = null;
    var message_hex: ?[]const u8 = null;

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--secret=")) {
            secret_hex = arg["--secret=".len..];
        } else if (std.mem.startsWith(u8, arg, "--message=")) {
            message_hex = arg["--message=".len..];
        }
    }

    if (secret_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_secret\", \"message\": \"--secret=<hex> required\"}}\n", .{});
        return;
    }

    if (message_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_message\", \"message\": \"--message=<hex> required\"}}\n", .{});
        return;
    }

    // Decode public key (33 bytes compressed)
    var pk_bytes: [33]u8 = undefined;
    if (std.fmt.hexToBytes(&pk_bytes, pk_hex)) |decoded| {
        if (decoded.len != 33) {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_pk_length\", \"message\": \"public key must be 33 bytes\"}}\n", .{});
            return;
        }
    } else |_| {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_pk_hex\"}}\n", .{});
        return;
    }

    // Decode secret key (32 bytes)
    var secret_bytes: [32]u8 = undefined;
    if (std.fmt.hexToBytes(&secret_bytes, secret_hex.?)) |decoded| {
        if (decoded.len != 32) {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_length\", \"message\": \"secret must be 32 bytes\"}}\n", .{});
            return;
        }
    } else |_| {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_hex\"}}\n", .{});
        return;
    }

    // Decode message
    var message_bytes: [4096]u8 = undefined;
    const message = std.fmt.hexToBytes(&message_bytes, message_hex.?) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_message_hex\"}}\n", .{});
        return;
    };

    // Create DlogProverInput from secret
    const dlog_input = DlogProverInput.init(secret_bytes) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_key\"}}\n", .{});
        return;
    };

    // Verify the public key matches the secret
    const derived_pk = dlog_input.publicImage();
    if (!std.mem.eql(u8, &derived_pk.public_key, &pk_bytes)) {
        try stdout.print("{{\"success\": false, \"error\": \"pk_secret_mismatch\", \"message\": \"public key does not match secret\"}}\n", .{});
        return;
    }

    // Create proposition
    const prop = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk_bytes) };

    // Generate proof
    const prove_result = pipeline.prove(prop, &[_]PrivateInput{.{ .dlog = dlog_input }}, message) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"proving_failed\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };

    // Output proof as hex
    try stdout.print("{{\"success\": true, \"proof\": \"", .{});
    for (prove_result.proofSlice()) |b| {
        try stdout.print("{x:0>2}", .{b});
    }
    try stdout.print("\", \"proof_len\": {}}}\n", .{prove_result.proof_len});
}

/// Verify command: Verify a Schnorr proof for a ProveDlog proposition
/// Usage: zigma verify <pk_hex> --proof=<hex> --message=<hex>
fn verifyCommand(pk_hex: []const u8, extra_args: []const []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse required arguments
    var proof_hex: ?[]const u8 = null;
    var message_hex: ?[]const u8 = null;

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--proof=")) {
            proof_hex = arg["--proof=".len..];
        } else if (std.mem.startsWith(u8, arg, "--message=")) {
            message_hex = arg["--message=".len..];
        }
    }

    if (proof_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_proof\", \"message\": \"--proof=<hex> required\"}}\n", .{});
        return;
    }

    if (message_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_message\", \"message\": \"--message=<hex> required\"}}\n", .{});
        return;
    }

    // Decode public key (33 bytes compressed)
    var pk_bytes: [33]u8 = undefined;
    if (std.fmt.hexToBytes(&pk_bytes, pk_hex)) |decoded| {
        if (decoded.len != 33) {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_pk_length\", \"message\": \"public key must be 33 bytes\"}}\n", .{});
            return;
        }
    } else |_| {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_pk_hex\"}}\n", .{});
        return;
    }

    // Decode proof
    var proof_bytes: [1024]u8 = undefined;
    const proof = std.fmt.hexToBytes(&proof_bytes, proof_hex.?) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_proof_hex\"}}\n", .{});
        return;
    };

    // Decode message
    var message_bytes: [4096]u8 = undefined;
    const message = std.fmt.hexToBytes(&message_bytes, message_hex.?) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_message_hex\"}}\n", .{});
        return;
    };

    // Create proposition
    const prop = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk_bytes) };

    // Verify proof
    const verify_result = pipeline.verify(prop, proof, message) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"verification_failed\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };

    try stdout.print("{{\"success\": true, \"valid\": {}, \"cost\": {}}}\n", .{ verify_result.valid, verify_result.cost });
}

/// Sign transaction command: Generate proofs for all inputs in a transaction
/// Usage: zigma sign-tx <file.json> --secrets=<hex,...> --message=<hex>
fn signTxCommand(path: []const u8, extra_args: []const []const u8, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse required arguments
    var secrets_hex: ?[]const u8 = null;
    var message_hex: ?[]const u8 = null;

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--secrets=")) {
            secrets_hex = arg["--secrets=".len..];
        } else if (std.mem.startsWith(u8, arg, "--message=")) {
            message_hex = arg["--message=".len..];
        }
    }

    if (secrets_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_secrets\", \"message\": \"--secrets=<hex,...> required\"}}\n", .{});
        return;
    }

    if (message_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_message\", \"message\": \"--message=<hex> required\"}}\n", .{});
        return;
    }

    // Decode message (transaction bytes to sign)
    var message_bytes: [8192]u8 = undefined;
    const message = std.fmt.hexToBytes(&message_bytes, message_hex.?) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_message_hex\"}}\n", .{});
        return;
    };

    // Parse secrets (comma-separated hex strings)
    var secrets: [16]PrivateInput = undefined;
    var secret_count: usize = 0;

    var secret_iter = std.mem.splitScalar(u8, secrets_hex.?, ',');
    while (secret_iter.next()) |secret_hex| {
        if (secret_count >= 16) {
            try stdout.print("{{\"success\": false, \"error\": \"too_many_secrets\", \"message\": \"max 16 secrets\"}}\n", .{});
            return;
        }

        var secret_bytes: [32]u8 = undefined;
        if (std.fmt.hexToBytes(&secret_bytes, secret_hex)) |decoded| {
            if (decoded.len != 32) {
                try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_length\", \"message\": \"secret {} must be 32 bytes\"}}\n", .{secret_count});
                return;
            }
        } else |_| {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_hex\", \"message\": \"secret {} invalid hex\"}}\n", .{secret_count});
            return;
        }

        const dlog_input = DlogProverInput.init(secret_bytes) catch {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_secret_key\", \"message\": \"secret {} invalid\"}}\n", .{secret_count});
            return;
        };

        secrets[secret_count] = .{ .dlog = dlog_input };
        secret_count += 1;
    }

    if (secret_count == 0) {
        try stdout.print("{{\"success\": false, \"error\": \"no_secrets\"}}\n", .{});
        return;
    }

    // Read the JSON file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"file_open_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer file.close();

    const json_content = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"file_read_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer allocator.free(json_content);

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_content, .{}) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"json_parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Extract height from version_context
    var height: u32 = 1000000;
    if (root.object.get("version_context")) |vc| {
        if (vc.object.get("height")) |h| {
            height = @intCast(h.integer);
        }
    }

    // Get transaction object
    const tx = root.object.get("transaction") orelse {
        try stdout.print("{{\"success\": false, \"error\": \"missing_transaction\"}}\n", .{});
        return;
    };

    // Parse inputs
    const inputs_json = tx.object.get("inputs") orelse {
        try stdout.print("{{\"success\": false, \"error\": \"missing_inputs\"}}\n", .{});
        return;
    };

    // Pre-allocated storage (same as eval-scenario)
    var inputs: [256]zigma.context.BoxView = undefined;
    var input_count: usize = 0;
    var all_tokens: [256 * 10]zigma.context.Token = undefined;
    var token_idx: usize = 0;
    var prop_bytes_storage: [256 * 512]u8 = undefined;
    var prop_bytes_idx: usize = 0;
    var register_storage: [256 * 6 * 256]u8 = undefined;
    var register_idx: usize = 0;

    for (inputs_json.array.items) |input_obj| {
        if (input_count >= 256) break;

        const box = parseBoxFromJson(
            input_obj,
            &all_tokens,
            &token_idx,
            &prop_bytes_storage,
            &prop_bytes_idx,
            &register_storage,
            &register_idx,
        ) catch |err| {
            try stdout.print("{{\"success\": false, \"error\": \"box_parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
            return;
        };

        inputs[input_count] = box;
        input_count += 1;
    }

    if (input_count == 0) {
        try stdout.print("{{\"success\": false, \"error\": \"no_inputs\"}}\n", .{});
        return;
    }

    // Parse outputs
    var outputs: [256]zigma.context.BoxView = undefined;
    var output_count: usize = 0;

    if (tx.object.get("outputs")) |outputs_json| {
        for (outputs_json.array.items) |output_obj| {
            if (output_count >= 256) break;

            const box = parseBoxFromJson(
                output_obj,
                &all_tokens,
                &token_idx,
                &prop_bytes_storage,
                &prop_bytes_idx,
                &register_storage,
                &register_idx,
            ) catch |err| {
                try stdout.print("{{\"success\": false, \"error\": \"output_parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
                return;
            };

            outputs[output_count] = box;
            output_count += 1;
        }
    }

    // Parse data_inputs
    var data_inputs: [256]zigma.context.BoxView = undefined;
    var data_input_count: usize = 0;

    if (tx.object.get("data_inputs")) |data_inputs_json| {
        for (data_inputs_json.array.items) |di_obj| {
            if (data_input_count >= 256) break;

            const box = parseBoxFromJson(
                di_obj,
                &all_tokens,
                &token_idx,
                &prop_bytes_storage,
                &prop_bytes_idx,
                &register_storage,
                &register_idx,
            ) catch |err| {
                try stdout.print("{{\"success\": false, \"error\": \"data_input_parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
                return;
            };

            data_inputs[data_input_count] = box;
            data_input_count += 1;
        }
    }

    // Output JSON start
    try stdout.print("{{\"success\": true, \"proofs\": [\n", .{});

    // Generate proof for each input
    var total_cost: u64 = 0;

    for (0..input_count) |i| {
        // Get ErgoTree from input
        const input_obj = inputs_json.array.items[i];
        const ergotree_hex = input_obj.object.get("ergotree_hex") orelse {
            try stdout.print("  {{\"input\": {}, \"error\": \"missing_ergotree_hex\"}}", .{i});
            if (i < input_count - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            continue;
        };

        // Decode ErgoTree
        var tree_bytes: [4096]u8 = undefined;
        const decoded = std.fmt.hexToBytes(&tree_bytes, ergotree_hex.string) catch {
            try stdout.print("  {{\"input\": {}, \"error\": \"invalid_ergotree_hex\"}}", .{i});
            if (i < input_count - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            continue;
        };

        // Parse ErgoTree
        var type_pool = TypePool.init();
        var tree = ErgoTree.init(&type_pool);
        var arena = BumpAllocator(4096).init();
        ergotree.deserialize(&tree, decoded, &arena) catch |err| {
            try stdout.print("  {{\"input\": {}, \"error\": \"parse_error\", \"message\": \"{s}\"}}", .{ i, @errorName(err) });
            if (i < input_count - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            continue;
        };

        // Build context for this input
        const ctx = Context{
            .inputs = inputs[0..input_count],
            .outputs = outputs[0..output_count],
            .data_inputs = data_inputs[0..data_input_count],
            .self_index = @intCast(i),
            .height = height,
            .headers = &[_]zigma.context.HeaderView{},
            .pre_header = .{
                .version = 2,
                .parent_id = [_]u8{0} ** 32,
                .timestamp = 0,
                .n_bits = 0,
                .height = height,
                .miner_pk = [_]u8{0} ** 33,
                .votes = [_]u8{0} ** 3,
            },
            .context_vars = [_]?[]const u8{null} ** zigma.context.max_context_vars,
            .extension_cache = null,
        };

        // Create evaluator and generate proof
        var eval = Evaluator.init(&tree.expr_tree, &ctx);

        const prove_result = pipeline.reduceAndProve(
            &eval,
            secrets[0..secret_count],
            message,
            pipeline.DEFAULT_COST_LIMIT,
        ) catch |err| {
            try stdout.print("  {{\"input\": {}, \"error\": \"proving_failed\", \"message\": \"{s}\"}}", .{ i, @errorName(err) });
            if (i < input_count - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            continue;
        };

        total_cost += prove_result.cost;

        // Output proof as hex
        try stdout.print("  {{\"input\": {}, \"proof\": \"", .{i});
        for (prove_result.proofSlice()) |b| {
            try stdout.print("{x:0>2}", .{b});
        }
        try stdout.print("\", \"proof_len\": {}, \"cost\": {}}}", .{ prove_result.proof_len, prove_result.cost });
        if (i < input_count - 1) try stdout.print(",", .{});
        try stdout.print("\n", .{});
    }

    try stdout.print("], \"total_cost\": {}}}\n", .{total_cost});
}

/// Verify transaction command: Verify proofs for all inputs in a transaction
/// Usage: zigma verify-tx <file.json> --message=<hex>
///
/// JSON format:
/// {
///   "inputs": [
///     { "ergotree_hex": "08cd...", "proof_hex": "abc123..." },
///     ...
///   ]
/// }
fn verifyTxCommand(path: []const u8, extra_args: []const []const u8, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse required arguments
    var message_hex: ?[]const u8 = null;

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--message=")) {
            message_hex = arg["--message=".len..];
        }
    }

    if (message_hex == null) {
        try stdout.print("{{\"success\": false, \"error\": \"missing_message\", \"message\": \"--message=<hex> required\"}}\n", .{});
        return;
    }

    // Decode message (transaction bytes)
    var message_bytes: [8192]u8 = undefined;
    const message = std.fmt.hexToBytes(&message_bytes, message_hex.?) catch {
        try stdout.print("{{\"success\": false, \"error\": \"invalid_message_hex\"}}\n", .{});
        return;
    };

    // Read the JSON file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"file_open_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer file.close();

    const json_content = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"file_read_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer allocator.free(json_content);

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_content, .{}) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"json_parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Get inputs array
    const inputs_json = root.object.get("inputs") orelse {
        try stdout.print("{{\"success\": false, \"error\": \"missing_inputs\"}}\n", .{});
        return;
    };

    // Output JSON start
    try stdout.print("{{\"success\": true, \"results\": [\n", .{});

    var all_valid = true;
    var total_cost: u64 = 0;

    for (inputs_json.array.items, 0..) |input_obj, i| {
        // Get ergotree_hex
        const ergotree_hex = input_obj.object.get("ergotree_hex") orelse {
            try stdout.print("  {{\"input\": {}, \"error\": \"missing_ergotree_hex\"}}", .{i});
            if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            all_valid = false;
            continue;
        };

        // Get proof_hex
        const proof_hex = input_obj.object.get("proof_hex") orelse {
            try stdout.print("  {{\"input\": {}, \"error\": \"missing_proof_hex\"}}", .{i});
            if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            all_valid = false;
            continue;
        };

        // Decode ErgoTree
        var tree_bytes: [4096]u8 = undefined;
        const decoded_tree = std.fmt.hexToBytes(&tree_bytes, ergotree_hex.string) catch {
            try stdout.print("  {{\"input\": {}, \"error\": \"invalid_ergotree_hex\"}}", .{i});
            if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            all_valid = false;
            continue;
        };

        // Decode proof
        var proof_bytes: [1024]u8 = undefined;
        const proof = std.fmt.hexToBytes(&proof_bytes, proof_hex.string) catch {
            try stdout.print("  {{\"input\": {}, \"error\": \"invalid_proof_hex\"}}", .{i});
            if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
            all_valid = false;
            continue;
        };

        // Try to parse as simple SigmaProp constant first (0x08cd... format)
        // Format: 0x08 (header) + 0xcd (SigmaPropConstant) + 33-byte public key
        var verify_result: pipeline.VerifyResult = undefined;

        if (decoded_tree.len >= 35 and decoded_tree[0] == 0x08 and decoded_tree[1] == 0xcd) {
            // Simple ProveDlog constant - verify directly
            var pk_bytes: [33]u8 = undefined;
            @memcpy(&pk_bytes, decoded_tree[2..35]);
            const prop = SigmaBoolean{ .prove_dlog = ProveDlog.init(pk_bytes) };

            verify_result = pipeline.verify(prop, proof, message) catch |err| {
                try stdout.print("  {{\"input\": {}, \"error\": \"verify_error\", \"message\": \"{s}\"}}", .{ i, @errorName(err) });
                if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
                try stdout.print("\n", .{});
                all_valid = false;
                continue;
            };
        } else {
            // Complex script - parse and reduce
            var type_pool = TypePool.init();
            var tree = ErgoTree.init(&type_pool);
            var arena = BumpAllocator(4096).init();
            ergotree.deserialize(&tree, decoded_tree, &arena) catch |err| {
                try stdout.print("  {{\"input\": {}, \"error\": \"parse_error\", \"message\": \"{s}\"}}", .{ i, @errorName(err) });
                if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
                try stdout.print("\n", .{});
                all_valid = false;
                continue;
            };

            // Build minimal context
            const dummy_box = zigma.context.testBox();
            const ctx_inputs = [_]zigma.context.BoxView{dummy_box};
            const ctx = Context.forHeight(1000000, &ctx_inputs);

            // Reduce and verify
            var eval = Evaluator.init(&tree.expr_tree, &ctx);
            verify_result = pipeline.reduceAndVerify(
                &eval,
                proof,
                message,
                pipeline.DEFAULT_COST_LIMIT,
            ) catch |err| {
                try stdout.print("  {{\"input\": {}, \"error\": \"verify_error\", \"message\": \"{s}\"}}", .{ i, @errorName(err) });
                if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
                try stdout.print("\n", .{});
                all_valid = false;
                continue;
            };
        }

        total_cost += verify_result.cost;
        if (!verify_result.valid) all_valid = false;

        try stdout.print("  {{\"input\": {}, \"valid\": {}, \"cost\": {}}}", .{ i, verify_result.valid, verify_result.cost });
        if (i < inputs_json.array.items.len - 1) try stdout.print(",", .{});
        try stdout.print("\n", .{});
    }

    try stdout.print("], \"all_valid\": {}, \"total_cost\": {}}}\n", .{ all_valid, total_cost });
}

/// Verify block command: Verify all transactions in a block
/// Usage: zigma verify-block <source> [options]
///
/// Source can be:
/// - JSON file path (e.g., "block.json")
/// - --height=N with --node=URL to fetch from node
/// - --id=<hex> with --node=URL to fetch by header ID
fn verifyBlockCommand(source: []const u8, extra_args: []const []const u8, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse options
    var node_url: []const u8 = "http://localhost:9052";
    var height: ?u32 = null;
    var header_id: ?[]const u8 = null;
    var verbose = false;
    var cost_limit: u64 = 10_000_000;

    // Check if source is an option
    if (std.mem.startsWith(u8, source, "--height=")) {
        const height_str = source["--height=".len..];
        height = std.fmt.parseInt(u32, height_str, 10) catch {
            try stdout.print("{{\"success\": false, \"error\": \"invalid_height\"}}\n", .{});
            return;
        };
    } else if (std.mem.startsWith(u8, source, "--id=")) {
        header_id = source["--id=".len..];
    }

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--node=")) {
            node_url = arg["--node=".len..];
        } else if (std.mem.startsWith(u8, arg, "--height=")) {
            const height_str = arg["--height=".len..];
            height = std.fmt.parseInt(u32, height_str, 10) catch {
                try stdout.print("{{\"success\": false, \"error\": \"invalid_height\"}}\n", .{});
                return;
            };
        } else if (std.mem.startsWith(u8, arg, "--id=")) {
            header_id = arg["--id=".len..];
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.startsWith(u8, arg, "--cost-limit=")) {
            const limit_str = arg["--cost-limit=".len..];
            cost_limit = std.fmt.parseInt(u64, limit_str, 10) catch {
                try stdout.print("{{\"success\": false, \"error\": \"invalid_cost_limit\"}}\n", .{});
                return;
            };
        }
    }

    // Determine data source
    var json_content: []u8 = undefined;
    var should_free = false;

    if (height != null or header_id != null) {
        // Fetch from node
        // ErgoNodeClient has 512KB buffer, must be heap-allocated
        const client = allocator.create(ErgoNodeClient) catch {
            try stdout.print("Error: Failed to allocate HTTP client\n", .{});
            return;
        };
        defer allocator.destroy(client);
        client.* = ErgoNodeClient.init(node_url);

        if (height) |h| {
            const result = client.getBlockAtHeight(h);
            if (result) |data| {
                // Copy to allocated buffer since client reuses internal buffer
                json_content = allocator.alloc(u8, data.len) catch {
                    try stdout.print("{{\"success\": false, \"error\": \"allocation_failed\"}}\n", .{});
                    return;
                };
                @memcpy(json_content, data);
                should_free = true;
            } else |err| {
                try stdout.print("{{\"success\": false, \"error\": \"fetch_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
                return;
            }
        } else if (header_id) |id_hex| {
            var id_bytes: [32]u8 = undefined;
            if (std.fmt.hexToBytes(&id_bytes, id_hex)) |decoded| {
                if (decoded.len != 32) {
                    try stdout.print("{{\"success\": false, \"error\": \"invalid_header_id\", \"message\": \"must be 32 bytes\"}}\n", .{});
                    return;
                }
            } else |_| {
                try stdout.print("{{\"success\": false, \"error\": \"invalid_header_id_hex\"}}\n", .{});
                return;
            }

            const result = client.getBlockById(&id_bytes);
            if (result) |data| {
                json_content = allocator.alloc(u8, data.len) catch {
                    try stdout.print("{{\"success\": false, \"error\": \"allocation_failed\"}}\n", .{});
                    return;
                };
                @memcpy(json_content, data);
                should_free = true;
            } else |err| {
                try stdout.print("{{\"success\": false, \"error\": \"fetch_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
                return;
            }
        }
    } else {
        // Read from file
        const file = std.fs.cwd().openFile(source, .{}) catch |err| {
            try stdout.print("{{\"success\": false, \"error\": \"file_open_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
            return;
        };
        defer file.close();

        json_content = file.readToEndAlloc(allocator, 4 * 1024 * 1024) catch |err| {
            try stdout.print("{{\"success\": false, \"error\": \"file_read_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
            return;
        };
        should_free = true;
    }

    defer if (should_free) allocator.free(json_content);

    // Parse block JSON
    // BlockStorage is huge (256KB+ for ad_proofs alone), must be heap-allocated
    const block_storage = allocator.create(block_mod.BlockStorage) catch {
        try stdout.print("Error: Failed to allocate block storage\n", .{});
        return;
    };
    defer allocator.destroy(block_storage);
    block_storage.initInPlace();
    const blk = json_parser.parseBlockJson(json_content, block_storage, allocator) catch |err| {
        try stdout.print("{{\"success\": false, \"error\": \"parse_error\", \"message\": \"{s}\"}}\n", .{@errorName(err)});
        return;
    };

    // Create verifier with empty UTXO source (will need to fetch from node)
    // For now, use a memory UTXO set from the block's transactions (outputs as UTXOs)
    // UtxoStorage is ~1.5MB, must be heap-allocated
    const utxo_storage = allocator.create(block_mod.UtxoStorage) catch {
        try stdout.print("Error: Failed to allocate UTXO storage\n", .{});
        return;
    };
    defer allocator.destroy(utxo_storage);
    utxo_storage.* = block_mod.UtxoStorage.init();

    // Build UTXO set from transaction outputs (for testing with pre-mined blocks)
    // In production, this would come from the node's UTXO set
    for (blk.transactions) |tx| {
        for (tx.outputs, 0..) |output, i| {
            // Create BoxView from Output
            var box_view: zigma.context.BoxView = std.mem.zeroes(zigma.context.BoxView);
            box_view.value = output.value;
            box_view.creation_height = output.creation_height;
            box_view.proposition_bytes = output.ergo_tree;
            box_view.index = @intCast(i);

            // Compute box ID per Ergo protocol:
            // Blake2b256(serialize(value, ergoTree, creationHeight, tokens, registers, txId, index))
            const box_id = block_mod.computeBoxId(&output, &tx.id, @intCast(i));

            utxo_storage.addBox(box_id, box_view) catch break;
        }
    }

    var utxo_set = utxo_storage.toUtxoSet();
    const utxo_source = utxo_set.asSource();

    // Initialize verifier on heap (struct is too large for stack)
    const verifier = allocator.create(BlockVerifier) catch {
        try stdout.print("Error: Failed to allocate verifier\n", .{});
        return;
    };
    defer allocator.destroy(verifier);
    verifier.initInPlace(utxo_source);
    verifier.setCostLimit(cost_limit);

    // Allocate result on heap (struct is 5MB+ due to tx_results array)
    const result = allocator.create(block_mod.BlockVerifyResult) catch {
        try stdout.print("Error: Failed to allocate block verify result\n", .{});
        return;
    };
    defer allocator.destroy(result);

    // Verify block (use in-place to avoid stack overflow)
    verifier.verifyBlockInPlace(&blk, result);

    // Output results
    try stdout.print("{{\n  \"success\": {},\n", .{result.valid});
    try stdout.print("  \"block_height\": {},\n", .{result.height});
    try stdout.print("  \"transaction_count\": {},\n", .{result.tx_count});
    try stdout.print("  \"total_cost\": {},\n", .{result.total_cost});
    try stdout.print("  \"merkle_valid\": {},\n", .{result.merkle_valid});

    if (result.first_error) |err| {
        try stdout.print("  \"error\": \"{s}\",\n", .{@errorName(err)});
    }

    try stdout.print("  \"tx_results_count\": {}", .{result.tx_count});

    if (verbose and result.tx_count > 0) {
        try stdout.print(",\n  \"tx_results\": [\n", .{});
        for (result.tx_results[0..result.tx_count], 0..) |tx_result, i| {
            try stdout.print("    {{\"index\": {}, \"valid\": {}, \"cost\": {}", .{ i, tx_result.valid, tx_result.total_cost });
            if (tx_result.first_error) |err| {
                try stdout.print(", \"error\": \"{s}\"", .{@errorName(err)});
            }
            try stdout.print("}}", .{});
            if (i < result.tx_count - 1) try stdout.print(",", .{});
            try stdout.print("\n", .{});
        }
        try stdout.print("  ]", .{});
    }

    try stdout.print("\n}}\n", .{});
}

// ============================================================================
// Scan Testnet Command
// ============================================================================

fn scanTestnetCommand(extra_args: []const []const u8, allocator: std.mem.Allocator) !void {
    const stdout = std.io.getStdOut().writer();

    // Parse options
    var node_url: []const u8 = "http://localhost:9052";
    var count: u32 = 100;
    var from_height: ?u32 = null;
    var continue_on_error = false;
    var verbose = false;

    for (extra_args) |arg| {
        if (std.mem.startsWith(u8, arg, "--node=")) {
            node_url = arg["--node=".len..];
        } else if (std.mem.startsWith(u8, arg, "--count=")) {
            const count_str = arg["--count=".len..];
            count = std.fmt.parseInt(u32, count_str, 10) catch {
                try stdout.print("Error: Invalid count value\n", .{});
                return;
            };
        } else if (std.mem.startsWith(u8, arg, "--from=")) {
            const from_str = arg["--from=".len..];
            from_height = std.fmt.parseInt(u32, from_str, 10) catch {
                try stdout.print("Error: Invalid from height value\n", .{});
                return;
            };
        } else if (std.mem.eql(u8, arg, "--continue")) {
            continue_on_error = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        }
    }

    try stdout.print("Connecting to node: {s}\n", .{node_url});

    // Initialize HTTP client on heap (large buffer would overflow stack)
    const client = allocator.create(ErgoNodeClient) catch {
        try stdout.print("Error: Failed to allocate HTTP client\n", .{});
        return;
    };
    defer allocator.destroy(client);
    client.* = ErgoNodeClient.init(node_url);

    // Get current height from node
    const current_height = blk: {
        const info = client.getNodeInfo() catch |err| {
            try stdout.print("Error: Failed to get node info: {s}\n", .{@errorName(err)});
            return;
        };
        // Parse fullHeight from JSON
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, info, .{}) catch {
            try stdout.print("Error: Failed to parse node info JSON\n", .{});
            return;
        };
        defer parsed.deinit();

        const height = switch (parsed.value) {
            .object => |obj| if (obj.get("fullHeight")) |h| switch (h) {
                .integer => |i| @as(u32, @intCast(i)),
                else => null,
            } else null,
            else => null,
        };

        if (height) |h| {
            break :blk h;
        } else {
            try stdout.print("Error: Could not get fullHeight from node info\n", .{});
            return;
        }
    };

    const start_height = from_height orelse current_height;
    try stdout.print("Scanning from height {} (current tip: {})\n", .{ start_height, current_height });
    try stdout.print("Will scan {} blocks, stopping on first failure: {}\n", .{ count, !continue_on_error });
    try stdout.print("\n", .{});

    // Initialize HTTP UTXO source on heap (struct is 32KB+)
    const http_utxo = allocator.create(block_mod.http_utxo.HttpUtxoSource) catch {
        try stdout.print("Error: Failed to allocate HTTP UTXO source\n", .{});
        return;
    };
    defer allocator.destroy(http_utxo);
    http_utxo.initInPlace(client, allocator);
    const utxo_source = http_utxo.asSource();

    // Initialize verifier on heap (struct is too large for stack)
    const verifier = allocator.create(BlockVerifier) catch {
        try stdout.print("Error: Failed to allocate verifier\n", .{});
        return;
    };
    defer allocator.destroy(verifier);
    verifier.initInPlace(utxo_source);

    // Allocate block storage on heap (struct is too large for stack - 500KB+)
    const block_storage = allocator.create(block_mod.BlockStorage) catch {
        try stdout.print("Error: Failed to allocate block storage\n", .{});
        return;
    };
    defer allocator.destroy(block_storage);
    block_storage.initInPlace();

    // Allocate result on heap (struct is 5MB+ due to tx_results array)
    const result = allocator.create(block_mod.BlockVerifyResult) catch {
        try stdout.print("Error: Failed to allocate block verify result\n", .{});
        return;
    };
    defer allocator.destroy(result);

    // Scan blocks
    var verified: u32 = 0;
    var failed: u32 = 0;
    var height = start_height;

    while (height > 0 and verified < count) {
        // Step 1: Get header IDs at this height
        const header_ids_json = client.getBlockAtHeight(height) catch |err| {
            try stdout.print("FETCH ERROR at height {}: {s}\n", .{ height, @errorName(err) });
            if (!continue_on_error) break;
            height -= 1;
            continue;
        };

        // Step 2: Parse the header ID array to get the first ID
        var header_id: [32]u8 = undefined;
        const got_header_id = blk: {
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, header_ids_json, .{}) catch {
                break :blk false;
            };
            defer parsed.deinit();

            const arr = switch (parsed.value) {
                .array => |a| a,
                else => break :blk false,
            };
            if (arr.items.len == 0) break :blk false;

            const hex_str = switch (arr.items[0]) {
                .string => |s| s,
                else => break :blk false,
            };
            if (hex_str.len != 64) break :blk false;
            _ = std.fmt.hexToBytes(&header_id, hex_str) catch break :blk false;
            break :blk true;
        };

        if (!got_header_id) {
            try stdout.print("ERROR at height {}: Failed to parse header ID\n", .{height});
            if (!continue_on_error) break;
            height -= 1;
            continue;
        }

        // Step 3: Fetch the full block by header ID
        const block_json = client.getBlockById(&header_id) catch |err| {
            try stdout.print("FETCH ERROR at height {} (block fetch): {s}\n", .{ height, @errorName(err) });
            if (!continue_on_error) break;
            height -= 1;
            continue;
        };

        // Copy json since client reuses buffer
        const json_copy = allocator.alloc(u8, block_json.len) catch {
            try stdout.print("Error: Allocation failed\n", .{});
            return;
        };
        @memcpy(json_copy, block_json);
        defer allocator.free(json_copy);

        // Parse block (reuse heap-allocated storage)
        block_storage.reset();
        const blk = json_parser.parseBlockJson(json_copy, block_storage, allocator) catch |err| {
            try stdout.print("PARSE ERROR at height {}: {s}\n", .{ height, @errorName(err) });
            failed += 1;
            if (!continue_on_error) break;
            height -= 1;
            continue;
        };

        // Verify block
        http_utxo.reset(); // Clear storage for new block
        verifier.verifyBlockInPlace(&blk, result);

        if (result.valid) {
            verified += 1;
            if (verbose) {
                try stdout.print("Block {}: OK ({} txs, {} cost)\n", .{ height, result.tx_count, result.total_cost });
            }
        } else {
            failed += 1;

            // Output failure details
            try stdout.print("\n========================================\n", .{});
            try stdout.print("FAILURE at block {} (id: ", .{height});
            for (result.block_id) |b| try stdout.print("{x:0>2}", .{b});
            try stdout.print(")\n", .{});

            if (result.first_error) |err| {
                const category = block_mod.BugCategory.fromError(err);
                try stdout.print("\nError: {s}\n", .{@errorName(err)});
                try stdout.print("Category: {s}\n", .{category.description()});
            }

            // Find first failed transaction
            for (result.tx_results[0..result.tx_count], 0..) |tx_result, tx_i| {
                if (!tx_result.valid) {
                    try stdout.print("\nTransaction {} failed", .{tx_i});
                    if (tx_result.first_error) |tx_err| {
                        try stdout.print(": {s}", .{@errorName(tx_err)});
                    }
                    try stdout.print("\n", .{});

                    // Find first failed input
                    for (tx_result.input_results[0..tx_result.input_count]) |input_result| {
                        if (!input_result.valid) {
                            try stdout.print("  Input {} failed", .{input_result.input_index});
                            if (input_result.err) |in_err| {
                                try stdout.print(": {s}", .{@errorName(in_err)});
                            }
                            try stdout.print("\n", .{});

                            // Print deserialization diagnostics if available
                            if (input_result.deser_diag) |diag| {
                                var diag_buf: [256]u8 = undefined;
                                const diag_str = diag.format(&diag_buf);
                                try stdout.print("  Diagnostics: {s}\n", .{diag_str});

                                // Show the phase and constant index if applicable
                                const phase_str = switch (diag.phase) {
                                    .header => "header parsing",
                                    .constants => "constant count",
                                    .constant_type => "constant type",
                                    .constant_value => "constant value",
                                    .expression => "expression parsing",
                                };
                                try stdout.print("  Phase: {s}\n", .{phase_str});
                                if (diag.constant_index) |ci| {
                                    try stdout.print("  Constant index: {}\n", .{ci});
                                }
                                if (diag.type_idx != null) {
                                    try stdout.print("  Constant type: {s}\n", .{diag.typeName()});
                                }
                            }

                            // Print evaluation diagnostics if available
                            if (input_result.eval_diag) |diag| {
                                if (diag.hasError()) {
                                    try stdout.print("  Eval error: {s}\n", .{diag.message()});
                                    if (diag.failed_opcode) |op| {
                                        try stdout.print("  Failed opcode: 0x{X:0>2}\n", .{op});
                                    }
                                    if (diag.failed_node_idx) |idx| {
                                        try stdout.print("  Node index: {}\n", .{idx});
                                    }
                                    if (diag.stack_depth) |depth| {
                                        try stdout.print("  Stack depth: {}\n", .{depth});
                                    }
                                    if (diag.cost_at_failure) |cost| {
                                        try stdout.print("  Cost consumed: {}\n", .{cost});
                                    }
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
            }

            try stdout.print("\nMerkle valid: {}\n", .{result.merkle_valid});
            try stdout.print("========================================\n\n", .{});

            if (!continue_on_error) {
                try stdout.print("Stopping scan. Use --continue to continue past failures.\n", .{});
                break;
            }
        }

        height -= 1;
    }

    // Summary
    try stdout.print("\n--- Summary ---\n", .{});
    try stdout.print("Blocks scanned: {}\n", .{verified + failed});
    try stdout.print("Verified OK: {}\n", .{verified});
    try stdout.print("Failed: {}\n", .{failed});

    const stats = http_utxo.getStats();
    try stdout.print("UTXO fetches: {} (errors: {})\n", .{ stats.misses, stats.errors });

    const verifier_stats = verifier.getStats();
    try stdout.print("Total cost: {}\n", .{verifier_stats.cost});
}
