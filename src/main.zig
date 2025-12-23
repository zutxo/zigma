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
        \\  deserialize <hex>       Deserialize and display ErgoTree
        \\  hash <algorithm> <hex>  Compute hash (blake2b256, sha256)
        \\  help                    Show this help message
        \\
        \\Examples:
        \\  zigma version
        \\  zigma eval 00d191a37300 --height=500000
        \\  zigma eval-scenario scenario.json
        \\  zigma deserialize 00d191a37300
        \\  zigma hash blake2b256 616263
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
    }
}
