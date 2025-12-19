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
        \\  version            Print version information
        \\  eval <hex>         Evaluate ErgoTree (hex-encoded)
        \\    --height=<n>     Block height for context (default: 1000000)
        \\  deserialize <hex>  Deserialize and display ErgoTree
        \\  hash <algorithm> <hex>  Compute hash (blake2b256, sha256)
        \\  help               Show this help message
        \\
        \\Examples:
        \\  zigma version
        \\  zigma eval 00d191a37300 --height=500000
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
        .hash32 => "Coll[Byte]",
        .soft_fork_placeholder => "SoftForkPlaceholder",
    };
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
