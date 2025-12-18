//! Zigma Benchmark Framework
//!
//! TigerBeetle-style benchmark harness for measuring interpreter performance.
//! Supports warmup, timed iterations, and ns/op reporting.
//!
//! Usage:
//!   ./zig/zig build bench              # Debug benchmarks
//!   ./zig/zig build bench -Doptimize=ReleaseFast  # Release benchmarks
//!
//! Categories:
//!   - Crypto: blake2b256, sha256, point operations
//!   - Arithmetic: BigInt operations, numeric conversions
//!   - Collections: map, filter, fold, append
//!   - Evaluation: Full ErgoTree evaluation

const std = @import("std");
const zigma = @import("zigma");

const hash = zigma.hash;
const BigInt256 = zigma.bigint.BigInt256;
const secp256k1 = zigma.secp256k1;
const Evaluator = zigma.evaluator.Evaluator;
const Context = zigma.context.Context;
const ExprTree = zigma.expr_serializer.ExprTree;
const TypePool = zigma.types.TypePool;

// ============================================================================
// Benchmark Infrastructure
// ============================================================================

/// Benchmark timing and statistics
pub const Benchmark = struct {
    name: []const u8,
    iterations: u64 = 0,
    warmup_iterations: u64 = 100,
    total_ns: u64 = 0,
    min_ns: u64 = std.math.maxInt(u64),
    max_ns: u64 = 0,

    /// Timer state
    timer: std.time.Timer = undefined,

    const Self = @This();

    pub fn init(name: []const u8) Self {
        return .{
            .name = name,
            .timer = std.time.Timer.start() catch unreachable,
        };
    }

    /// Run benchmark with warmup and timed iterations
    pub fn run(self: *Self, comptime func: fn () void, target_iterations: u64) void {
        // Warmup phase (not timed)
        for (0..self.warmup_iterations) |_| {
            func();
        }

        // Timed phase
        self.iterations = target_iterations;
        self.total_ns = 0;
        self.min_ns = std.math.maxInt(u64);
        self.max_ns = 0;

        for (0..target_iterations) |_| {
            const start = std.time.nanoTimestamp();
            func();
            const end = std.time.nanoTimestamp();

            const elapsed: u64 = @intCast(end - start);
            self.total_ns += elapsed;
            self.min_ns = @min(self.min_ns, elapsed);
            self.max_ns = @max(self.max_ns, elapsed);
        }
    }

    /// Run benchmark with data (for size-varying benchmarks)
    pub fn runWithArg(self: *Self, comptime T: type, comptime func: fn (T) void, arg: T, target_iterations: u64) void {
        // Warmup phase
        for (0..self.warmup_iterations) |_| {
            func(arg);
        }

        // Timed phase
        self.iterations = target_iterations;
        self.total_ns = 0;
        self.min_ns = std.math.maxInt(u64);
        self.max_ns = 0;

        for (0..target_iterations) |_| {
            const start = std.time.nanoTimestamp();
            func(arg);
            const end = std.time.nanoTimestamp();

            const elapsed: u64 = @intCast(end - start);
            self.total_ns += elapsed;
            self.min_ns = @min(self.min_ns, elapsed);
            self.max_ns = @max(self.max_ns, elapsed);
        }
    }

    /// Get nanoseconds per operation
    pub fn nsPerOp(self: *const Self) u64 {
        if (self.iterations == 0) return 0;
        return self.total_ns / self.iterations;
    }

    /// Get operations per second
    pub fn opsPerSec(self: *const Self) u64 {
        if (self.total_ns == 0) return 0;
        return (self.iterations * 1_000_000_000) / self.total_ns;
    }

    /// Print benchmark results
    pub fn report(self: *const Self) void {
        const stdout = std.io.getStdOut().writer();
        const ns_per_op = self.nsPerOp();
        const ops_per_sec = self.opsPerSec();

        stdout.print("{s:<30} {d:>10} ns/op  {d:>12} ops/sec  (min: {d}, max: {d})\n", .{
            self.name,
            ns_per_op,
            ops_per_sec,
            self.min_ns,
            self.max_ns,
        }) catch {};
    }
};

/// Run all benchmarks and report results
pub fn runAllBenchmarks() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("\n", .{}) catch {};
    stdout.print("=" ** 80 ++ "\n", .{}) catch {};
    stdout.print("                         Zigma Benchmark Results\n", .{}) catch {};
    stdout.print("=" ** 80 ++ "\n\n", .{}) catch {};

    // Crypto benchmarks
    stdout.print("--- Crypto ---\n", .{}) catch {};
    benchBlake2b256();
    benchSha256();
    stdout.print("\n", .{}) catch {};

    // BigInt benchmarks
    stdout.print("--- BigInt ---\n", .{}) catch {};
    benchBigIntAdd();
    benchBigIntMul();
    benchBigIntMod();
    stdout.print("\n", .{}) catch {};

    // Point operations
    stdout.print("--- Curve (secp256k1) ---\n", .{}) catch {};
    benchPointDecode();
    benchPointMul();
    stdout.print("\n", .{}) catch {};

    // Evaluation benchmarks
    stdout.print("--- Evaluation ---\n", .{}) catch {};
    benchEvalTrueLeaf();
    benchEvalHeight();
    benchEvalComparison();
    stdout.print("\n", .{}) catch {};

    stdout.print("=" ** 80 ++ "\n", .{}) catch {};
}

// ============================================================================
// Crypto Benchmarks
// ============================================================================

var blake_input: [64]u8 = [_]u8{0x42} ** 64;
var blake_output: [32]u8 = undefined;

fn doBlake2b256() void {
    blake_output = hash.blake2b256(&blake_input);
}

fn benchBlake2b256() void {
    var bench = Benchmark.init("blake2b256 (64 bytes)");
    bench.run(doBlake2b256, 100_000);
    bench.report();
}

var sha_input: [64]u8 = [_]u8{0x42} ** 64;
var sha_output: [32]u8 = undefined;

fn doSha256() void {
    sha_output = hash.sha256(&sha_input);
}

fn benchSha256() void {
    var bench = Benchmark.init("sha256 (64 bytes)");
    bench.run(doSha256, 100_000);
    bench.report();
}

// ============================================================================
// BigInt Benchmarks
// ============================================================================

var bigint_a: BigInt256 = BigInt256.fromInt(0x123456789ABCDEF);
var bigint_b: BigInt256 = BigInt256.fromInt(0xFEDCBA98765432);
var bigint_result: BigInt256 = undefined;

fn doBigIntAdd() void {
    bigint_result = BigInt256.add(bigint_a, bigint_b) catch return;
}

fn benchBigIntAdd() void {
    var bench = Benchmark.init("BigInt256.add");
    bench.run(doBigIntAdd, 100_000);
    bench.report();
}

fn doBigIntMul() void {
    bigint_result = BigInt256.mul(bigint_a, bigint_b) catch return;
}

fn benchBigIntMul() void {
    var bench = Benchmark.init("BigInt256.mul");
    bench.run(doBigIntMul, 100_000);
    bench.report();
}

var bigint_mod: BigInt256 = BigInt256.fromInt(0xFFFF);

fn doBigIntMod() void {
    bigint_result = BigInt256.mod(bigint_a, bigint_mod) catch return;
}

fn benchBigIntMod() void {
    var bench = Benchmark.init("BigInt256.mod");
    bench.run(doBigIntMod, 50_000);
    bench.report();
}

// ============================================================================
// Point Benchmarks
// ============================================================================

const Point = secp256k1.Point;

// Generator point in compressed form
const generator_compressed: [33]u8 = .{
    0x02,
    0x79,
    0xBE,
    0x66,
    0x7E,
    0xF9,
    0xDC,
    0xBB,
    0xAC,
    0x55,
    0xA0,
    0x62,
    0x95,
    0xCE,
    0x87,
    0x0B,
    0x07,
    0x02,
    0x9B,
    0xFC,
    0xDB,
    0x2D,
    0xCE,
    0x28,
    0xD9,
    0x59,
    0xF2,
    0x81,
    0x5B,
    0x16,
    0xF8,
    0x17,
    0x98,
};

fn doPointDecode() void {
    _ = Point.decode(&generator_compressed) catch {};
}

fn benchPointDecode() void {
    var bench = Benchmark.init("Point.decode");
    bench.run(doPointDecode, 10_000);
    bench.report();
}

// Scalar as [4]u64 (little-endian limbs)
var scalar: [4]u64 = .{ 7, 0, 0, 0 };

fn doPointMul() void {
    const point = Point.decode(&generator_compressed) catch return;
    _ = point.mul(scalar);
}

fn benchPointMul() void {
    var bench = Benchmark.init("Point.mul");
    bench.run(doPointMul, 1_000);
    bench.report();
}

// ============================================================================
// Evaluation Benchmarks
// ============================================================================

fn doEvalTrueLeaf() void {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .true_leaf, .result_type = TypePool.BOOLEAN };
    tree.node_count = 1;

    const test_inputs = [_]zigma.context.BoxView{zigma.context.testBox()};
    const ctx = Context.forHeight(100, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    _ = eval.evaluate() catch {};
}

fn benchEvalTrueLeaf() void {
    var bench = Benchmark.init("eval: true_leaf");
    bench.run(doEvalTrueLeaf, 100_000);
    bench.report();
}

fn doEvalHeight() void {
    var tree = ExprTree.init();
    tree.nodes[0] = .{ .tag = .height, .result_type = TypePool.INT };
    tree.node_count = 1;

    const test_inputs = [_]zigma.context.BoxView{zigma.context.testBox()};
    const ctx = Context.forHeight(12345, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    _ = eval.evaluate() catch {};
}

fn benchEvalHeight() void {
    var bench = Benchmark.init("eval: height");
    bench.run(doEvalHeight, 100_000);
    bench.report();
}

fn doEvalComparison() void {
    var tree = ExprTree.init();

    // Create: height > 100
    tree.nodes[0] = .{
        .tag = .bin_op,
        .data = @intFromEnum(zigma.expr_serializer.BinOpKind.gt),
        .result_type = TypePool.BOOLEAN,
    };
    tree.nodes[1] = .{ .tag = .height, .result_type = TypePool.INT };
    tree.nodes[2] = .{ .tag = .constant, .data = 0, .result_type = TypePool.INT };
    tree.values[0] = .{ .int = 100 };
    tree.node_count = 3;
    tree.value_count = 1;

    const test_inputs = [_]zigma.context.BoxView{zigma.context.testBox()};
    const ctx = Context.forHeight(200, &test_inputs);

    var eval = Evaluator.init(&tree, &ctx);
    _ = eval.evaluate() catch {};
}

fn benchEvalComparison() void {
    var bench = Benchmark.init("eval: height > 100");
    bench.run(doEvalComparison, 50_000);
    bench.report();
}

// ============================================================================
// Entry Point
// ============================================================================

pub fn main() !void {
    runAllBenchmarks();
}

// ============================================================================
// Tests
// ============================================================================

test "benchmark: infrastructure" {
    var bench = Benchmark.init("test_bench");
    std.testing.expect(bench.iterations == 0) catch unreachable;
    std.testing.expect(bench.nsPerOp() == 0) catch unreachable;
}
