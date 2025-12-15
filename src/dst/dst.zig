//! Deterministic Simulation Testing (DST) Main Simulator
//!
//! TigerBeetle-inspired DST for the zigma sigma-state interpreter.
//! Orchestrates expression generation, context fuzzing, and property verification.
//!
//! Usage:
//!   ./zig/zig build dst                     # Run with random seed
//!   ./zig/zig build dst -- --seed=12345     # Run with specific seed
//!   ./zig/zig build dst -- --seed=$(git rev-parse HEAD)  # CI mode

const std = @import("std");
const assert = std.debug.assert;

// DST modules
const prng_mod = @import("prng.zig");
const expr_gen_mod = @import("generators/expr_gen.zig");
const context_gen_mod = @import("generators/context_gen.zig");
const determinism_mod = @import("checkers/determinism.zig");
const cost_checker_mod = @import("checkers/cost_checker.zig");

const PRNG = prng_mod.PRNG;
const Ratio = prng_mod.Ratio;
const ExprGenerator = expr_gen_mod.ExprGenerator;
const ExprGenOptions = expr_gen_mod.ExprGenOptions;
const ContextGenerator = context_gen_mod.ContextGenerator;
const ContextGenOptions = context_gen_mod.ContextGenOptions;
const DeterminismChecker = determinism_mod.DeterminismChecker;
const DeterminismResult = determinism_mod.DeterminismResult;
const CostChecker = cost_checker_mod.CostChecker;
const CostCheckResult = cost_checker_mod.CostCheckResult;

// Zigma imports
const zigma = @import("zigma");
const ExprTree = zigma.expr_serializer.ExprTree;
const Context = zigma.context.Context;

const log = std.log.scoped(.dst);

// ============================================================================
// Configuration
// ============================================================================

/// Default number of ticks (evaluations) per run
const default_ticks_max: u64 = 10_000;

/// Default determinism check repetitions
const default_determinism_reps: u8 = 5;

// ============================================================================
// Types
// ============================================================================

/// Simulator options
pub const Options = struct {
    /// Initial seed (use parse_seed for git hash support)
    seed: u64,

    /// Maximum number of ticks (evaluations)
    ticks_max: u64 = default_ticks_max,

    /// Expression generation options
    expr_gen: ExprGenOptions = .{},

    /// Context generation options
    context_gen: ContextGenOptions = .{},

    /// Determinism repetitions
    determinism_repetitions: u8 = default_determinism_reps,

    /// Probability of checking determinism (expensive)
    determinism_check_probability: Ratio = .{ .numerator = 100, .denominator = 100 },

    /// Probability of checking cost invariants
    cost_check_probability: Ratio = .{ .numerator = 100, .denominator = 100 },

    /// Log progress every N ticks (0 = no logging)
    log_interval: u64 = 1000,
};

/// Simulation result
pub const SimulationResult = struct {
    status: Status,
    tick: u64,
    seed: u64,
    evaluations_total: u64,
    evaluations_success: u64,
    evaluations_failed: u64,
    determinism_checks: u64,
    determinism_failures: u64,
    cost_checks: u64,
    cost_violations: u64,

    pub const Status = enum {
        success,
        determinism_failure,
        cost_violation,
        generation_error,
    };
};

/// Main simulator
pub const Simulator = struct {
    prng: PRNG,
    options: Options,

    // Generators (stateful - contain storage)
    expr_gen: ExprGenerator,
    context_gen: ContextGenerator,

    // Checkers (stateless)
    determinism_checker: DeterminismChecker,

    // Shared tree storage
    tree: ExprTree,

    // Statistics
    evaluations_total: u64 = 0,
    evaluations_success: u64 = 0,
    evaluations_failed: u64 = 0,
    determinism_checks: u64 = 0,
    determinism_failures: u64 = 0,
    cost_checks: u64 = 0,
    cost_violations: u64 = 0,

    /// Initialize simulator with options
    pub fn init(options: Options) Simulator {
        var prng = PRNG.from_seed(options.seed);
        var tree = ExprTree.init();

        return .{
            .prng = prng,
            .options = options,
            .expr_gen = ExprGenerator.init(&prng, &tree, options.expr_gen),
            .context_gen = ContextGenerator.init(&prng, options.context_gen),
            .determinism_checker = .{ .repetitions = options.determinism_repetitions },
            .tree = tree,
        };
    }

    /// Run a single tick (one evaluation cycle)
    pub fn tick(self: *Simulator) TickResult {
        // 1. Generate expression tree
        self.tree.reset();
        self.expr_gen.tree = &self.tree;
        self.expr_gen.prng = &self.prng;
        self.expr_gen.generate() catch {
            return .generation_error;
        };

        // 2. Generate context
        self.context_gen.prng = &self.prng;
        const generated_ctx = self.context_gen.generate();
        const ctx = generated_ctx.toContext();

        // 3. Check determinism (if enabled for this tick)
        if (self.prng.chance(self.options.determinism_check_probability)) {
            const det_result = self.determinism_checker.check(&self.tree, &ctx);
            self.determinism_checks += 1;

            switch (det_result) {
                .deterministic => {},
                .non_deterministic => {
                    self.determinism_failures += 1;
                    return .determinism_failure;
                },
            }
        }

        // 4. Check cost invariants (if enabled for this tick)
        if (self.prng.chance(self.options.cost_check_probability)) {
            const cost_result = CostChecker.check(&self.tree, &ctx);
            self.cost_checks += 1;

            switch (cost_result) {
                .valid => |stats| {
                    self.evaluations_total += 1;
                    if (stats.success) {
                        self.evaluations_success += 1;
                    } else {
                        self.evaluations_failed += 1;
                    }
                },
                .violation => {
                    self.cost_violations += 1;
                    return .cost_violation;
                },
            }
        } else {
            // Just count the evaluation
            self.evaluations_total += 1;
        }

        return .success;
    }

    /// Run full simulation
    pub fn run(self: *Simulator) SimulationResult {
        const start_time = std.time.milliTimestamp();

        for (0..self.options.ticks_max) |tick_num| {
            // Progress logging
            if (self.options.log_interval > 0 and tick_num > 0 and tick_num % self.options.log_interval == 0) {
                const elapsed_ms = std.time.milliTimestamp() - start_time;
                const ticks_per_sec = if (elapsed_ms > 0) tick_num * 1000 / @as(u64, @intCast(elapsed_ms)) else 0;
                log.info("tick {}/{} ({} ticks/s) evals={} det_checks={} cost_checks={}", .{
                    tick_num,
                    self.options.ticks_max,
                    ticks_per_sec,
                    self.evaluations_total,
                    self.determinism_checks,
                    self.cost_checks,
                });
            }

            const tick_result = self.tick();

            switch (tick_result) {
                .success => {},
                .determinism_failure => {
                    return self.makeResult(.determinism_failure, tick_num);
                },
                .cost_violation => {
                    return self.makeResult(.cost_violation, tick_num);
                },
                .generation_error => {
                    return self.makeResult(.generation_error, tick_num);
                },
            }
        }

        return self.makeResult(.success, self.options.ticks_max);
    }

    fn makeResult(self: *Simulator, status: SimulationResult.Status, tick_num: u64) SimulationResult {
        return .{
            .status = status,
            .tick = tick_num,
            .seed = self.options.seed,
            .evaluations_total = self.evaluations_total,
            .evaluations_success = self.evaluations_success,
            .evaluations_failed = self.evaluations_failed,
            .determinism_checks = self.determinism_checks,
            .determinism_failures = self.determinism_failures,
            .cost_checks = self.cost_checks,
            .cost_violations = self.cost_violations,
        };
    }
};

const TickResult = enum {
    success,
    determinism_failure,
    cost_violation,
    generation_error,
};

// ============================================================================
// CLI Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var args = try std.process.argsWithAllocator(gpa.allocator());
    defer args.deinit();

    // Skip program name
    _ = args.skip();

    // Parse arguments
    var seed: ?u64 = null;
    var ticks_max: u64 = default_ticks_max;
    var lite_mode = false;

    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            const seed_str = arg["--seed=".len..];
            seed = prng_mod.parse_seed(seed_str) orelse {
                std.debug.print("Invalid seed: {s}\n", .{seed_str});
                return error.InvalidSeed;
            };
        } else if (std.mem.startsWith(u8, arg, "--ticks-max=")) {
            const ticks_str = arg["--ticks-max=".len..];
            ticks_max = std.fmt.parseUnsigned(u64, ticks_str, 10) catch {
                std.debug.print("Invalid ticks-max: {s}\n", .{ticks_str});
                return error.InvalidTicksMax;
            };
        } else if (std.mem.eql(u8, arg, "--lite")) {
            lite_mode = true;
        }
    }

    // Generate random seed if not provided
    const final_seed = seed orelse std.crypto.random.int(u64);

    // Configure options
    const options = Options{
        .seed = final_seed,
        .ticks_max = if (lite_mode) 1000 else ticks_max,
        .log_interval = if (lite_mode) 100 else 1000,
    };

    log.info("", .{});
    log.info("========================================", .{});
    log.info("    ZIGMA Deterministic Simulation Testing", .{});
    log.info("========================================", .{});
    log.info("", .{});
    log.info("SEED={}", .{final_seed});
    log.info("ticks_max={}", .{options.ticks_max});
    log.info("", .{});

    // Run simulation
    var sim = Simulator.init(options);
    const result = sim.run();

    // Report results
    log.info("", .{});
    log.info("========================================", .{});
    switch (result.status) {
        .success => {
            log.info("PASSED", .{});
        },
        .determinism_failure => {
            log.err("FAILED: Determinism failure at tick {}", .{result.tick});
            log.err("Reproduce with: --seed={}", .{result.seed});
        },
        .cost_violation => {
            log.err("FAILED: Cost violation at tick {}", .{result.tick});
            log.err("Reproduce with: --seed={}", .{result.seed});
        },
        .generation_error => {
            log.err("FAILED: Generation error at tick {}", .{result.tick});
            log.err("Reproduce with: --seed={}", .{result.seed});
        },
    }
    log.info("========================================", .{});
    log.info("", .{});
    log.info("Statistics:", .{});
    log.info("  evaluations: {} ({} success, {} failed)", .{
        result.evaluations_total,
        result.evaluations_success,
        result.evaluations_failed,
    });
    log.info("  determinism_checks: {} ({} failures)", .{
        result.determinism_checks,
        result.determinism_failures,
    });
    log.info("  cost_checks: {} ({} violations)", .{
        result.cost_checks,
        result.cost_violations,
    });
    log.info("", .{});

    if (result.status != .success) {
        return error.SimulationFailed;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "simulator: basic run" {
    var sim = Simulator.init(.{
        .seed = 12345,
        .ticks_max = 100,
        .log_interval = 0, // Disable logging in tests
    });

    const result = sim.run();

    try std.testing.expectEqual(SimulationResult.Status.success, result.status);
    try std.testing.expect(result.evaluations_total > 0);
}

test "simulator: determinism checks" {
    var sim = Simulator.init(.{
        .seed = 67890,
        .ticks_max = 50,
        .determinism_check_probability = Ratio.one(),
        .log_interval = 0,
    });

    const result = sim.run();

    try std.testing.expectEqual(SimulationResult.Status.success, result.status);
    try std.testing.expect(result.determinism_checks > 0);
    try std.testing.expectEqual(@as(u64, 0), result.determinism_failures);
}

test "simulator: cost checks" {
    var sim = Simulator.init(.{
        .seed = 11111,
        .ticks_max = 50,
        .cost_check_probability = Ratio.one(),
        .log_interval = 0,
    });

    const result = sim.run();

    try std.testing.expectEqual(SimulationResult.Status.success, result.status);
    try std.testing.expect(result.cost_checks > 0);
    try std.testing.expectEqual(@as(u64, 0), result.cost_violations);
}

test "simulator: seed reproducibility" {
    const seed: u64 = 99999;

    var sim1 = Simulator.init(.{
        .seed = seed,
        .ticks_max = 20,
        .log_interval = 0,
    });
    const result1 = sim1.run();

    var sim2 = Simulator.init(.{
        .seed = seed,
        .ticks_max = 20,
        .log_interval = 0,
    });
    const result2 = sim2.run();

    // Same seed should produce same results
    try std.testing.expectEqual(result1.status, result2.status);
    try std.testing.expectEqual(result1.evaluations_total, result2.evaluations_total);
    try std.testing.expectEqual(result1.evaluations_success, result2.evaluations_success);
}
