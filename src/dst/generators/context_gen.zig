//! Context Generator for DST
//!
//! Generates realistic blockchain contexts for expression evaluation.
//! Produces valid inputs, outputs, headers, and context extensions.
//!
//! Key features:
//!   - Realistic box values and tokens
//!   - Random register population
//!   - Valid block headers
//!   - Context extension variables

const std = @import("std");
const assert = std.debug.assert;
const prng_mod = @import("../prng.zig");
const PRNG = prng_mod.PRNG;
const Ratio = prng_mod.Ratio;

// Import from zigma module
const zigma = @import("zigma");
const context_mod = zigma.context;

const Context = context_mod.Context;
const BoxView = context_mod.BoxView;
const HeaderView = context_mod.HeaderView;
const PreHeaderView = context_mod.PreHeaderView;
const Token = context_mod.Token;
const VersionContext = context_mod.VersionContext;

// ============================================================================
// Configuration
// ============================================================================

/// Default maximum inputs
const default_max_inputs: u8 = 10;

/// Default maximum outputs
const default_max_outputs: u8 = 10;

/// Default maximum data inputs
const default_max_data_inputs: u8 = 5;

/// Default headers count
const default_headers_count: u8 = 10;

// ============================================================================
// Types
// ============================================================================

/// Context generation options
pub const ContextGenOptions = struct {
    /// Minimum number of inputs (must be >= 1)
    min_inputs: u8 = 1,
    /// Maximum number of inputs
    max_inputs: u8 = default_max_inputs,

    /// Minimum number of outputs
    min_outputs: u8 = 1,
    /// Maximum number of outputs
    max_outputs: u8 = default_max_outputs,

    /// Minimum number of data inputs
    min_data_inputs: u8 = 0,
    /// Maximum number of data inputs
    max_data_inputs: u8 = default_max_data_inputs,

    /// Number of headers to generate
    headers_count: u8 = default_headers_count,

    // Box generation options
    /// Minimum box value in nanoERG
    min_box_value: i64 = 1000, // 0.000001 ERG
    /// Maximum box value in nanoERG
    max_box_value: i64 = 1_000_000_000_000, // 1000 ERG

    /// Probability of a register being populated (R4-R9)
    register_fill_probability: Ratio = .{ .numerator = 50, .denominator = 100 },

    /// Maximum number of tokens per box
    max_tokens_per_box: u8 = 5,

    /// Probability of a box having tokens
    token_probability: Ratio = .{ .numerator = 30, .denominator = 100 },

    // Height options
    /// Minimum block height
    min_height: u32 = 1,
    /// Maximum block height
    max_height: u32 = 2_000_000, // ~4 years of blocks at 2min/block

    /// Version context
    version: VersionContext = VersionContext.v2(),
};

/// Context generator
pub const ContextGenerator = struct {
    prng: *PRNG,
    options: ContextGenOptions,

    // Storage for generated data (fixed-size, no allocation)
    // These are static to avoid per-call allocation
    boxes: [256]BoxView = undefined,
    box_count: usize = 0,

    tokens_storage: [256][10]Token = undefined,
    register_storage: [256][6]?[64]u8 = undefined,

    headers: [16]HeaderView = undefined,

    pub fn init(prng: *PRNG, options: ContextGenOptions) ContextGenerator {
        assert(options.min_inputs >= 1);
        assert(options.max_inputs >= options.min_inputs);
        return .{
            .prng = prng,
            .options = options,
        };
    }

    /// Generate a complete context
    pub fn generate(self: *ContextGenerator) GeneratedContext {
        self.box_count = 0;

        // Generate height
        const height = self.prng.range_inclusive(u32, self.options.min_height, self.options.max_height);

        // Generate inputs
        const input_count = self.prng.range_inclusive(u8, self.options.min_inputs, self.options.max_inputs);
        const inputs_start = self.box_count;
        for (0..input_count) |_| {
            self.generateBox(height);
        }
        const inputs_end = self.box_count;

        // Generate outputs
        const output_count = self.prng.range_inclusive(u8, self.options.min_outputs, self.options.max_outputs);
        const outputs_start = self.box_count;
        for (0..output_count) |_| {
            self.generateBox(height);
        }
        const outputs_end = self.box_count;

        // Generate data inputs
        const data_input_count = self.prng.range_inclusive(u8, self.options.min_data_inputs, self.options.max_data_inputs);
        const data_inputs_start = self.box_count;
        for (0..data_input_count) |_| {
            self.generateBox(height);
        }
        const data_inputs_end = self.box_count;

        // Generate headers
        const header_count = @min(self.options.headers_count, 16);
        for (0..header_count) |i| {
            self.headers[i] = self.generateHeader(@intCast(height -| i));
        }

        // Select self_index randomly from inputs
        const self_index = self.prng.range(u16, 0, input_count);

        // Create pre-header
        const pre_header = self.generatePreHeader(height);

        return .{
            .inputs = self.boxes[inputs_start..inputs_end],
            .outputs = self.boxes[outputs_start..outputs_end],
            .data_inputs = self.boxes[data_inputs_start..data_inputs_end],
            .headers = self.headers[0..header_count],
            .self_index = self_index,
            .height = height,
            .pre_header = pre_header,
        };
    }

    /// Generate a single box
    fn generateBox(self: *ContextGenerator, height: u32) void {
        if (self.box_count >= 256) return;

        const idx = self.box_count;

        // Generate box ID (random 32 bytes)
        var id: [32]u8 = undefined;
        self.prng.fill(&id);

        // Generate transaction ID
        var tx_id: [32]u8 = undefined;
        self.prng.fill(&tx_id);

        // Generate value
        const value = self.prng.range_inclusive(i64, self.options.min_box_value, self.options.max_box_value);

        // Creation height (before current height)
        const creation_height = self.prng.range_inclusive(u32, 1, @max(1, height -| 1));

        // Generate tokens
        var token_count: usize = 0;
        if (self.prng.chance(self.options.token_probability)) {
            token_count = self.prng.range_inclusive(u8, 1, self.options.max_tokens_per_box);
            for (0..token_count) |t| {
                var token_id: [32]u8 = undefined;
                self.prng.fill(&token_id);
                const amount = self.prng.range_inclusive(i64, 1, 1_000_000_000);
                self.tokens_storage[idx][t] = .{
                    .id = token_id,
                    .amount = amount,
                };
            }
        }

        // Generate registers R4-R9
        for (0..6) |r| {
            if (self.prng.chance(self.options.register_fill_probability)) {
                // Generate random register data (small bytes)
                const reg_len = self.prng.range_inclusive(u8, 1, 32);
                var reg_data: [64]u8 = undefined;
                self.prng.fill(reg_data[0..reg_len]);
                self.register_storage[idx][r] = reg_data;
            } else {
                self.register_storage[idx][r] = null;
            }
        }

        self.boxes[idx] = .{
            .id = id,
            .value = value,
            .proposition_bytes = &[_]u8{ 0x00, 0x7F }, // TrueLeaf (simple valid script)
            .creation_height = creation_height,
            .tx_id = tx_id,
            .index = @intCast(idx % 256),
            .tokens = self.tokens_storage[idx][0..token_count],
            .registers = blk: {
                var regs: [6]?[]const u8 = [_]?[]const u8{null} ** 6;
                for (0..6) |r| {
                    if (self.register_storage[idx][r]) |*reg| {
                        regs[r] = reg[0..32]; // First 32 bytes
                    }
                }
                break :blk regs;
            },
        };

        self.box_count += 1;
    }

    /// Generate a block header
    fn generateHeader(self: *ContextGenerator, height: u32) HeaderView {
        var id: [32]u8 = undefined;
        self.prng.fill(&id);

        var parent_id: [32]u8 = undefined;
        self.prng.fill(&parent_id);

        var ad_proofs_root: [32]u8 = undefined;
        self.prng.fill(&ad_proofs_root);

        var state_root: [44]u8 = undefined;
        self.prng.fill(&state_root);

        var transactions_root: [32]u8 = undefined;
        self.prng.fill(&transactions_root);

        var extension_root: [32]u8 = undefined;
        self.prng.fill(&extension_root);

        // Miner PK - valid compressed point (0x02 or 0x03 prefix)
        var miner_pk: [33]u8 = undefined;
        miner_pk[0] = if (self.prng.boolean()) 0x02 else 0x03;
        self.prng.fill(miner_pk[1..]);

        var pow_onetime_pk: [33]u8 = undefined;
        pow_onetime_pk[0] = if (self.prng.boolean()) 0x02 else 0x03;
        self.prng.fill(pow_onetime_pk[1..]);

        var pow_nonce: [8]u8 = undefined;
        self.prng.fill(&pow_nonce);

        var pow_distance: [32]u8 = undefined;
        self.prng.fill(&pow_distance);

        var votes: [3]u8 = undefined;
        self.prng.fill(&votes);

        // Timestamp: roughly 2 minutes per block from genesis
        const timestamp: u64 = 1561978800000 + @as(u64, height) * 120_000;

        return .{
            .id = id,
            .version = 2,
            .parent_id = parent_id,
            .ad_proofs_root = ad_proofs_root,
            .state_root = state_root,
            .transactions_root = transactions_root,
            .timestamp = timestamp,
            .n_bits = 0x01000000, // Standard difficulty encoding
            .height = height,
            .extension_root = extension_root,
            .miner_pk = miner_pk,
            .pow_onetime_pk = pow_onetime_pk,
            .pow_nonce = pow_nonce,
            .pow_distance = pow_distance,
            .votes = votes,
        };
    }

    /// Generate a pre-header
    fn generatePreHeader(self: *ContextGenerator, height: u32) PreHeaderView {
        var parent_id: [32]u8 = undefined;
        self.prng.fill(&parent_id);

        var miner_pk: [33]u8 = undefined;
        miner_pk[0] = if (self.prng.boolean()) 0x02 else 0x03;
        self.prng.fill(miner_pk[1..]);

        var votes: [3]u8 = undefined;
        self.prng.fill(&votes);

        const timestamp: u64 = 1561978800000 + @as(u64, height) * 120_000;

        return .{
            .version = 2,
            .parent_id = parent_id,
            .timestamp = timestamp,
            .n_bits = 0x01000000,
            .height = height,
            .miner_pk = miner_pk,
            .votes = votes,
        };
    }
};

/// Generated context data (references internal storage)
pub const GeneratedContext = struct {
    inputs: []const BoxView,
    outputs: []const BoxView,
    data_inputs: []const BoxView,
    headers: []const HeaderView,
    self_index: u16,
    height: u32,
    pre_header: PreHeaderView,

    /// Convert to a Context struct
    pub fn toContext(self: *const GeneratedContext) Context {
        return .{
            .inputs = self.inputs,
            .outputs = self.outputs,
            .data_inputs = self.data_inputs,
            .self_index = self.self_index,
            .height = self.height,
            .headers = self.headers,
            .pre_header = self.pre_header,
            .context_vars = [_]?[]const u8{null} ** context_mod.max_context_vars,
            .extension_cache = null,
        };
    }
};

pub const GenerateError = error{
    TooManyBoxes,
};

// ============================================================================
// Tests
// ============================================================================

test "context_gen: basic generation" {
    var prng = PRNG.from_seed(12345);

    var gen = ContextGenerator.init(&prng, .{});
    const generated = gen.generate();

    // Should have at least 1 input
    try std.testing.expect(generated.inputs.len >= 1);

    // Height should be valid
    try std.testing.expect(generated.height >= 1);

    // Self index should be valid
    try std.testing.expect(generated.self_index < generated.inputs.len);
}

test "context_gen: respects min/max" {
    var prng = PRNG.from_seed(67890);

    var gen = ContextGenerator.init(&prng, .{
        .min_inputs = 3,
        .max_inputs = 5,
        .min_outputs = 2,
        .max_outputs = 4,
        .min_height = 100000,
        .max_height = 200000,
    });

    const generated = gen.generate();

    try std.testing.expect(generated.inputs.len >= 3);
    try std.testing.expect(generated.inputs.len <= 5);
    try std.testing.expect(generated.outputs.len >= 2);
    try std.testing.expect(generated.outputs.len <= 4);
    try std.testing.expect(generated.height >= 100000);
    try std.testing.expect(generated.height <= 200000);
}

test "context_gen: determinism" {
    const seed: u64 = 99999;

    var prng1 = PRNG.from_seed(seed);
    var gen1 = ContextGenerator.init(&prng1, .{});
    const ctx1 = gen1.generate();

    var prng2 = PRNG.from_seed(seed);
    var gen2 = ContextGenerator.init(&prng2, .{});
    const ctx2 = gen2.generate();

    // Same seed should produce same context
    try std.testing.expectEqual(ctx1.inputs.len, ctx2.inputs.len);
    try std.testing.expectEqual(ctx1.outputs.len, ctx2.outputs.len);
    try std.testing.expectEqual(ctx1.height, ctx2.height);
    try std.testing.expectEqual(ctx1.self_index, ctx2.self_index);

    // Box values should match
    for (ctx1.inputs, ctx2.inputs) |b1, b2| {
        try std.testing.expectEqual(b1.value, b2.value);
        try std.testing.expectEqual(b1.creation_height, b2.creation_height);
    }
}

test "context_gen: box values in range" {
    var prng = PRNG.from_seed(11111);

    var gen = ContextGenerator.init(&prng, .{
        .min_box_value = 1000,
        .max_box_value = 100000,
    });

    const generated = gen.generate();

    for (generated.inputs) |box| {
        try std.testing.expect(box.value >= 1000);
        try std.testing.expect(box.value <= 100000);
    }
}

test "context_gen: to_context conversion" {
    var prng = PRNG.from_seed(22222);

    var gen = ContextGenerator.init(&prng, .{});
    const generated = gen.generate();
    const ctx = generated.toContext();

    // Verify context is valid
    try std.testing.expectEqual(generated.height, ctx.height);
    try std.testing.expectEqual(generated.self_index, ctx.self_index);
    try std.testing.expectEqual(generated.inputs.len, ctx.inputs.len);

    // SELF should be accessible
    const self_box = ctx.getSelf();
    try std.testing.expect(self_box.value > 0);
}
