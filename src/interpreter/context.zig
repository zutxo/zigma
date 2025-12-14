//! Execution Context for ErgoTree Evaluation
//!
//! Provides the read-only blockchain environment accessible during script evaluation.
//! Context is validated BEFORE execution begins and immutable during evaluation.
//!
//! Key components:
//!   - HEIGHT: current block height
//!   - INPUTS: boxes being spent
//!   - OUTPUTS: boxes being created
//!   - SELF: the box containing this script
//!   - dataInputs: read-only reference boxes
//!   - headers: last N block headers
//!
//! Reference: ErgoTree Spec Section A.12 (Context type)

const std = @import("std");
const assert = std.debug.assert;

const context_extension_cache = @import("context_extension_cache.zig");
pub const ContextExtensionCache = context_extension_cache.ContextExtensionCache;
pub const ExtensionSource = context_extension_cache.ExtensionSource;

// ============================================================================
// Configuration
// ============================================================================

/// Maximum number of inputs per transaction
pub const max_inputs: usize = 256;

/// Maximum number of outputs per transaction
pub const max_outputs: usize = 256;

/// Maximum number of data inputs per transaction
pub const max_data_inputs: usize = 256;

/// Maximum number of headers accessible
pub const max_headers: usize = 10;

/// Maximum number of context variables
pub const max_context_vars: usize = 256;

// Compile-time sanity checks
comptime {
    // Limits must fit in u16 for indexing
    assert(max_inputs <= std.math.maxInt(u16));
    assert(max_outputs <= std.math.maxInt(u16));
    assert(max_data_inputs <= std.math.maxInt(u16));
    assert(max_headers <= 256);
}

// ============================================================================
// Register
// ============================================================================

/// Box register indices (R0-R9)
/// R0-R3 are mandatory, R4-R9 are user-defined
pub const Register = enum(u4) {
    R0 = 0, // Value (Long) - accessed via box.value
    R1 = 1, // Script (Coll[Byte]) - accessed via box.proposition_bytes
    R2 = 2, // Tokens (Coll[(Coll[Byte], Long)]) - accessed via box.tokens
    R3 = 3, // CreationInfo ((Int, Coll[Byte])) - computed from box fields
    R4 = 4, // User-defined
    R5 = 5, // User-defined
    R6 = 6, // User-defined
    R7 = 7, // User-defined
    R8 = 8, // User-defined
    R9 = 9, // User-defined

    /// Check if this is a mandatory register (R0-R3)
    pub fn isMandatory(self: Register) bool {
        return @intFromEnum(self) <= 3;
    }

    /// Check if this is a user-defined register (R4-R9)
    pub fn isUserDefined(self: Register) bool {
        return @intFromEnum(self) >= 4;
    }
};

// ============================================================================
// Token
// ============================================================================

/// Token representation: (tokenId, amount)
pub const Token = struct {
    /// Token ID (32 bytes, Blake2b hash)
    id: [32]u8,
    /// Token amount (signed for Ergo compatibility)
    amount: i64,
};

// ============================================================================
// BoxView
// ============================================================================

/// Immutable view of a box during evaluation.
/// Boxes are read-only in script context.
pub const BoxView = struct {
    /// Box ID (32 bytes Blake2b hash of serialized box)
    id: [32]u8,

    /// Value in nanoERGs
    value: i64,

    /// ErgoTree bytes (proposition script)
    proposition_bytes: []const u8,

    /// Creation height (block height when box was created)
    creation_height: u32,

    /// Transaction ID (32 bytes, hash of transaction that created this box)
    tx_id: [32]u8,

    /// Output index in creating transaction
    index: u16,

    /// Tokens: (tokenId, amount) pairs
    tokens: []const Token,

    /// Additional registers (R4-R9), serialized bytes
    /// null means register is not present
    registers: [6]?[]const u8,

    /// Get register value as serialized bytes
    /// R0-R3 return null (accessed via dedicated fields)
    /// R4-R9 return serialized register value or null if not set
    pub fn getRegister(self: *const BoxView, reg: Register) ?[]const u8 {
        assert(@intFromEnum(reg) <= 9);
        return switch (reg) {
            .R0 => null, // Value accessed via .value
            .R1 => self.proposition_bytes,
            .R2 => null, // Tokens accessed via .tokens
            .R3 => null, // CreationInfo computed from fields
            else => self.registers[@intFromEnum(reg) - 4],
        };
    }

    /// Check if a register is defined
    pub fn hasRegister(self: *const BoxView, reg: Register) bool {
        assert(@intFromEnum(reg) <= 9);
        return switch (reg) {
            .R0, .R1, .R2, .R3 => true, // Mandatory registers always present
            else => self.registers[@intFromEnum(reg) - 4] != null,
        };
    }
};

// ============================================================================
// HeaderView
// ============================================================================

/// Block header view (read-only)
pub const HeaderView = struct {
    /// Header ID (32 bytes Blake2b hash)
    id: [32]u8,
    /// Block version
    version: u8,
    /// Parent block ID
    parent_id: [32]u8,
    /// ADProofs root hash
    ad_proofs_root: [32]u8,
    /// State root (AvlTree digest, 44 bytes)
    state_root: [44]u8,
    /// Transactions root hash
    transactions_root: [32]u8,
    /// Block timestamp (milliseconds since epoch)
    timestamp: u64,
    /// Encoded difficulty target
    n_bits: u64,
    /// Block height
    height: u32,
    /// Extension root hash
    extension_root: [32]u8,
    /// Miner public key (SEC1 compressed, 33 bytes)
    miner_pk: [33]u8,
    /// PoW one-time public key
    pow_onetime_pk: [33]u8,
    /// PoW nonce (8 bytes)
    pow_nonce: [8]u8,
    /// PoW distance (BigInt as 32 bytes)
    pow_distance: [32]u8,
    /// Votes (3 bytes for soft-fork voting)
    votes: [3]u8,
};

// ============================================================================
// PreHeaderView
// ============================================================================

/// Pre-header: predictable parts of the current block being validated.
/// These are known before mining/PoW.
pub const PreHeaderView = struct {
    /// Block version
    version: u8,
    /// Parent block ID
    parent_id: [32]u8,
    /// Block timestamp
    timestamp: u64,
    /// Encoded difficulty target
    n_bits: u64,
    /// Block height
    height: u32,
    /// Miner public key (proposed)
    miner_pk: [33]u8,
    /// Votes
    votes: [3]u8,
};

// ============================================================================
// VersionContext
// ============================================================================

/// Protocol version context for evaluation.
/// Controls cost model selection and feature gating.
///
/// Ergo protocol versions:
///   v0: Pre-4.0 (legacy AOT interpreter)
///   v1: 4.0 hard fork (AOT with new cost model)
///   v2: 5.0 soft fork (JIT interpreter, current mainnet)
///   v3: 6.0 soft fork (EIP-50, new opcodes)
///
/// Reference: VersionContext.scala in sigmastate-interpreter
pub const VersionContext = struct {
    /// Network-activated protocol version (from block headers/consensus)
    /// This determines which cost model to use.
    activated_version: u8,

    /// ErgoTree script version (bits 0-2 of header byte)
    /// Scripts declare their target version.
    ergo_tree_version: u8,

    // -------------------------------------------------------------------------
    // Version Constants (matches Scala VersionContext)
    // -------------------------------------------------------------------------

    /// JIT interpreter activation version
    pub const JIT_ACTIVATION_VERSION: u8 = 2;

    /// v6 features activation version (EIP-50)
    pub const V6_ACTIVATION_VERSION: u8 = 3;

    /// Maximum valid version we support
    pub const MAX_SUPPORTED_VERSION: u8 = 3;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /// Create a VersionContext for v2 (current mainnet default)
    pub fn v2() VersionContext {
        return .{
            .activated_version = 2,
            .ergo_tree_version = 0,
        };
    }

    /// Create a VersionContext for testing with explicit versions
    pub fn init(activated: u8, tree_version: u8) VersionContext {
        // PRECONDITION: versions within supported range
        assert(activated <= MAX_SUPPORTED_VERSION);
        assert(tree_version <= MAX_SUPPORTED_VERSION);
        return .{
            .activated_version = activated,
            .ergo_tree_version = tree_version,
        };
    }

    // -------------------------------------------------------------------------
    // Version Checks
    // -------------------------------------------------------------------------

    /// Returns true if JIT interpreter is activated (v2+).
    /// JIT uses different cost model than AOT.
    pub fn isJitActivated(self: VersionContext) bool {
        // POSTCONDITION: JIT is activated iff activated_version >= 2
        return self.activated_version >= JIT_ACTIVATION_VERSION;
    }

    /// Returns true if v6 features are available (v3+).
    /// Enables new opcodes from EIP-50.
    pub fn isV6Activated(self: VersionContext) bool {
        // POSTCONDITION: v6 features enabled iff both versions >= 3
        return self.activated_version >= V6_ACTIVATION_VERSION and
            self.ergo_tree_version >= V6_ACTIVATION_VERSION;
    }

    /// Returns true if this script version is supported.
    /// Unknown versions should be handled via soft-fork rules.
    pub fn isScriptVersionSupported(self: VersionContext) bool {
        return self.ergo_tree_version <= MAX_SUPPORTED_VERSION;
    }

    /// Returns the effective script version (min of activated and declared).
    /// Used for feature gating - can't use features not yet activated.
    pub fn effectiveVersion(self: VersionContext) u8 {
        // INVARIANT: effective version never exceeds either component
        const eff = @min(self.activated_version, self.ergo_tree_version);
        assert(eff <= self.activated_version);
        assert(eff <= self.ergo_tree_version);
        return eff;
    }

    /// Returns true if unknown opcodes should be accepted with placeholder values.
    /// This is the soft-fork rule: if the script declares a version higher than
    /// the activated protocol version, unknown opcodes are accepted to allow
    /// old nodes to validate blocks with new script features.
    ///
    /// Reference: VersionContext.scala allowsUnknownOpCode
    pub fn allowsSoftForkPlaceholder(self: VersionContext) bool {
        // Soft-fork condition: script version > activated version
        // This means the script uses features from a future soft-fork
        // that hasn't activated yet on this node's understanding of consensus.
        return self.ergo_tree_version > self.activated_version;
    }
};

// ============================================================================
// Context Validation Errors
// ============================================================================

pub const ValidationError = error{
    /// self_index is out of bounds for inputs array
    InvalidSelfIndex,
    /// Box has negative value
    NegativeBoxValue,
    /// Box has empty proposition
    EmptyProposition,
    /// Height is invalid (e.g., zero for mainnet)
    InvalidHeight,
    /// Inputs array is empty
    EmptyInputs,
};

// ============================================================================
// Context
// ============================================================================

/// Execution context (read-only during evaluation).
/// All data must be validated before evaluation begins.
pub const Context = struct {
    /// Input boxes being spent
    inputs: []const BoxView,

    /// Output boxes being created
    outputs: []const BoxView,

    /// Data input boxes (read-only references, not spent)
    data_inputs: []const BoxView,

    /// Index of SELF in inputs array
    self_index: u16,

    /// Current block height (HEIGHT in ErgoScript)
    height: u32,

    /// Last N headers (newest first)
    headers: []const HeaderView,

    /// Pre-header for current block
    pre_header: PreHeaderView,

    /// Context variables for executeFromVar (SELF's context extension)
    /// Indexed by variable ID (0-255)
    context_vars: [max_context_vars]?[]const u8,

    /// Per-input context extension cache (optional, for getVarFromInput)
    /// When null, getVarFromInput returns None for all queries
    extension_cache: ?*const ContextExtensionCache,

    /// Get SELF box (the box being validated)
    pub fn getSelf(self: *const Context) *const BoxView {
        assert(self.self_index < self.inputs.len);
        return &self.inputs[self.self_index];
    }

    /// Get context variable by ID (from SELF's context extension)
    pub fn getVar(self: *const Context, id: u8) ?[]const u8 {
        return self.context_vars[id];
    }

    /// Get context variable from a specific input box.
    /// Returns null if:
    ///   - input_idx is out of bounds
    ///   - extension_cache is not set
    ///   - variable is not set for that input
    pub fn getVarFromInput(self: *const Context, input_idx: u16, var_id: u8) ?[]const u8 {
        // PRECONDITION: input_idx checked against inputs.len
        if (input_idx >= self.inputs.len) return null;

        // Extension cache required for cross-input access
        const cache = self.extension_cache orelse return null;

        return cache.get(.inputs, input_idx, var_id);
    }

    /// Get context variable from a specific data input box.
    /// Returns null if:
    ///   - data_input_idx is out of bounds
    ///   - extension_cache is not set
    ///   - variable is not set for that data input
    pub fn getVarFromDataInput(self: *const Context, data_input_idx: u16, var_id: u8) ?[]const u8 {
        // PRECONDITION: data_input_idx checked against data_inputs.len
        if (data_input_idx >= self.data_inputs.len) return null;

        // Extension cache required for cross-input access
        const cache = self.extension_cache orelse return null;

        return cache.get(.data_inputs, data_input_idx, var_id);
    }

    /// Validate context consistency before evaluation.
    /// Must be called before passing context to evaluator.
    pub fn validate(self: *const Context) ValidationError!void {
        // Assertions for invariants
        assert(self.inputs.len <= max_inputs);
        assert(self.outputs.len <= max_outputs);
        assert(self.data_inputs.len <= max_data_inputs);

        // Must have at least one input
        if (self.inputs.len == 0) {
            return error.EmptyInputs;
        }

        // SELF index must be valid
        if (self.self_index >= self.inputs.len) {
            return error.InvalidSelfIndex;
        }

        // Validate all input boxes
        for (self.inputs) |box| {
            if (box.value < 0) return error.NegativeBoxValue;
            if (box.proposition_bytes.len == 0) return error.EmptyProposition;
        }

        // Validate all output boxes
        for (self.outputs) |box| {
            if (box.value < 0) return error.NegativeBoxValue;
            if (box.proposition_bytes.len == 0) return error.EmptyProposition;
        }

        // Height should be positive (mainnet started at height 1)
        if (self.height == 0) {
            return error.InvalidHeight;
        }
    }

    /// Create a minimal context for testing with just height.
    /// Other fields are set to safe defaults.
    pub fn forHeight(height: u32, inputs: []const BoxView) Context {
        assert(height > 0);
        assert(inputs.len > 0);

        return .{
            .inputs = inputs,
            .outputs = &[_]BoxView{},
            .data_inputs = &[_]BoxView{},
            .self_index = 0,
            .height = height,
            .headers = &[_]HeaderView{},
            .pre_header = .{
                .version = 2,
                .parent_id = [_]u8{0} ** 32,
                .timestamp = 0,
                .n_bits = 0,
                .height = height,
                .miner_pk = [_]u8{0} ** 33,
                .votes = [_]u8{0} ** 3,
            },
            .context_vars = [_]?[]const u8{null} ** max_context_vars,
            .extension_cache = null,
        };
    }
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a minimal box for testing
pub fn testBox() BoxView {
    return .{
        .id = [_]u8{0} ** 32,
        .value = 1000000, // 1 ERG in nanoERGs
        .proposition_bytes = &[_]u8{ 0x00, 0x7F }, // TrueLeaf
        .creation_height = 1,
        .tx_id = [_]u8{0} ** 32,
        .index = 0,
        .tokens = &[_]Token{},
        .registers = [_]?[]const u8{null} ** 6,
    };
}

/// Create a minimal header for testing
pub fn testHeader() HeaderView {
    return .{
        .id = [_]u8{0} ** 32,
        .version = 2,
        .parent_id = [_]u8{0} ** 32,
        .ad_proofs_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 44,
        .transactions_root = [_]u8{0} ** 32,
        .timestamp = 1700000000000, // Nov 2023
        .n_bits = 0x01000000,
        .height = 1000000,
        .extension_root = [_]u8{0} ** 32,
        .miner_pk = [_]u8{0x02} ++ [_]u8{0} ** 32,
        .pow_onetime_pk = [_]u8{0x02} ++ [_]u8{0} ** 32,
        .pow_nonce = [_]u8{0} ** 8,
        .pow_distance = [_]u8{0} ** 32,
        .votes = [_]u8{0} ** 3,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "context: register enum" {
    try std.testing.expect(Register.R0.isMandatory());
    try std.testing.expect(Register.R3.isMandatory());
    try std.testing.expect(!Register.R4.isMandatory());
    try std.testing.expect(Register.R4.isUserDefined());
    try std.testing.expect(Register.R9.isUserDefined());
    try std.testing.expect(!Register.R0.isUserDefined());
}

test "context: box register access" {
    const r4_data = [_]u8{ 0x01, 0x02, 0x03 };
    var box = testBox();
    box.registers[0] = &r4_data; // R4

    // Mandatory registers
    try std.testing.expect(box.hasRegister(.R0));
    try std.testing.expect(box.hasRegister(.R1));
    try std.testing.expectEqual(box.proposition_bytes, box.getRegister(.R1));

    // User-defined registers
    try std.testing.expect(box.hasRegister(.R4));
    try std.testing.expect(!box.hasRegister(.R5));
    try std.testing.expectEqualSlices(u8, &r4_data, box.getRegister(.R4).?);
    try std.testing.expectEqual(@as(?[]const u8, null), box.getRegister(.R5));
}

test "context: getSelf" {
    const box1 = testBox();
    var box2 = testBox();
    box2.value = 2000000;

    const inputs = [_]BoxView{ box1, box2 };

    var ctx = Context.forHeight(100, &inputs);
    ctx.self_index = 1;

    const self = ctx.getSelf();
    try std.testing.expectEqual(@as(i64, 2000000), self.value);
}

test "context: getVar" {
    const var_data = [_]u8{ 0xAA, 0xBB };
    const inputs = [_]BoxView{testBox()};

    var ctx = Context.forHeight(100, &inputs);
    ctx.context_vars[42] = &var_data;

    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVar(0));
    try std.testing.expectEqualSlices(u8, &var_data, ctx.getVar(42).?);
}

test "context: getVarFromInput without cache returns null" {
    const inputs = [_]BoxView{ testBox(), testBox() };
    const ctx = Context.forHeight(100, &inputs);

    // No extension_cache set
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(0, 5));
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(1, 10));
}

test "context: getVarFromInput with cache" {
    var cache = ContextExtensionCache.init();
    const var_data = [_]u8{ 0x04, 0x54 }; // SInt 42
    cache.set(.inputs, 0, 5, &var_data);

    const inputs = [_]BoxView{ testBox(), testBox() };
    var ctx = Context.forHeight(100, &inputs);
    ctx.extension_cache = &cache;

    // Variable set on input 0, var 5
    const result = ctx.getVarFromInput(0, 5);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &var_data, result.?);

    // Unset variable returns null
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(0, 6));

    // Different input returns null (not set)
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(1, 5));
}

test "context: getVarFromInput out of bounds returns null" {
    var cache = ContextExtensionCache.init();
    const var_data = [_]u8{0x42};
    cache.set(.inputs, 10, 5, &var_data); // Set at index 10

    const inputs = [_]BoxView{ testBox(), testBox() }; // Only 2 inputs
    var ctx = Context.forHeight(100, &inputs);
    ctx.extension_cache = &cache;

    // Index 10 is out of bounds (only 2 inputs)
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(10, 5));

    // Valid indices still work
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromInput(0, 5));
}

test "context: getVarFromDataInput with cache" {
    var cache = ContextExtensionCache.init();
    const var_data = [_]u8{ 0x01, 0x01 }; // Boolean true
    cache.set(.data_inputs, 2, 100, &var_data);

    const inputs = [_]BoxView{testBox()};
    const data_inputs = [_]BoxView{ testBox(), testBox(), testBox() };
    var ctx = Context.forHeight(100, &inputs);
    ctx.data_inputs = &data_inputs;
    ctx.extension_cache = &cache;

    // Variable set on data_input 2, var 100
    const result = ctx.getVarFromDataInput(2, 100);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &var_data, result.?);

    // Out of bounds returns null
    try std.testing.expectEqual(@as(?[]const u8, null), ctx.getVarFromDataInput(5, 100));
}

test "context: validation success" {
    const inputs = [_]BoxView{testBox()};
    const ctx = Context.forHeight(100, &inputs);
    try ctx.validate();
}

test "context: validation invalid self_index" {
    const inputs = [_]BoxView{testBox()};
    var ctx = Context.forHeight(100, &inputs);
    ctx.self_index = 99; // Out of bounds

    try std.testing.expectError(error.InvalidSelfIndex, ctx.validate());
}

test "context: validation negative box value" {
    var box = testBox();
    box.value = -100;
    const inputs = [_]BoxView{box};

    const ctx = Context.forHeight(100, &inputs);
    try std.testing.expectError(error.NegativeBoxValue, ctx.validate());
}

test "context: validation empty proposition" {
    var box = testBox();
    box.proposition_bytes = &[_]u8{};
    const inputs = [_]BoxView{box};

    const ctx = Context.forHeight(100, &inputs);
    try std.testing.expectError(error.EmptyProposition, ctx.validate());
}

test "context: validation zero height" {
    const inputs = [_]BoxView{testBox()};
    var ctx = Context.forHeight(1, &inputs);
    ctx.height = 0;

    try std.testing.expectError(error.InvalidHeight, ctx.validate());
}

test "context: forHeight helper" {
    const box = testBox();
    const inputs = [_]BoxView{box};
    const ctx = Context.forHeight(500, &inputs);

    try std.testing.expectEqual(@as(u32, 500), ctx.height);
    try std.testing.expectEqual(@as(u16, 0), ctx.self_index);
    try std.testing.expectEqual(@as(usize, 1), ctx.inputs.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs.len);
}

// ============================================================================
// VersionContext Tests
// ============================================================================

test "version_context: v2 constructor returns mainnet defaults" {
    const vc = VersionContext.v2();
    try std.testing.expectEqual(@as(u8, 2), vc.activated_version);
    try std.testing.expectEqual(@as(u8, 0), vc.ergo_tree_version);
}

test "version_context: isJitActivated" {
    // Pre-JIT versions
    const v0 = VersionContext.init(0, 0);
    const v1 = VersionContext.init(1, 0);
    try std.testing.expect(!v0.isJitActivated());
    try std.testing.expect(!v1.isJitActivated());

    // JIT activated (v2+)
    const v2 = VersionContext.init(2, 0);
    const v3 = VersionContext.init(3, 0);
    try std.testing.expect(v2.isJitActivated());
    try std.testing.expect(v3.isJitActivated());
}

test "version_context: isV6Activated" {
    // Not v6 - activated version too low
    const vc1 = VersionContext.init(2, 3);
    try std.testing.expect(!vc1.isV6Activated());

    // Not v6 - tree version too low
    const vc2 = VersionContext.init(3, 2);
    try std.testing.expect(!vc2.isV6Activated());

    // Both at v3 - v6 enabled
    const vc3 = VersionContext.init(3, 3);
    try std.testing.expect(vc3.isV6Activated());
}

test "version_context: isScriptVersionSupported" {
    const v0 = VersionContext.init(2, 0);
    const v1 = VersionContext.init(2, 1);
    const v2 = VersionContext.init(2, 2);
    const v3 = VersionContext.init(3, 3);

    try std.testing.expect(v0.isScriptVersionSupported());
    try std.testing.expect(v1.isScriptVersionSupported());
    try std.testing.expect(v2.isScriptVersionSupported());
    try std.testing.expect(v3.isScriptVersionSupported());
}

test "version_context: effectiveVersion" {
    // Effective = min(activated, tree)
    const vc1 = VersionContext.init(3, 2);
    try std.testing.expectEqual(@as(u8, 2), vc1.effectiveVersion());

    const vc2 = VersionContext.init(2, 3);
    try std.testing.expectEqual(@as(u8, 2), vc2.effectiveVersion());

    const vc3 = VersionContext.init(3, 3);
    try std.testing.expectEqual(@as(u8, 3), vc3.effectiveVersion());

    const vc4 = VersionContext.init(2, 0);
    try std.testing.expectEqual(@as(u8, 0), vc4.effectiveVersion());
}

test "version_context: allowsSoftForkPlaceholder" {
    // Script version > activated version - soft-fork allowed
    const vc1 = VersionContext.init(2, 3);
    try std.testing.expect(vc1.allowsSoftForkPlaceholder());

    // Script version == activated version - no soft-fork
    const vc2 = VersionContext.init(2, 2);
    try std.testing.expect(!vc2.allowsSoftForkPlaceholder());

    // Script version < activated version - no soft-fork
    const vc3 = VersionContext.init(3, 2);
    try std.testing.expect(!vc3.allowsSoftForkPlaceholder());

    // Common case: old script on v2 mainnet
    const vc4 = VersionContext.init(2, 0);
    try std.testing.expect(!vc4.allowsSoftForkPlaceholder());

    // Future script on v2 mainnet
    const vc5 = VersionContext.init(2, 3);
    try std.testing.expect(vc5.allowsSoftForkPlaceholder());
}
