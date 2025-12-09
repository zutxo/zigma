//! ErgoTree Opcode Catalog
//!
//! All opcodes for ErgoTree bytecode interpreter.
//! Opcodes 1-111 are type codes (used for constant encoding).
//! Operation opcodes start at base 112 (0x70).
//!
//! Reference: OPCODES.md extracted from sigma-rust and sigmastate-interpreter

const std = @import("std");

/// Base opcode value - operations start here
pub const op_base: u8 = 112;

/// Opcode byte value
pub const OpCode = u8;

/// Operation categories for organization
pub const Category = enum {
    constant, // Type codes (1-111)
    variable, // TaggedVariable, ValUse
    literal, // TrueLeaf, FalseLeaf, etc.
    arithmetic, // Plus, Minus, Multiply, etc.
    comparison, // LT, LE, GT, GE, EQ, NEQ
    logical, // AND, OR, NOT, XOR
    bitwise, // BitAnd, BitOr, BitXor, etc.
    collection, // Map, Filter, Fold, Slice, etc.
    box_ops, // ExtractRegisterAs, ExtractAmount, etc.
    context, // Height, Inputs, Outputs, Self, etc.
    sigma, // SigmaAnd, SigmaOr, AtLeast, etc.
    crypto, // CalcBlake2b256, CalcSha256, ProveDlog, etc.
    type_ops, // Upcast, Downcast, SizeOf, etc.
    control, // If, BlockValue, ValDef
    special, // ConstantPlaceholder, SubstConstants, etc.
};

/// Metadata for each opcode
pub const OpInfo = struct {
    /// Human-readable name
    name: []const u8,
    /// Opcode byte value
    code: OpCode,
    /// Operation category
    category: Category,
    /// Base cost (JitCost v4)
    cost: u16,
    /// Per-item cost for collection operations (0 if N/A)
    per_item_cost: u16 = 0,
};

// ============================================================================
// Opcode Constants
// ============================================================================

/// Constant type range (used for constant encoding)
pub const constant_first: OpCode = 1;
pub const constant_last: OpCode = 111;

/// Variable operations
pub const TaggedVariable: OpCode = 113; // 0x71
pub const ValUse: OpCode = 114; // 0x72
pub const ValDef: OpCode = 115; // 0x73 (NOTE: Wrong! Should be 214 per Scala - see zigma-a5q)
pub const FunDef: OpCode = 117; // 0x75 (NOTE: Wrong! Should be 215 per Scala - see zigma-a5q)
pub const BlockValue: OpCode = 116; // 0x74 (NOTE: Wrong! Should be 216 per Scala - see zigma-a5q)
pub const FuncValue: OpCode = 131; // 0x83 (NOTE: Wrong! Should be 217 per Scala - see zigma-a5q) - using 131 to avoid conflict

/// Boolean literals
pub const TrueLeaf: OpCode = 127; // 0x7F
pub const FalseLeaf: OpCode = 128; // 0x80
pub const UnitConstant: OpCode = 129; // 0x81

/// Constant operations
pub const ConstantPlaceholder: OpCode = 118; // 0x76
pub const SubstConstants: OpCode = 119; // 0x77
pub const LongToByteArray: OpCode = 120; // 0x78
pub const ByteArrayToBigInt: OpCode = 121; // 0x79
pub const ByteArrayToLong: OpCode = 122; // 0x7A

/// Serialization operations
pub const Deserialize: OpCode = 130; // 0x82

/// Comparison operations (shift 31-36)
pub const LT: OpCode = 143; // 0x8F - less than
pub const LE: OpCode = 144; // 0x90 - less or equal
pub const GT: OpCode = 145; // 0x91 - greater than
pub const GE: OpCode = 146; // 0x92 - greater or equal
pub const EQ: OpCode = 147; // 0x93 - equality
pub const NEQ: OpCode = 148; // 0x94 - inequality

/// Conditional
pub const If: OpCode = 149; // 0x95

/// Arithmetic operations (shift 41-50)
pub const Minus: OpCode = 153; // 0x99
pub const Plus: OpCode = 154; // 0x9A
pub const Multiply: OpCode = 156; // 0x9C
pub const Division: OpCode = 157; // 0x9D
pub const Modulo: OpCode = 158; // 0x9E
pub const Negation: OpCode = 155; // 0x9B
pub const Min: OpCode = 159; // 0x9F
pub const Max: OpCode = 160; // 0xA0

/// Context operations (shift 51-60)
pub const Height: OpCode = 163; // 0xA3
pub const Inputs: OpCode = 164; // 0xA4
pub const Outputs: OpCode = 165; // 0xA5
pub const LastBlockUtxoRootHash: OpCode = 166; // 0xA6
pub const Self: OpCode = 167; // 0xA7
pub const Context: OpCode = 168; // 0xA8
pub const Global: OpCode = 169; // 0xA9
pub const MinerPubKey: OpCode = 170; // 0xAA

/// Collection operations (shift 61-80)
pub const MapCollection: OpCode = 173; // 0xAD
pub const Exists: OpCode = 174; // 0xAE
pub const ForAll: OpCode = 175; // 0xAF
pub const Fold: OpCode = 176; // 0xB0
pub const SizeOf: OpCode = 177; // 0xB1
pub const ByIndex: OpCode = 178; // 0xB2
pub const Slice: OpCode = 179; // 0xB3
pub const Append: OpCode = 180; // 0xB4
pub const Filter: OpCode = 181; // 0xB5
pub const Flatmap: OpCode = 182; // 0xB6
pub const Zip: OpCode = 183; // 0xB7
pub const Indices: OpCode = 184; // 0xB8
pub const GetVar: OpCode = 185; // 0xB9
pub const OptionGet: OpCode = 186; // 0xBA
pub const OptionIsDefined: OpCode = 187; // 0xBB
pub const OptionGetOrElse: OpCode = 188; // 0xBC

/// Tuple operations
pub const SelectField: OpCode = 189; // 0xBD
pub const Tuple: OpCode = 190; // 0xBE

/// Logical operations
pub const LogicalNot: OpCode = 191; // 0xBF
pub const AND: OpCode = 192; // 0xC0 (binary logical and)
pub const OR: OpCode = 193; // 0xC1 (binary logical or)
pub const XorOf: OpCode = 255; // 0xFF

/// Bitwise operations
pub const BitOr: OpCode = 194; // 0xC2
pub const BitAnd: OpCode = 195; // 0xC3
pub const BitXor: OpCode = 196; // 0xC4
pub const BitNot: OpCode = 197; // 0xC5
pub const BitShiftLeft: OpCode = 198; // 0xC6
pub const BitShiftRight: OpCode = 199; // 0xC7
pub const BitShiftRightZeroed: OpCode = 200; // 0xC8

/// Sigma protocol operations
pub const SigmaAnd: OpCode = 201; // 0xC9
pub const SigmaOr: OpCode = 202; // 0xCA
pub const AtLeast: OpCode = 209; // 0xD1

/// Crypto operations (shift 91-100)
pub const CalcBlake2b256: OpCode = 203; // 0xCB
pub const CalcSha256: OpCode = 204; // 0xCC
pub const ProveDlog: OpCode = 205; // 0xCD
pub const ProveDHTuple: OpCode = 206; // 0xCE
pub const DecodePoint: OpCode = 208; // 0xD0
pub const GroupGenerator: OpCode = 210; // 0xD2
pub const Exponentiate: OpCode = 211; // 0xD3
pub const MultiplyGroup: OpCode = 212; // 0xD4

/// Box operations (shift 101-110)
pub const ExtractRegisterAs: OpCode = 213; // 0xD5
pub const ExtractAmount: OpCode = 214; // 0xD6
pub const ExtractScriptBytes: OpCode = 215; // 0xD7
pub const ExtractBytes: OpCode = 216; // 0xD8
pub const ExtractBytesWithNoRef: OpCode = 217; // 0xD9
pub const ExtractId: OpCode = 218; // 0xDA
pub const ExtractCreationInfo: OpCode = 219; // 0xDB

/// Collection constructors
pub const ConcreteCollection: OpCode = 220; // 0xDC
pub const PairConstructor: OpCode = 221; // 0xDD
pub const TripleConstructor: OpCode = 222; // 0xDE

/// AVL tree operations
pub const TreeLookup: OpCode = 223; // 0xDF
pub const CreateAvlTree: OpCode = 224; // 0xE0
pub const TreeModifications: OpCode = 225; // 0xE1

/// String/byte operations
pub const ByteArrayToString: OpCode = 226; // 0xE2
pub const StringToByteArray: OpCode = 227; // 0xE3

/// Type operations
pub const Upcast: OpCode = 228; // 0xE4
pub const Downcast: OpCode = 229; // 0xE5

/// Logical collection operations
pub const AllOf: OpCode = 230; // 0xE6
pub const AnyOf: OpCode = 231; // 0xE7

/// Serialization
pub const Serialize: OpCode = 232; // 0xE8

/// Header operations
pub const ExtractVersion: OpCode = 233; // 0xE9
pub const ExtractParentId: OpCode = 234; // 0xEA
pub const ExtractAdProofsRoot: OpCode = 235; // 0xEB
pub const ExtractStateRoot: OpCode = 236; // 0xEC
pub const ExtractTransactionsRoot: OpCode = 237; // 0xED
pub const ExtractTimestamp: OpCode = 238; // 0xEE
pub const ExtractNBits: OpCode = 239; // 0xEF
pub const ExtractDifficulty: OpCode = 240; // 0xF0
pub const ExtractVotes: OpCode = 241; // 0xF1
pub const ExtractMinerRewards: OpCode = 242; // 0xF2

/// Property access (method calls)
pub const PropertyCall: OpCode = 243; // 0xF3
pub const MethodCall: OpCode = 244; // 0xF4

/// Apply function
pub const Apply: OpCode = 245; // 0xF5

// ============================================================================
// Opcode Metadata Table
// ============================================================================

/// Get metadata for an opcode
pub fn getInfo(code: OpCode) ?OpInfo {
    return switch (code) {
        // Constants (type codes) - no cost as they're handled specially
        constant_first...constant_last => null,

        // Variables
        TaggedVariable => .{ .name = "TaggedVariable", .code = TaggedVariable, .category = .variable, .cost = 10 },
        ValUse => .{ .name = "ValUse", .code = ValUse, .category = .variable, .cost = 10 },
        ValDef => .{ .name = "ValDef", .code = ValDef, .category = .control, .cost = 10 },
        FunDef => .{ .name = "FunDef", .code = FunDef, .category = .control, .cost = 10 },
        BlockValue => .{ .name = "BlockValue", .code = BlockValue, .category = .control, .cost = 10 },
        FuncValue => .{ .name = "FuncValue", .code = FuncValue, .category = .control, .cost = 20 },

        // Literals
        TrueLeaf => .{ .name = "TrueLeaf", .code = TrueLeaf, .category = .literal, .cost = 10 },
        FalseLeaf => .{ .name = "FalseLeaf", .code = FalseLeaf, .category = .literal, .cost = 10 },
        UnitConstant => .{ .name = "UnitConstant", .code = UnitConstant, .category = .literal, .cost = 10 },

        // Constants
        ConstantPlaceholder => .{ .name = "ConstantPlaceholder", .code = ConstantPlaceholder, .category = .constant, .cost = 10 },
        SubstConstants => .{ .name = "SubstConstants", .code = SubstConstants, .category = .special, .cost = 100 },
        LongToByteArray => .{ .name = "LongToByteArray", .code = LongToByteArray, .category = .type_ops, .cost = 17 },
        ByteArrayToBigInt => .{ .name = "ByteArrayToBigInt", .code = ByteArrayToBigInt, .category = .type_ops, .cost = 30 },
        ByteArrayToLong => .{ .name = "ByteArrayToLong", .code = ByteArrayToLong, .category = .type_ops, .cost = 16 },

        // Serialization
        Deserialize => .{ .name = "Deserialize", .code = Deserialize, .category = .special, .cost = 100 },

        // Comparison
        LT => .{ .name = "LT", .code = LT, .category = .comparison, .cost = 36 },
        LE => .{ .name = "LE", .code = LE, .category = .comparison, .cost = 36 },
        GT => .{ .name = "GT", .code = GT, .category = .comparison, .cost = 36 },
        GE => .{ .name = "GE", .code = GE, .category = .comparison, .cost = 36 },
        EQ => .{ .name = "EQ", .code = EQ, .category = .comparison, .cost = 36 },
        NEQ => .{ .name = "NEQ", .code = NEQ, .category = .comparison, .cost = 36 },

        // Conditional
        If => .{ .name = "If", .code = If, .category = .control, .cost = 10 },

        // Arithmetic
        Minus => .{ .name = "Minus", .code = Minus, .category = .arithmetic, .cost = 36 },
        Plus => .{ .name = "Plus", .code = Plus, .category = .arithmetic, .cost = 36 },
        Multiply => .{ .name = "Multiply", .code = Multiply, .category = .arithmetic, .cost = 41 },
        Division => .{ .name = "Division", .code = Division, .category = .arithmetic, .cost = 41 },
        Modulo => .{ .name = "Modulo", .code = Modulo, .category = .arithmetic, .cost = 41 },
        Negation => .{ .name = "Negation", .code = Negation, .category = .arithmetic, .cost = 30 },
        Min => .{ .name = "Min", .code = Min, .category = .arithmetic, .cost = 36 },
        Max => .{ .name = "Max", .code = Max, .category = .arithmetic, .cost = 36 },

        // Context
        Height => .{ .name = "Height", .code = Height, .category = .context, .cost = 26 },
        Inputs => .{ .name = "Inputs", .code = Inputs, .category = .context, .cost = 10 },
        Outputs => .{ .name = "Outputs", .code = Outputs, .category = .context, .cost = 10 },
        LastBlockUtxoRootHash => .{ .name = "LastBlockUtxoRootHash", .code = LastBlockUtxoRootHash, .category = .context, .cost = 15 },
        Self => .{ .name = "Self", .code = Self, .category = .context, .cost = 10 },
        Context => .{ .name = "Context", .code = Context, .category = .context, .cost = 10 },
        Global => .{ .name = "Global", .code = Global, .category = .context, .cost = 10 },
        MinerPubKey => .{ .name = "MinerPubKey", .code = MinerPubKey, .category = .context, .cost = 100 },

        // Collection operations
        MapCollection => .{ .name = "MapCollection", .code = MapCollection, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Exists => .{ .name = "Exists", .code = Exists, .category = .collection, .cost = 20, .per_item_cost = 1 },
        ForAll => .{ .name = "ForAll", .code = ForAll, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Fold => .{ .name = "Fold", .code = Fold, .category = .collection, .cost = 20, .per_item_cost = 1 },
        SizeOf => .{ .name = "SizeOf", .code = SizeOf, .category = .collection, .cost = 14 },
        ByIndex => .{ .name = "ByIndex", .code = ByIndex, .category = .collection, .cost = 30 },
        Slice => .{ .name = "Slice", .code = Slice, .category = .collection, .cost = 20, .per_item_cost = 2 },
        Append => .{ .name = "Append", .code = Append, .category = .collection, .cost = 20, .per_item_cost = 2 },
        Filter => .{ .name = "Filter", .code = Filter, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Flatmap => .{ .name = "Flatmap", .code = Flatmap, .category = .collection, .cost = 60, .per_item_cost = 10 },
        Zip => .{ .name = "Zip", .code = Zip, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Indices => .{ .name = "Indices", .code = Indices, .category = .collection, .cost = 20, .per_item_cost = 1 },
        GetVar => .{ .name = "GetVar", .code = GetVar, .category = .collection, .cost = 100 },
        OptionGet => .{ .name = "OptionGet", .code = OptionGet, .category = .collection, .cost = 15 },
        OptionIsDefined => .{ .name = "OptionIsDefined", .code = OptionIsDefined, .category = .collection, .cost = 15 },
        OptionGetOrElse => .{ .name = "OptionGetOrElse", .code = OptionGetOrElse, .category = .collection, .cost = 20 },

        // Tuple
        SelectField => .{ .name = "SelectField", .code = SelectField, .category = .collection, .cost = 10 },
        Tuple => .{ .name = "Tuple", .code = Tuple, .category = .collection, .cost = 10 },

        // Logical
        LogicalNot => .{ .name = "LogicalNot", .code = LogicalNot, .category = .logical, .cost = 11 },
        AND => .{ .name = "AND", .code = AND, .category = .logical, .cost = 36 },
        OR => .{ .name = "OR", .code = OR, .category = .logical, .cost = 36 },
        XorOf => .{ .name = "XorOf", .code = XorOf, .category = .logical, .cost = 20 },

        // Bitwise
        BitOr => .{ .name = "BitOr", .code = BitOr, .category = .bitwise, .cost = 36 },
        BitAnd => .{ .name = "BitAnd", .code = BitAnd, .category = .bitwise, .cost = 36 },
        BitXor => .{ .name = "BitXor", .code = BitXor, .category = .bitwise, .cost = 36 },
        BitNot => .{ .name = "BitNot", .code = BitNot, .category = .bitwise, .cost = 30 },
        BitShiftLeft => .{ .name = "BitShiftLeft", .code = BitShiftLeft, .category = .bitwise, .cost = 36 },
        BitShiftRight => .{ .name = "BitShiftRight", .code = BitShiftRight, .category = .bitwise, .cost = 36 },
        BitShiftRightZeroed => .{ .name = "BitShiftRightZeroed", .code = BitShiftRightZeroed, .category = .bitwise, .cost = 36 },

        // Sigma
        SigmaAnd => .{ .name = "SigmaAnd", .code = SigmaAnd, .category = .sigma, .cost = 20 },
        SigmaOr => .{ .name = "SigmaOr", .code = SigmaOr, .category = .sigma, .cost = 20 },
        AtLeast => .{ .name = "AtLeast", .code = AtLeast, .category = .sigma, .cost = 100 },

        // Crypto
        CalcBlake2b256 => .{ .name = "CalcBlake2b256", .code = CalcBlake2b256, .category = .crypto, .cost = 59, .per_item_cost = 1 },
        CalcSha256 => .{ .name = "CalcSha256", .code = CalcSha256, .category = .crypto, .cost = 64, .per_item_cost = 1 },
        ProveDlog => .{ .name = "ProveDlog", .code = ProveDlog, .category = .crypto, .cost = 100 },
        ProveDHTuple => .{ .name = "ProveDHTuple", .code = ProveDHTuple, .category = .crypto, .cost = 200 },
        DecodePoint => .{ .name = "DecodePoint", .code = DecodePoint, .category = .crypto, .cost = 1100 },
        GroupGenerator => .{ .name = "GroupGenerator", .code = GroupGenerator, .category = .crypto, .cost = 10 },
        Exponentiate => .{ .name = "Exponentiate", .code = Exponentiate, .category = .crypto, .cost = 5100 },
        MultiplyGroup => .{ .name = "MultiplyGroup", .code = MultiplyGroup, .category = .crypto, .cost = 250 },

        // Box operations
        ExtractRegisterAs => .{ .name = "ExtractRegisterAs", .code = ExtractRegisterAs, .category = .box_ops, .cost = 50 },
        ExtractAmount => .{ .name = "ExtractAmount", .code = ExtractAmount, .category = .box_ops, .cost = 12 },
        ExtractScriptBytes => .{ .name = "ExtractScriptBytes", .code = ExtractScriptBytes, .category = .box_ops, .cost = 20 },
        ExtractBytes => .{ .name = "ExtractBytes", .code = ExtractBytes, .category = .box_ops, .cost = 100 },
        ExtractBytesWithNoRef => .{ .name = "ExtractBytesWithNoRef", .code = ExtractBytesWithNoRef, .category = .box_ops, .cost = 20 },
        ExtractId => .{ .name = "ExtractId", .code = ExtractId, .category = .box_ops, .cost = 12 },
        ExtractCreationInfo => .{ .name = "ExtractCreationInfo", .code = ExtractCreationInfo, .category = .box_ops, .cost = 16 },

        // Collection constructors
        ConcreteCollection => .{ .name = "ConcreteCollection", .code = ConcreteCollection, .category = .collection, .cost = 20 },
        PairConstructor => .{ .name = "PairConstructor", .code = PairConstructor, .category = .collection, .cost = 10 },
        TripleConstructor => .{ .name = "TripleConstructor", .code = TripleConstructor, .category = .collection, .cost = 10 },

        // AVL tree
        TreeLookup => .{ .name = "TreeLookup", .code = TreeLookup, .category = .crypto, .cost = 200 },
        CreateAvlTree => .{ .name = "CreateAvlTree", .code = CreateAvlTree, .category = .crypto, .cost = 100 },
        TreeModifications => .{ .name = "TreeModifications", .code = TreeModifications, .category = .crypto, .cost = 300 },

        // String/byte operations
        ByteArrayToString => .{ .name = "ByteArrayToString", .code = ByteArrayToString, .category = .type_ops, .cost = 50 },
        StringToByteArray => .{ .name = "StringToByteArray", .code = StringToByteArray, .category = .type_ops, .cost = 50 },

        // Type operations
        Upcast => .{ .name = "Upcast", .code = Upcast, .category = .type_ops, .cost = 10 },
        Downcast => .{ .name = "Downcast", .code = Downcast, .category = .type_ops, .cost = 10 },

        // Logical collection operations
        AllOf => .{ .name = "AllOf", .code = AllOf, .category = .logical, .cost = 20, .per_item_cost = 1 },
        AnyOf => .{ .name = "AnyOf", .code = AnyOf, .category = .logical, .cost = 20, .per_item_cost = 1 },

        // Serialization
        Serialize => .{ .name = "Serialize", .code = Serialize, .category = .special, .cost = 100 },

        // Header operations
        ExtractVersion => .{ .name = "ExtractVersion", .code = ExtractVersion, .category = .box_ops, .cost = 10 },
        ExtractParentId => .{ .name = "ExtractParentId", .code = ExtractParentId, .category = .box_ops, .cost = 10 },
        ExtractAdProofsRoot => .{ .name = "ExtractAdProofsRoot", .code = ExtractAdProofsRoot, .category = .box_ops, .cost = 10 },
        ExtractStateRoot => .{ .name = "ExtractStateRoot", .code = ExtractStateRoot, .category = .box_ops, .cost = 10 },
        ExtractTransactionsRoot => .{ .name = "ExtractTransactionsRoot", .code = ExtractTransactionsRoot, .category = .box_ops, .cost = 10 },
        ExtractTimestamp => .{ .name = "ExtractTimestamp", .code = ExtractTimestamp, .category = .box_ops, .cost = 10 },
        ExtractNBits => .{ .name = "ExtractNBits", .code = ExtractNBits, .category = .box_ops, .cost = 10 },
        ExtractDifficulty => .{ .name = "ExtractDifficulty", .code = ExtractDifficulty, .category = .box_ops, .cost = 10 },
        ExtractVotes => .{ .name = "ExtractVotes", .code = ExtractVotes, .category = .box_ops, .cost = 10 },
        ExtractMinerRewards => .{ .name = "ExtractMinerRewards", .code = ExtractMinerRewards, .category = .box_ops, .cost = 10 },

        // Property/method access
        PropertyCall => .{ .name = "PropertyCall", .code = PropertyCall, .category = .special, .cost = 10 },
        MethodCall => .{ .name = "MethodCall", .code = MethodCall, .category = .special, .cost = 10 },

        // Apply
        Apply => .{ .name = "Apply", .code = Apply, .category = .control, .cost = 20 },

        else => null,
    };
}

/// Check if opcode is a constant (type code)
pub fn isConstant(code: OpCode) bool {
    return code >= constant_first and code <= constant_last;
}

/// Check if opcode is an operation
pub fn isOperation(code: OpCode) bool {
    return code >= op_base;
}

/// Get operation name for debugging
pub fn getName(code: OpCode) []const u8 {
    if (isConstant(code)) return "Constant";
    if (getInfo(code)) |info| return info.name;
    return "Unknown";
}

// ============================================================================
// Tests
// ============================================================================

test "opcodes: constant range" {
    try std.testing.expect(isConstant(1));
    try std.testing.expect(isConstant(111));
    try std.testing.expect(!isConstant(0));
    try std.testing.expect(!isConstant(112));
}

test "opcodes: operation check" {
    try std.testing.expect(!isOperation(0));
    try std.testing.expect(!isOperation(111));
    try std.testing.expect(isOperation(112));
    try std.testing.expect(isOperation(255));
}

test "opcodes: known opcode values from spec" {
    // From vectors.json opcodes section
    try std.testing.expectEqual(@as(OpCode, 0x71), TaggedVariable);
    try std.testing.expectEqual(@as(OpCode, 0x72), ValUse);
    try std.testing.expectEqual(@as(OpCode, 0x7f), TrueLeaf);
    try std.testing.expectEqual(@as(OpCode, 0x80), FalseLeaf);
    try std.testing.expectEqual(@as(OpCode, 0x8f), LT);
    try std.testing.expectEqual(@as(OpCode, 0x9a), Plus);
    try std.testing.expectEqual(@as(OpCode, 0x99), Minus);
    try std.testing.expectEqual(@as(OpCode, 0x9c), Multiply);
    try std.testing.expectEqual(@as(OpCode, 0x9d), Division);
    try std.testing.expectEqual(@as(OpCode, 0xa3), Height);
    try std.testing.expectEqual(@as(OpCode, 0xa4), Inputs);
    try std.testing.expectEqual(@as(OpCode, 0xa5), Outputs);
    try std.testing.expectEqual(@as(OpCode, 0xa7), Self);
    try std.testing.expectEqual(@as(OpCode, 0xcb), CalcBlake2b256);
    try std.testing.expectEqual(@as(OpCode, 0xcc), CalcSha256);
    try std.testing.expectEqual(@as(OpCode, 0xcd), ProveDlog);
    try std.testing.expectEqual(@as(OpCode, 0xff), XorOf);
}

test "opcodes: getInfo returns metadata" {
    const plus_info = getInfo(Plus);
    try std.testing.expect(plus_info != null);
    try std.testing.expectEqualStrings("Plus", plus_info.?.name);
    try std.testing.expectEqual(Category.arithmetic, plus_info.?.category);
    try std.testing.expectEqual(@as(u16, 36), plus_info.?.cost);

    const blake_info = getInfo(CalcBlake2b256);
    try std.testing.expect(blake_info != null);
    try std.testing.expectEqual(@as(u16, 59), blake_info.?.cost);
    try std.testing.expectEqual(@as(u16, 1), blake_info.?.per_item_cost);
}

test "opcodes: getName returns human-readable name" {
    try std.testing.expectEqualStrings("Constant", getName(1));
    try std.testing.expectEqualStrings("Constant", getName(50));
    try std.testing.expectEqualStrings("Plus", getName(Plus));
    try std.testing.expectEqualStrings("CalcBlake2b256", getName(CalcBlake2b256));
    try std.testing.expectEqualStrings("Unknown", getName(0));
}

test "opcodes: expensive crypto operations have high cost" {
    const decode_point = getInfo(DecodePoint);
    try std.testing.expect(decode_point.?.cost >= 1000);

    const exponentiate = getInfo(Exponentiate);
    try std.testing.expect(exponentiate.?.cost >= 5000);
}
