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
// Opcode Constants - CANONICAL VALUES FROM SCALA OpCodes.scala
// ============================================================================
// Formula: opcode = 112 (LastConstantCode) + shift
// Source: sigmastate/data/shared/src/main/scala/sigma/serialization/OpCodes.scala

/// Constant type range (used for constant encoding)
pub const constant_first: OpCode = 1;
pub const constant_last: OpCode = 111;

// ---------------------------------------------------------------------------
// Variables (shift 1-4)
// ---------------------------------------------------------------------------
pub const TaggedVariable: OpCode = 113; // shift 1
pub const ValUse: OpCode = 114; // shift 2
pub const ConstantPlaceholder: OpCode = 115; // shift 3
pub const SubstConstants: OpCode = 116; // shift 4

// ---------------------------------------------------------------------------
// Type conversions (shift 10-14)
// ---------------------------------------------------------------------------
pub const LongToByteArray: OpCode = 122; // shift 10
pub const ByteArrayToBigInt: OpCode = 123; // shift 11
pub const ByteArrayToLong: OpCode = 124; // shift 12
pub const Downcast: OpCode = 125; // shift 13
pub const Upcast: OpCode = 126; // shift 14

// ---------------------------------------------------------------------------
// Literals (shift 15-21)
// ---------------------------------------------------------------------------
pub const TrueLeaf: OpCode = 127; // shift 15
pub const FalseLeaf: OpCode = 128; // shift 16
pub const UnitConstant: OpCode = 129; // shift 17
pub const GroupGenerator: OpCode = 130; // shift 18
pub const ConcreteCollection: OpCode = 131; // shift 19
// reserved: shift 20
pub const ConcreteCollectionBooleanConstant: OpCode = 133; // shift 21

// ---------------------------------------------------------------------------
// Tuple operations (shift 22-28)
// ---------------------------------------------------------------------------
pub const Tuple: OpCode = 134; // shift 22
pub const Select1: OpCode = 135; // shift 23
pub const Select2: OpCode = 136; // shift 24
pub const Select3: OpCode = 137; // shift 25
pub const Select4: OpCode = 138; // shift 26
pub const Select5: OpCode = 139; // shift 27
pub const SelectField: OpCode = 140; // shift 28

// ---------------------------------------------------------------------------
// Relations (shift 31-40)
// ---------------------------------------------------------------------------
pub const LT: OpCode = 143; // shift 31
pub const LE: OpCode = 144; // shift 32
pub const GT: OpCode = 145; // shift 33
pub const GE: OpCode = 146; // shift 34
pub const EQ: OpCode = 147; // shift 35
pub const NEQ: OpCode = 148; // shift 36
pub const If: OpCode = 149; // shift 37
pub const AND: OpCode = 150; // shift 38
pub const OR: OpCode = 151; // shift 39
pub const AtLeast: OpCode = 152; // shift 40

// ---------------------------------------------------------------------------
// Arithmetic (shift 41-50)
// ---------------------------------------------------------------------------
pub const Minus: OpCode = 153; // shift 41
pub const Plus: OpCode = 154; // shift 42
pub const Xor: OpCode = 155; // shift 43 - byte array XOR
pub const Multiply: OpCode = 156; // shift 44
pub const Division: OpCode = 157; // shift 45
pub const Modulo: OpCode = 158; // shift 46
pub const Exponentiate: OpCode = 159; // shift 47
pub const MultiplyGroup: OpCode = 160; // shift 48
pub const Min: OpCode = 161; // shift 49
pub const Max: OpCode = 162; // shift 50

// ---------------------------------------------------------------------------
// Environment/Context (shift 51-60)
// ---------------------------------------------------------------------------
pub const Height: OpCode = 163; // shift 51
pub const Inputs: OpCode = 164; // shift 52
pub const Outputs: OpCode = 165; // shift 53
pub const LastBlockUtxoRootHash: OpCode = 166; // shift 54
pub const Self: OpCode = 167; // shift 55
// reserved: shift 56-59
pub const MinerPubkey: OpCode = 172; // shift 60

// ---------------------------------------------------------------------------
// Collection operations (shift 61-72)
// ---------------------------------------------------------------------------
pub const MapCollection: OpCode = 173; // shift 61
pub const Exists: OpCode = 174; // shift 62
pub const ForAll: OpCode = 175; // shift 63
pub const Fold: OpCode = 176; // shift 64
pub const SizeOf: OpCode = 177; // shift 65
pub const ByIndex: OpCode = 178; // shift 66
pub const Append: OpCode = 179; // shift 67
pub const Slice: OpCode = 180; // shift 68
pub const Filter: OpCode = 181; // shift 69
pub const AvlTree: OpCode = 182; // shift 70
pub const AvlTreeGet: OpCode = 183; // shift 71
pub const FlatMapCollection: OpCode = 184; // shift 72

// ---------------------------------------------------------------------------
// Box operations (shift 81-87)
// ---------------------------------------------------------------------------
pub const ExtractAmount: OpCode = 193; // shift 81
pub const ExtractScriptBytes: OpCode = 194; // shift 82
pub const ExtractBytes: OpCode = 195; // shift 83
pub const ExtractBytesWithNoRef: OpCode = 196; // shift 84
pub const ExtractId: OpCode = 197; // shift 85
pub const ExtractRegisterAs: OpCode = 198; // shift 86
pub const ExtractCreationInfo: OpCode = 199; // shift 87

// ---------------------------------------------------------------------------
// Crypto (shift 91-99)
// ---------------------------------------------------------------------------
pub const CalcBlake2b256: OpCode = 203; // shift 91
pub const CalcSha256: OpCode = 204; // shift 92
pub const ProveDlog: OpCode = 205; // shift 93
pub const ProveDHTuple: OpCode = 206; // shift 94
pub const SigmaPropIsProven: OpCode = 207; // shift 95
pub const SigmaPropBytes: OpCode = 208; // shift 96
pub const BoolToSigmaProp: OpCode = 209; // shift 97
pub const TrivialPropFalse: OpCode = 210; // shift 98
pub const TrivialPropTrue: OpCode = 211; // shift 99

// ---------------------------------------------------------------------------
// Deserialization (shift 100-101)
// ---------------------------------------------------------------------------
pub const DeserializeContext: OpCode = 212; // shift 100
pub const DeserializeRegister: OpCode = 213; // shift 101

// ---------------------------------------------------------------------------
// Block/Function (shift 102-109)
// ---------------------------------------------------------------------------
pub const ValDef: OpCode = 214; // shift 102
pub const FunDef: OpCode = 215; // shift 103
pub const BlockValue: OpCode = 216; // shift 104
pub const FuncValue: OpCode = 217; // shift 105
pub const FuncApply: OpCode = 218; // shift 106
pub const PropertyCall: OpCode = 219; // shift 107
pub const MethodCall: OpCode = 220; // shift 108
pub const Global: OpCode = 221; // shift 109

// ---------------------------------------------------------------------------
// Option constructors (shift 110-111) - deprecated in Scala
// ---------------------------------------------------------------------------
pub const SomeValue: OpCode = 222; // shift 110 - deprecated
pub const NoneValue: OpCode = 223; // shift 111 - deprecated

// ---------------------------------------------------------------------------
// Option operations (shift 115-118)
// ---------------------------------------------------------------------------
pub const GetVar: OpCode = 227; // shift 115
pub const OptionGet: OpCode = 228; // shift 116
pub const OptionGetOrElse: OpCode = 229; // shift 117
pub const OptionIsDefined: OpCode = 230; // shift 118

// ---------------------------------------------------------------------------
// Modular arithmetic (shift 119-121) - deprecated in Scala
// ---------------------------------------------------------------------------
pub const ModQ: OpCode = 231; // shift 119 - deprecated
pub const PlusModQ: OpCode = 232; // shift 120 - deprecated
pub const MinusModQ: OpCode = 233; // shift 121 - deprecated

// ---------------------------------------------------------------------------
// Sigma operations (shift 122-125)
// ---------------------------------------------------------------------------
pub const SigmaAnd: OpCode = 234; // shift 122
pub const SigmaOr: OpCode = 235; // shift 123
pub const BinOr: OpCode = 236; // shift 124
pub const BinAnd: OpCode = 237; // shift 125

// ---------------------------------------------------------------------------
// More crypto (shift 126)
// ---------------------------------------------------------------------------
pub const DecodePoint: OpCode = 238; // shift 126

// ---------------------------------------------------------------------------
// Unary operations (shift 127-131)
// ---------------------------------------------------------------------------
pub const LogicalNot: OpCode = 239; // shift 127
pub const Negation: OpCode = 240; // shift 128
pub const BitInversion: OpCode = 241; // shift 129
pub const BitOr: OpCode = 242; // shift 130
pub const BitAnd: OpCode = 243; // shift 131

// ---------------------------------------------------------------------------
// XOR operations (shift 132-133)
// ---------------------------------------------------------------------------
pub const BinXor: OpCode = 244; // shift 132
pub const BitXor: OpCode = 245; // shift 133

// ---------------------------------------------------------------------------
// Bit shifts (shift 134-136)
// ---------------------------------------------------------------------------
pub const BitShiftRight: OpCode = 246; // shift 134
pub const BitShiftLeft: OpCode = 247; // shift 135
pub const BitShiftRightZeroed: OpCode = 248; // shift 136

// ---------------------------------------------------------------------------
// Collection shifts (shift 137-141) - deprecated in Scala
// ---------------------------------------------------------------------------
pub const CollShiftRight: OpCode = 249; // shift 137 - deprecated
pub const CollShiftLeft: OpCode = 250; // shift 138 - deprecated
pub const CollShiftRightZeroed: OpCode = 251; // shift 139 - deprecated
pub const CollRotateLeft: OpCode = 252; // shift 140 - deprecated
pub const CollRotateRight: OpCode = 253; // shift 141 - deprecated

// ---------------------------------------------------------------------------
// Context and XorOf (shift 142-143)
// ---------------------------------------------------------------------------
pub const Context: OpCode = 254; // shift 142
pub const XorOf: OpCode = 255; // shift 143

// ---------------------------------------------------------------------------
// Legacy aliases for backwards compatibility
// ---------------------------------------------------------------------------
pub const Apply: OpCode = FuncApply;
pub const MinerPubKey: OpCode = MinerPubkey; // case-insensitive alias

// ============================================================================
// Opcode Metadata Table
// ============================================================================

/// Get metadata for an opcode
pub fn getInfo(code: OpCode) ?OpInfo {
    return switch (code) {
        // Constants (type codes) - no cost as they're handled specially
        constant_first...constant_last => null,

        // Variables (shift 1-4)
        TaggedVariable => .{ .name = "TaggedVariable", .code = TaggedVariable, .category = .variable, .cost = 10 },
        ValUse => .{ .name = "ValUse", .code = ValUse, .category = .variable, .cost = 10 },
        ConstantPlaceholder => .{ .name = "ConstantPlaceholder", .code = ConstantPlaceholder, .category = .constant, .cost = 10 },
        SubstConstants => .{ .name = "SubstConstants", .code = SubstConstants, .category = .special, .cost = 100 },

        // Type conversions (shift 10-14)
        LongToByteArray => .{ .name = "LongToByteArray", .code = LongToByteArray, .category = .type_ops, .cost = 17 },
        ByteArrayToBigInt => .{ .name = "ByteArrayToBigInt", .code = ByteArrayToBigInt, .category = .type_ops, .cost = 30 },
        ByteArrayToLong => .{ .name = "ByteArrayToLong", .code = ByteArrayToLong, .category = .type_ops, .cost = 16 },
        Downcast => .{ .name = "Downcast", .code = Downcast, .category = .type_ops, .cost = 10 },
        Upcast => .{ .name = "Upcast", .code = Upcast, .category = .type_ops, .cost = 10 },

        // Literals (shift 15-21)
        TrueLeaf => .{ .name = "TrueLeaf", .code = TrueLeaf, .category = .literal, .cost = 10 },
        FalseLeaf => .{ .name = "FalseLeaf", .code = FalseLeaf, .category = .literal, .cost = 10 },
        UnitConstant => .{ .name = "UnitConstant", .code = UnitConstant, .category = .literal, .cost = 10 },
        GroupGenerator => .{ .name = "GroupGenerator", .code = GroupGenerator, .category = .crypto, .cost = 10 },
        ConcreteCollection => .{ .name = "ConcreteCollection", .code = ConcreteCollection, .category = .collection, .cost = 20 },
        ConcreteCollectionBooleanConstant => .{ .name = "ConcreteCollectionBooleanConstant", .code = ConcreteCollectionBooleanConstant, .category = .collection, .cost = 20 },

        // Tuple operations (shift 22-28)
        Tuple => .{ .name = "Tuple", .code = Tuple, .category = .collection, .cost = 10 },
        Select1 => .{ .name = "Select1", .code = Select1, .category = .collection, .cost = 10 },
        Select2 => .{ .name = "Select2", .code = Select2, .category = .collection, .cost = 10 },
        Select3 => .{ .name = "Select3", .code = Select3, .category = .collection, .cost = 10 },
        Select4 => .{ .name = "Select4", .code = Select4, .category = .collection, .cost = 10 },
        Select5 => .{ .name = "Select5", .code = Select5, .category = .collection, .cost = 10 },
        SelectField => .{ .name = "SelectField", .code = SelectField, .category = .collection, .cost = 10 },

        // Relations (shift 31-40)
        LT => .{ .name = "LT", .code = LT, .category = .comparison, .cost = 36 },
        LE => .{ .name = "LE", .code = LE, .category = .comparison, .cost = 36 },
        GT => .{ .name = "GT", .code = GT, .category = .comparison, .cost = 36 },
        GE => .{ .name = "GE", .code = GE, .category = .comparison, .cost = 36 },
        EQ => .{ .name = "EQ", .code = EQ, .category = .comparison, .cost = 36 },
        NEQ => .{ .name = "NEQ", .code = NEQ, .category = .comparison, .cost = 36 },
        If => .{ .name = "If", .code = If, .category = .control, .cost = 10 },
        AND => .{ .name = "AND", .code = AND, .category = .logical, .cost = 36 },
        OR => .{ .name = "OR", .code = OR, .category = .logical, .cost = 36 },
        AtLeast => .{ .name = "AtLeast", .code = AtLeast, .category = .sigma, .cost = 100 },

        // Arithmetic (shift 41-50)
        Minus => .{ .name = "Minus", .code = Minus, .category = .arithmetic, .cost = 36 },
        Plus => .{ .name = "Plus", .code = Plus, .category = .arithmetic, .cost = 36 },
        Xor => .{ .name = "Xor", .code = Xor, .category = .bitwise, .cost = 36 },
        Multiply => .{ .name = "Multiply", .code = Multiply, .category = .arithmetic, .cost = 41 },
        Division => .{ .name = "Division", .code = Division, .category = .arithmetic, .cost = 41 },
        Modulo => .{ .name = "Modulo", .code = Modulo, .category = .arithmetic, .cost = 41 },
        Exponentiate => .{ .name = "Exponentiate", .code = Exponentiate, .category = .crypto, .cost = 5100 },
        MultiplyGroup => .{ .name = "MultiplyGroup", .code = MultiplyGroup, .category = .crypto, .cost = 250 },
        Min => .{ .name = "Min", .code = Min, .category = .arithmetic, .cost = 36 },
        Max => .{ .name = "Max", .code = Max, .category = .arithmetic, .cost = 36 },

        // Environment/Context (shift 51-60)
        Height => .{ .name = "Height", .code = Height, .category = .context, .cost = 26 },
        Inputs => .{ .name = "Inputs", .code = Inputs, .category = .context, .cost = 10 },
        Outputs => .{ .name = "Outputs", .code = Outputs, .category = .context, .cost = 10 },
        LastBlockUtxoRootHash => .{ .name = "LastBlockUtxoRootHash", .code = LastBlockUtxoRootHash, .category = .context, .cost = 15 },
        Self => .{ .name = "Self", .code = Self, .category = .context, .cost = 10 },
        MinerPubkey => .{ .name = "MinerPubkey", .code = MinerPubkey, .category = .context, .cost = 100 },

        // Collection operations (shift 61-72)
        MapCollection => .{ .name = "MapCollection", .code = MapCollection, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Exists => .{ .name = "Exists", .code = Exists, .category = .collection, .cost = 20, .per_item_cost = 1 },
        ForAll => .{ .name = "ForAll", .code = ForAll, .category = .collection, .cost = 20, .per_item_cost = 1 },
        Fold => .{ .name = "Fold", .code = Fold, .category = .collection, .cost = 20, .per_item_cost = 1 },
        SizeOf => .{ .name = "SizeOf", .code = SizeOf, .category = .collection, .cost = 14 },
        ByIndex => .{ .name = "ByIndex", .code = ByIndex, .category = .collection, .cost = 30 },
        Append => .{ .name = "Append", .code = Append, .category = .collection, .cost = 20, .per_item_cost = 2 },
        Slice => .{ .name = "Slice", .code = Slice, .category = .collection, .cost = 20, .per_item_cost = 2 },
        Filter => .{ .name = "Filter", .code = Filter, .category = .collection, .cost = 20, .per_item_cost = 1 },
        AvlTree => .{ .name = "AvlTree", .code = AvlTree, .category = .crypto, .cost = 100 },
        AvlTreeGet => .{ .name = "AvlTreeGet", .code = AvlTreeGet, .category = .crypto, .cost = 200 },
        FlatMapCollection => .{ .name = "FlatMapCollection", .code = FlatMapCollection, .category = .collection, .cost = 60, .per_item_cost = 10 },

        // Box operations (shift 81-87)
        ExtractAmount => .{ .name = "ExtractAmount", .code = ExtractAmount, .category = .box_ops, .cost = 12 },
        ExtractScriptBytes => .{ .name = "ExtractScriptBytes", .code = ExtractScriptBytes, .category = .box_ops, .cost = 20 },
        ExtractBytes => .{ .name = "ExtractBytes", .code = ExtractBytes, .category = .box_ops, .cost = 100 },
        ExtractBytesWithNoRef => .{ .name = "ExtractBytesWithNoRef", .code = ExtractBytesWithNoRef, .category = .box_ops, .cost = 20 },
        ExtractId => .{ .name = "ExtractId", .code = ExtractId, .category = .box_ops, .cost = 12 },
        ExtractRegisterAs => .{ .name = "ExtractRegisterAs", .code = ExtractRegisterAs, .category = .box_ops, .cost = 50 },
        ExtractCreationInfo => .{ .name = "ExtractCreationInfo", .code = ExtractCreationInfo, .category = .box_ops, .cost = 16 },

        // Crypto (shift 91-99)
        CalcBlake2b256 => .{ .name = "CalcBlake2b256", .code = CalcBlake2b256, .category = .crypto, .cost = 59, .per_item_cost = 1 },
        CalcSha256 => .{ .name = "CalcSha256", .code = CalcSha256, .category = .crypto, .cost = 64, .per_item_cost = 1 },
        ProveDlog => .{ .name = "ProveDlog", .code = ProveDlog, .category = .crypto, .cost = 100 },
        ProveDHTuple => .{ .name = "ProveDHTuple", .code = ProveDHTuple, .category = .crypto, .cost = 200 },
        SigmaPropIsProven => .{ .name = "SigmaPropIsProven", .code = SigmaPropIsProven, .category = .sigma, .cost = 20 },
        SigmaPropBytes => .{ .name = "SigmaPropBytes", .code = SigmaPropBytes, .category = .sigma, .cost = 35 },
        BoolToSigmaProp => .{ .name = "BoolToSigmaProp", .code = BoolToSigmaProp, .category = .sigma, .cost = 15 },
        TrivialPropFalse => .{ .name = "TrivialPropFalse", .code = TrivialPropFalse, .category = .sigma, .cost = 10 },
        TrivialPropTrue => .{ .name = "TrivialPropTrue", .code = TrivialPropTrue, .category = .sigma, .cost = 10 },

        // Deserialization (shift 100-101)
        DeserializeContext => .{ .name = "DeserializeContext", .code = DeserializeContext, .category = .special, .cost = 100 },
        DeserializeRegister => .{ .name = "DeserializeRegister", .code = DeserializeRegister, .category = .special, .cost = 100 },

        // Block/Function (shift 102-109)
        ValDef => .{ .name = "ValDef", .code = ValDef, .category = .control, .cost = 10 },
        FunDef => .{ .name = "FunDef", .code = FunDef, .category = .control, .cost = 10 },
        BlockValue => .{ .name = "BlockValue", .code = BlockValue, .category = .control, .cost = 10 },
        FuncValue => .{ .name = "FuncValue", .code = FuncValue, .category = .control, .cost = 20 },
        FuncApply => .{ .name = "FuncApply", .code = FuncApply, .category = .control, .cost = 20 },
        PropertyCall => .{ .name = "PropertyCall", .code = PropertyCall, .category = .special, .cost = 10 },
        MethodCall => .{ .name = "MethodCall", .code = MethodCall, .category = .special, .cost = 10 },
        Global => .{ .name = "Global", .code = Global, .category = .context, .cost = 10 },

        // Option constructors (shift 110-111) - deprecated
        SomeValue => .{ .name = "SomeValue", .code = SomeValue, .category = .collection, .cost = 15 },
        NoneValue => .{ .name = "NoneValue", .code = NoneValue, .category = .collection, .cost = 10 },

        // Option operations (shift 115-118)
        GetVar => .{ .name = "GetVar", .code = GetVar, .category = .context, .cost = 100 },
        OptionGet => .{ .name = "OptionGet", .code = OptionGet, .category = .collection, .cost = 15 },
        OptionGetOrElse => .{ .name = "OptionGetOrElse", .code = OptionGetOrElse, .category = .collection, .cost = 20 },
        OptionIsDefined => .{ .name = "OptionIsDefined", .code = OptionIsDefined, .category = .collection, .cost = 15 },

        // Modular arithmetic (shift 119-121) - deprecated
        ModQ => .{ .name = "ModQ", .code = ModQ, .category = .crypto, .cost = 100 },
        PlusModQ => .{ .name = "PlusModQ", .code = PlusModQ, .category = .crypto, .cost = 100 },
        MinusModQ => .{ .name = "MinusModQ", .code = MinusModQ, .category = .crypto, .cost = 100 },

        // Sigma operations (shift 122-125)
        SigmaAnd => .{ .name = "SigmaAnd", .code = SigmaAnd, .category = .sigma, .cost = 20 },
        SigmaOr => .{ .name = "SigmaOr", .code = SigmaOr, .category = .sigma, .cost = 20 },
        BinOr => .{ .name = "BinOr", .code = BinOr, .category = .logical, .cost = 36 },
        BinAnd => .{ .name = "BinAnd", .code = BinAnd, .category = .logical, .cost = 36 },

        // More crypto (shift 126)
        DecodePoint => .{ .name = "DecodePoint", .code = DecodePoint, .category = .crypto, .cost = 1100 },

        // Unary operations (shift 127-131)
        LogicalNot => .{ .name = "LogicalNot", .code = LogicalNot, .category = .logical, .cost = 11 },
        Negation => .{ .name = "Negation", .code = Negation, .category = .arithmetic, .cost = 30 },
        BitInversion => .{ .name = "BitInversion", .code = BitInversion, .category = .bitwise, .cost = 30 },
        BitOr => .{ .name = "BitOr", .code = BitOr, .category = .bitwise, .cost = 36 },
        BitAnd => .{ .name = "BitAnd", .code = BitAnd, .category = .bitwise, .cost = 36 },

        // XOR operations (shift 132-133)
        BinXor => .{ .name = "BinXor", .code = BinXor, .category = .logical, .cost = 36 },
        BitXor => .{ .name = "BitXor", .code = BitXor, .category = .bitwise, .cost = 36 },

        // Bit shifts (shift 134-136)
        BitShiftRight => .{ .name = "BitShiftRight", .code = BitShiftRight, .category = .bitwise, .cost = 36 },
        BitShiftLeft => .{ .name = "BitShiftLeft", .code = BitShiftLeft, .category = .bitwise, .cost = 36 },
        BitShiftRightZeroed => .{ .name = "BitShiftRightZeroed", .code = BitShiftRightZeroed, .category = .bitwise, .cost = 36 },

        // Collection shifts (shift 137-141) - deprecated
        CollShiftRight => .{ .name = "CollShiftRight", .code = CollShiftRight, .category = .collection, .cost = 50 },
        CollShiftLeft => .{ .name = "CollShiftLeft", .code = CollShiftLeft, .category = .collection, .cost = 50 },
        CollShiftRightZeroed => .{ .name = "CollShiftRightZeroed", .code = CollShiftRightZeroed, .category = .collection, .cost = 50 },
        CollRotateLeft => .{ .name = "CollRotateLeft", .code = CollRotateLeft, .category = .collection, .cost = 50 },
        CollRotateRight => .{ .name = "CollRotateRight", .code = CollRotateRight, .category = .collection, .cost = 50 },

        // Context and XorOf (shift 142-143)
        Context => .{ .name = "Context", .code = Context, .category = .context, .cost = 10 },
        XorOf => .{ .name = "XorOf", .code = XorOf, .category = .logical, .cost = 20 },

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
