//! ErgoTree Type System
//!
//! Implements the SType hierarchy for ErgoTree bytecode. Types are used for:
//! - Compile-time type checking
//! - Serialization format determination
//! - Runtime value representation
//!
//! Design: Pre-allocated TypePool avoids dynamic allocation during evaluation.

const std = @import("std");
const assert = std.debug.assert;

/// Type code for serialization (0-255)
pub const TypeCode = u8;

/// Number of embeddable primitive types (codes 1-9)
pub const embeddable_count: u8 = 9;

/// Type constructor multiplier for embeddable optimization
pub const type_constr_base: u8 = 12;

// Compile-time sanity checks for type code layout
comptime {
    // Embeddable types must fit in type code ranges
    assert(embeddable_count <= type_constr_base);
    // Type constructor highest code (symmetric pair + max embeddable) must be < tuple5plus
    // symmetric_pair_base (84) + embeddable_count (9) = 93 < 96
    assert(84 + embeddable_count < 96);
    // Tuple5plus (96) must be below object range (97+)
    assert(96 < 97);
}

// ============================================================================
// Type Code Constants
// ============================================================================

/// Primitive type codes (embeddable: can combine with type constructors)
pub const PrimitiveCode = struct {
    pub const boolean: TypeCode = 1;
    pub const byte: TypeCode = 2;
    pub const short: TypeCode = 3;
    pub const int: TypeCode = 4;
    pub const long: TypeCode = 5;
    pub const big_int: TypeCode = 6;
    pub const group_element: TypeCode = 7;
    pub const sigma_prop: TypeCode = 8;
    pub const unsigned_big_int: TypeCode = 9; // v6+ only

    pub fn isEmbeddable(code: TypeCode) bool {
        return code >= 1 and code <= embeddable_count;
    }
};

/// Type constructor codes (for serialization format detection)
pub const TypeConstrCode = struct {
    /// Coll[T] where T is embeddable: 12 + T.code
    pub const coll_base: TypeCode = 12;
    /// Coll[Coll[T]] where T is embeddable: 24 + T.code
    pub const nested_coll_base: TypeCode = 24;
    /// Option[T] where T is embeddable: 36 + T.code
    pub const option_base: TypeCode = 36;
    /// Option[Coll[T]] where T is embeddable: 48 + T.code
    pub const option_coll_base: TypeCode = 48;
    /// (T, _) where T is embeddable: 60 + T.code
    pub const pair1_base: TypeCode = 60;
    /// (_, T) where T is embeddable: 72 + T.code (also Triple marker)
    pub const pair2_base: TypeCode = 72;
    /// (T, T) where T is embeddable: 84 + T.code (also Quadruple marker)
    pub const symmetric_pair_base: TypeCode = 84;
    /// Tuple with 5+ elements
    pub const tuple5plus: TypeCode = 96;

    /// Generic collection (non-embeddable element)
    pub const coll_generic: TypeCode = 0x0C; // 12
    /// Generic option (non-embeddable element)
    pub const option_generic: TypeCode = 0x24; // 36
    /// Triple marker
    pub const triple: TypeCode = 0x48; // 72
    /// Quadruple marker
    pub const quadruple: TypeCode = 0x54; // 84
};

/// Object type codes (non-embeddable)
pub const ObjectCode = struct {
    pub const any: TypeCode = 97;
    pub const unit: TypeCode = 98;
    pub const box: TypeCode = 99;
    pub const avl_tree: TypeCode = 100;
    pub const context: TypeCode = 101;
    pub const string: TypeCode = 102; // internal use
    pub const type_var: TypeCode = 103; // compiler use
    pub const header: TypeCode = 104;
    pub const pre_header: TypeCode = 105;
    pub const global: TypeCode = 106;
    // 107-111 reserved
    pub const func: TypeCode = 112; // v6+
};

// ============================================================================
// SType - Runtime Type Representation
// ============================================================================

/// Index into TypePool
pub const TypeIndex = u16;

/// Maximum types in a TypePool
pub const max_pool_types: usize = 256;

// Compile-time sanity checks for TypePool
comptime {
    // TypeIndex must be able to address all pool slots
    assert(max_pool_types <= std.math.maxInt(TypeIndex));
    // Pool size is reasonable for stack allocation
    assert(max_pool_types <= 4096);
    // Pool can hold at least primitives + common composites
    assert(max_pool_types >= 32);
}

/// Maximum tuple elements for inline storage
pub const max_tuple_elements: usize = 10;

/// Maximum function domain types (v6+)
pub const max_func_domain: usize = 8;

/// Maximum type params in function type (v6+)
pub const max_func_tpe_params: usize = 4;

/// Maximum type variable name length (v6+)
pub const max_type_var_name: usize = 16;

/// Tuple with N elements (5-10), inline storage for SType.tuple
pub const TupleN = struct {
    elements: [max_tuple_elements]TypeIndex,
    len: u8, // 5-10

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        assert(max_tuple_elements >= 5);
        assert(max_tuple_elements <= 255); // len fits in u8
        assert(@sizeOf(TupleN) <= 32); // Reasonable size
    }

    pub fn get(self: TupleN, idx: usize) TypeIndex {
        assert(idx < self.len);
        return self.elements[idx];
    }

    pub fn slice(self: *const TupleN) []const TypeIndex {
        return self.elements[0..self.len];
    }
};

/// Function type with inline storage for domain types (v6+)
pub const FuncType = struct {
    domain: [max_func_domain]TypeIndex,
    domain_len: u8,
    range: TypeIndex,
    /// Type parameters (indices to type_var entries in pool)
    tpe_params: [max_func_tpe_params]TypeIndex,
    tpe_params_len: u8,

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        assert(max_func_domain >= 1);
        assert(max_func_domain <= 255);
        assert(max_func_tpe_params <= 255);
        assert(@sizeOf(FuncType) <= 48); // Reasonable size
    }

    pub fn domainSlice(self: *const FuncType) []const TypeIndex {
        return self.domain[0..self.domain_len];
    }

    pub fn tpeParamsSlice(self: *const FuncType) []const TypeIndex {
        return self.tpe_params[0..self.tpe_params_len];
    }
};

/// Type variable with inline name storage (v6+)
pub const TypeVarType = struct {
    name: [max_type_var_name]u8,
    name_len: u8,

    // Compile-time assertions (ZIGMA_STYLE)
    comptime {
        assert(max_type_var_name >= 1);
        assert(max_type_var_name <= 255);
        assert(@sizeOf(TypeVarType) <= 24);
    }

    pub fn nameSlice(self: *const TypeVarType) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn eql(self: *const TypeVarType, other: *const TypeVarType) bool {
        if (self.name_len != other.name_len) return false;
        return std.mem.eql(u8, self.nameSlice(), other.nameSlice());
    }
};

/// Runtime type representation using tagged union.
/// Composite types store indices into TypePool to avoid recursion.
pub const SType = union(enum) {
    // Primitives (embeddable)
    boolean,
    byte,
    short,
    int,
    long,
    big_int,
    group_element,
    sigma_prop,
    unsigned_big_int, // v6+

    // Composite types (element type stored as pool index)
    coll: TypeIndex,
    option: TypeIndex,

    // Tuple types (indices into pool for each element)
    pair: struct { first: TypeIndex, second: TypeIndex },
    triple: struct { a: TypeIndex, b: TypeIndex, c: TypeIndex },
    quadruple: struct { a: TypeIndex, b: TypeIndex, c: TypeIndex, d: TypeIndex },
    /// Tuple with 5+ elements (inline storage, max 10)
    tuple: TupleN,

    /// Function type (v6+)
    func: FuncType,

    /// Type variable (v6+, used in polymorphic functions)
    type_var: TypeVarType,

    // Object types (non-embeddable)
    any,
    unit,
    box,
    avl_tree,
    context,
    header,
    pre_header,
    global,

    /// Get the type code for serialization
    pub fn typeCode(self: SType) TypeCode {
        return switch (self) {
            .boolean => PrimitiveCode.boolean,
            .byte => PrimitiveCode.byte,
            .short => PrimitiveCode.short,
            .int => PrimitiveCode.int,
            .long => PrimitiveCode.long,
            .big_int => PrimitiveCode.big_int,
            .group_element => PrimitiveCode.group_element,
            .sigma_prop => PrimitiveCode.sigma_prop,
            .unsigned_big_int => PrimitiveCode.unsigned_big_int,
            .any => ObjectCode.any,
            .unit => ObjectCode.unit,
            .box => ObjectCode.box,
            .avl_tree => ObjectCode.avl_tree,
            .context => ObjectCode.context,
            .header => ObjectCode.header,
            .pre_header => ObjectCode.pre_header,
            .global => ObjectCode.global,
            // Composite types and type_var need special serialization (not just type code)
            .coll, .option, .pair, .triple, .quadruple, .tuple, .func, .type_var => 0,
        };
    }

    /// Check if this is an embeddable primitive type
    pub fn isEmbeddable(self: SType) bool {
        return switch (self) {
            .boolean, .byte, .short, .int, .long, .big_int, .group_element, .sigma_prop, .unsigned_big_int => true,
            else => false,
        };
    }

    /// Check if this is a numeric type
    pub fn isNumeric(self: SType) bool {
        return switch (self) {
            .byte, .short, .int, .long, .big_int, .unsigned_big_int => true,
            else => false,
        };
    }

    /// Get embeddable code (1-9) or null if not embeddable
    pub fn embeddableCode(self: SType) ?u8 {
        return switch (self) {
            .boolean => 1,
            .byte => 2,
            .short => 3,
            .int => 4,
            .long => 5,
            .big_int => 6,
            .group_element => 7,
            .sigma_prop => 8,
            .unsigned_big_int => 9,
            else => null,
        };
    }
};

// ============================================================================
// TypePool - Pre-allocated Type Storage
// ============================================================================

/// Pre-allocated pool for type instances.
/// Avoids dynamic allocation during evaluation.
pub const TypePool = struct {
    types: [max_pool_types]SType,
    count: TypeIndex,

    // Pre-allocated indices for common types
    pub const BOOLEAN: TypeIndex = 0;
    pub const BYTE: TypeIndex = 1;
    pub const SHORT: TypeIndex = 2;
    pub const INT: TypeIndex = 3;
    pub const LONG: TypeIndex = 4;
    pub const BIG_INT: TypeIndex = 5;
    pub const GROUP_ELEMENT: TypeIndex = 6;
    pub const SIGMA_PROP: TypeIndex = 7;
    pub const UNSIGNED_BIG_INT: TypeIndex = 8;
    pub const ANY: TypeIndex = 9;
    pub const UNIT: TypeIndex = 10;
    pub const BOX: TypeIndex = 11;
    pub const AVL_TREE: TypeIndex = 12;
    pub const CONTEXT: TypeIndex = 13;
    pub const HEADER: TypeIndex = 14;
    pub const PRE_HEADER: TypeIndex = 15;
    pub const GLOBAL: TypeIndex = 16;
    // Common composite types
    pub const COLL_BYTE: TypeIndex = 17;
    pub const COLL_INT: TypeIndex = 18;
    pub const COLL_LONG: TypeIndex = 19;
    pub const COLL_COLL_BYTE: TypeIndex = 20;
    pub const OPTION_INT: TypeIndex = 21;
    pub const OPTION_LONG: TypeIndex = 22;
    pub const OPTION_COLL_BYTE: TypeIndex = 23;

    const first_dynamic: TypeIndex = 24;

    /// Initialize pool with all primitive and common types
    pub fn init() TypePool {
        var pool = TypePool{
            .types = undefined,
            .count = first_dynamic,
        };

        // Primitives
        pool.types[BOOLEAN] = .boolean;
        pool.types[BYTE] = .byte;
        pool.types[SHORT] = .short;
        pool.types[INT] = .int;
        pool.types[LONG] = .long;
        pool.types[BIG_INT] = .big_int;
        pool.types[GROUP_ELEMENT] = .group_element;
        pool.types[SIGMA_PROP] = .sigma_prop;
        pool.types[UNSIGNED_BIG_INT] = .unsigned_big_int;

        // Objects
        pool.types[ANY] = .any;
        pool.types[UNIT] = .unit;
        pool.types[BOX] = .box;
        pool.types[AVL_TREE] = .avl_tree;
        pool.types[CONTEXT] = .context;
        pool.types[HEADER] = .header;
        pool.types[PRE_HEADER] = .pre_header;
        pool.types[GLOBAL] = .global;

        // Common composites
        pool.types[COLL_BYTE] = .{ .coll = BYTE };
        pool.types[COLL_INT] = .{ .coll = INT };
        pool.types[COLL_LONG] = .{ .coll = LONG };
        pool.types[COLL_COLL_BYTE] = .{ .coll = COLL_BYTE };
        pool.types[OPTION_INT] = .{ .option = INT };
        pool.types[OPTION_LONG] = .{ .option = LONG };
        pool.types[OPTION_COLL_BYTE] = .{ .option = COLL_BYTE };

        return pool;
    }

    /// Get type at index
    pub fn get(self: *const TypePool, idx: TypeIndex) SType {
        assert(idx < self.count);
        return self.types[idx];
    }

    /// Add a new type, returns its index
    pub fn add(self: *TypePool, t: SType) error{PoolFull}!TypeIndex {
        if (self.count >= max_pool_types) return error.PoolFull;
        const idx = self.count;
        self.types[idx] = t;
        self.count += 1;
        return idx;
    }

    /// Get or create Coll[T] type
    pub fn getColl(self: *TypePool, elem_idx: TypeIndex) error{PoolFull}!TypeIndex {
        // PRECONDITION: Element type must exist in pool
        assert(elem_idx < self.count);

        // Check for pre-allocated common types
        if (elem_idx == BYTE) return COLL_BYTE;
        if (elem_idx == INT) return COLL_INT;
        if (elem_idx == LONG) return COLL_LONG;
        if (elem_idx == COLL_BYTE) return COLL_COLL_BYTE;

        // Search existing
        for (self.types[first_dynamic..self.count], first_dynamic..) |t, i| {
            if (t == .coll and t.coll == elem_idx) {
                return @intCast(i);
            }
        }

        // Create new
        const result = try self.add(.{ .coll = elem_idx });

        // POSTCONDITION: Result is valid index with correct type
        assert(result < self.count);
        assert(self.types[result] == .coll);

        return result;
    }

    /// Get or create Option[T] type
    pub fn getOption(self: *TypePool, elem_idx: TypeIndex) error{PoolFull}!TypeIndex {
        // PRECONDITION: Element type must exist in pool
        assert(elem_idx < self.count);

        // Check for pre-allocated common types
        if (elem_idx == INT) return OPTION_INT;
        if (elem_idx == LONG) return OPTION_LONG;
        if (elem_idx == COLL_BYTE) return OPTION_COLL_BYTE;

        // Search existing
        for (self.types[first_dynamic..self.count], first_dynamic..) |t, i| {
            if (t == .option and t.option == elem_idx) {
                return @intCast(i);
            }
        }

        // Create new
        const result = try self.add(.{ .option = elem_idx });

        // POSTCONDITION: Result is valid index with correct type
        assert(result < self.count);
        assert(self.types[result] == .option);

        return result;
    }

    /// Get or create (T1, T2) pair type
    pub fn getPair(self: *TypePool, first: TypeIndex, second: TypeIndex) error{PoolFull}!TypeIndex {
        // PRECONDITIONS: Both element types must exist in pool
        assert(first < self.count);
        assert(second < self.count);

        // Search existing
        for (self.types[first_dynamic..self.count], first_dynamic..) |t, i| {
            if (t == .pair and t.pair.first == first and t.pair.second == second) {
                return @intCast(i);
            }
        }

        // Create new
        const result = try self.add(.{ .pair = .{ .first = first, .second = second } });

        // POSTCONDITION: Result is valid index with correct type
        assert(result < self.count);
        assert(self.types[result] == .pair);

        return result;
    }

    /// Get or create a TupleN (5-10 elements) type
    pub fn getTupleN(self: *TypePool, elements: []const TypeIndex) error{PoolFull}!TypeIndex {
        // PRECONDITION: Valid length for tuple5+
        assert(elements.len >= 5);
        assert(elements.len <= max_tuple_elements);
        // PRECONDITION: All element indices are valid
        for (elements) |e| {
            assert(e < self.count);
        }

        // Build TupleN structure
        var tuple = TupleN{
            .elements = undefined,
            .len = @intCast(elements.len),
        };
        for (elements, 0..) |e, i| {
            tuple.elements[i] = e;
        }
        // Zero-fill remaining slots
        for (elements.len..max_tuple_elements) |i| {
            tuple.elements[i] = 0;
        }

        // Search existing
        for (self.types[first_dynamic..self.count], first_dynamic..) |t, i| {
            if (t == .tuple and t.tuple.len == elements.len) {
                var matches = true;
                for (0..elements.len) |j| {
                    if (t.tuple.elements[j] != elements[j]) {
                        matches = false;
                        break;
                    }
                }
                if (matches) return @intCast(i);
            }
        }

        // Create new
        const result = try self.add(.{ .tuple = tuple });

        // POSTCONDITION: Result is valid index with correct type
        assert(result < self.count);
        assert(self.types[result] == .tuple);

        return result;
    }

    /// Calculate serialization type code for a type at given index
    pub fn getTypeCode(self: *const TypePool, idx: TypeIndex) TypeCode {
        const t = self.get(idx);

        // Direct type codes for non-composite types
        const direct_code = t.typeCode();
        if (direct_code != 0) return direct_code;

        // Composite type encoding
        switch (t) {
            .coll => |elem_idx| {
                const elem = self.get(elem_idx);
                // Check if nested Coll[Coll[T]] first
                if (elem == .coll) {
                    const inner_elem = self.get(elem.coll);
                    if (inner_elem.embeddableCode()) |inner_code| {
                        return TypeConstrCode.nested_coll_base + inner_code;
                    }
                }
                // Then check for Coll[T] where T is embeddable
                if (elem.embeddableCode()) |code| {
                    return TypeConstrCode.coll_base + code;
                }
                return TypeConstrCode.coll_generic;
            },
            .option => |elem_idx| {
                const elem = self.get(elem_idx);
                // Check Option[Coll[T]] first
                if (elem == .coll) {
                    const inner_elem = self.get(elem.coll);
                    if (inner_elem.embeddableCode()) |inner_code| {
                        return TypeConstrCode.option_coll_base + inner_code;
                    }
                }
                // Then check for Option[T] where T is embeddable
                if (elem.embeddableCode()) |code| {
                    return TypeConstrCode.option_base + code;
                }
                return TypeConstrCode.option_generic;
            },
            .pair => |p| {
                const first = self.get(p.first);
                const second = self.get(p.second);
                // Symmetric pair (T, T)
                if (p.first == p.second) {
                    if (first.embeddableCode()) |code| {
                        return TypeConstrCode.symmetric_pair_base + code;
                    }
                }
                // (T, _) where T is embeddable
                if (first.embeddableCode()) |code| {
                    return TypeConstrCode.pair1_base + code;
                }
                // (_, T) where T is embeddable
                if (second.embeddableCode()) |code| {
                    return TypeConstrCode.pair2_base + code;
                }
                // Generic pair - use pair1 with first type serialized after
                return TypeConstrCode.pair1_base;
            },
            .triple => return TypeConstrCode.triple,
            .quadruple => return TypeConstrCode.quadruple,
            .tuple => return TypeConstrCode.tuple5plus,
            .func => return ObjectCode.func,
            .type_var => return ObjectCode.type_var,
            else => unreachable,
        }
    }

    /// Reset pool to initial state (keeps pre-allocated types)
    pub fn reset(self: *TypePool) void {
        self.count = first_dynamic;
    }
};

// ============================================================================
// Type Parsing from Code
// ============================================================================

/// Parse a type code into its structure
pub const TypeCodeInfo = union(enum) {
    /// Invalid type code
    invalid,
    /// Primitive type (code 1-9)
    primitive: SType,
    /// Coll[Primitive] (codes 13-21)
    coll_primitive: u8, // inner primitive code
    /// Coll[Coll[Primitive]] (codes 25-33)
    nested_coll_primitive: u8,
    /// Option[Primitive] (codes 37-45)
    option_primitive: u8,
    /// Option[Coll[Primitive]] (codes 49-57)
    option_coll_primitive: u8,
    /// (Primitive, _) (codes 61-69)
    pair1_primitive: u8,
    /// (_, Primitive) (codes 73-81)
    pair2_primitive: u8,
    /// (Primitive, Primitive) symmetric (codes 85-93)
    symmetric_pair_primitive: u8,
    /// Object type (codes 97-106)
    object: SType,
    /// Generic collection - needs recursive parsing
    coll_generic,
    /// Generic option - needs recursive parsing
    option_generic,
    /// Generic pair1 - both elements need recursive parsing (code 60)
    pair1_generic,
    /// Triple - needs 3 recursive types
    triple,
    /// Quadruple - needs 4 recursive types
    quadruple,
    /// Tuple 5+ - needs length then recursive types
    tuple5plus,
    /// Function type (v6+)
    func,
    /// Type variable (v6+)
    type_var,

    pub fn parse(code: TypeCode) TypeCodeInfo {
        // Primitives (1-9)
        if (code >= 1 and code <= embeddable_count) {
            return .{ .primitive = primitiveFromCode(code) };
        }

        // Type variable (103) - v6+
        if (code == ObjectCode.type_var) return .type_var;

        // Object types (97-106, excluding type_var)
        if (code >= ObjectCode.any and code <= ObjectCode.global) {
            return .{ .object = objectFromCode(code) };
        }

        // Function (112)
        if (code == ObjectCode.func) return .func;

        // Invalid (0, 10-11, 107-111, 113+)
        if (code == 0 or (code >= 10 and code <= 11) or code >= 113) {
            return .invalid;
        }

        // Type constructor ranges
        if (code >= TypeConstrCode.symmetric_pair_base) {
            const offset = code - TypeConstrCode.symmetric_pair_base;
            if (offset == 0) return .quadruple; // 84 = quadruple marker
            if (offset <= embeddable_count) return .{ .symmetric_pair_primitive = offset };
            if (code == TypeConstrCode.tuple5plus) return .tuple5plus;
            return .invalid;
        }

        if (code >= TypeConstrCode.pair2_base) {
            const offset = code - TypeConstrCode.pair2_base;
            if (offset == 0) return .triple; // 72 = triple marker
            if (offset <= embeddable_count) return .{ .pair2_primitive = offset };
            return .invalid;
        }

        if (code >= TypeConstrCode.pair1_base) {
            const offset = code - TypeConstrCode.pair1_base;
            if (offset == 0) return .pair1_generic; // 60 = pair where first is non-embeddable
            if (offset <= embeddable_count) return .{ .pair1_primitive = offset };
            return .invalid;
        }

        if (code >= TypeConstrCode.option_coll_base) {
            const offset = code - TypeConstrCode.option_coll_base;
            if (offset <= embeddable_count and offset >= 1) return .{ .option_coll_primitive = offset };
            return .invalid;
        }

        if (code >= TypeConstrCode.option_base) {
            const offset = code - TypeConstrCode.option_base;
            if (offset == 0) return .option_generic; // 36 = option with non-embeddable
            if (offset <= embeddable_count) return .{ .option_primitive = offset };
            return .invalid;
        }

        if (code >= TypeConstrCode.nested_coll_base) {
            const offset = code - TypeConstrCode.nested_coll_base;
            if (offset <= embeddable_count and offset >= 1) return .{ .nested_coll_primitive = offset };
            return .invalid;
        }

        if (code >= TypeConstrCode.coll_base) {
            const offset = code - TypeConstrCode.coll_base;
            if (offset == 0) return .coll_generic; // 12 = coll with non-embeddable
            if (offset <= embeddable_count) return .{ .coll_primitive = offset };
            return .invalid;
        }

        return .invalid;
    }
};

fn primitiveFromCode(code: u8) SType {
    return switch (code) {
        1 => .boolean,
        2 => .byte,
        3 => .short,
        4 => .int,
        5 => .long,
        6 => .big_int,
        7 => .group_element,
        8 => .sigma_prop,
        9 => .unsigned_big_int,
        else => unreachable,
    };
}

fn objectFromCode(code: TypeCode) SType {
    return switch (code) {
        ObjectCode.any => .any,
        ObjectCode.unit => .unit,
        ObjectCode.box => .box,
        ObjectCode.avl_tree => .avl_tree,
        ObjectCode.context => .context,
        ObjectCode.header => .header,
        ObjectCode.pre_header => .pre_header,
        ObjectCode.global => .global,
        else => unreachable,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "types: primitive type codes" {
    const boolean: SType = .boolean;
    const byte: SType = .byte;
    const short: SType = .short;
    const int: SType = .int;
    const long: SType = .long;
    const big_int: SType = .big_int;
    const group_element: SType = .group_element;
    const sigma_prop: SType = .sigma_prop;
    const unsigned_big_int: SType = .unsigned_big_int;

    try std.testing.expectEqual(@as(TypeCode, 1), boolean.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 2), byte.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 3), short.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 4), int.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 5), long.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 6), big_int.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 7), group_element.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 8), sigma_prop.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 9), unsigned_big_int.typeCode());
}

test "types: object type codes" {
    const any: SType = .any;
    const unit: SType = .unit;
    const box: SType = .box;
    const avl_tree: SType = .avl_tree;
    const context: SType = .context;
    const header: SType = .header;
    const pre_header: SType = .pre_header;
    const global: SType = .global;

    try std.testing.expectEqual(@as(TypeCode, 97), any.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 98), unit.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 99), box.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 100), avl_tree.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 101), context.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 104), header.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 105), pre_header.typeCode());
    try std.testing.expectEqual(@as(TypeCode, 106), global.typeCode());
}

test "types: embeddable check" {
    const boolean: SType = .boolean;
    const int: SType = .int;
    const big_int: SType = .big_int;
    const box: SType = .box;
    const any: SType = .any;

    try std.testing.expect(boolean.isEmbeddable());
    try std.testing.expect(int.isEmbeddable());
    try std.testing.expect(big_int.isEmbeddable());
    try std.testing.expect(!box.isEmbeddable());
    try std.testing.expect(!any.isEmbeddable());
}

test "types: numeric check" {
    const boolean: SType = .boolean;
    const byte: SType = .byte;
    const int: SType = .int;
    const long: SType = .long;
    const big_int: SType = .big_int;
    const group_element: SType = .group_element;

    try std.testing.expect(!boolean.isNumeric());
    try std.testing.expect(byte.isNumeric());
    try std.testing.expect(int.isNumeric());
    try std.testing.expect(long.isNumeric());
    try std.testing.expect(big_int.isNumeric());
    try std.testing.expect(!group_element.isNumeric());
}

test "types: TypePool initialization" {
    const pool = TypePool.init();

    try std.testing.expectEqual(SType.boolean, pool.get(TypePool.BOOLEAN));
    try std.testing.expectEqual(SType.int, pool.get(TypePool.INT));
    try std.testing.expectEqual(SType.box, pool.get(TypePool.BOX));

    // Check pre-allocated composite types
    const coll_byte = pool.get(TypePool.COLL_BYTE);
    try std.testing.expect(coll_byte == .coll);
    try std.testing.expectEqual(TypePool.BYTE, coll_byte.coll);
}

test "types: TypePool composite type codes" {
    const pool = TypePool.init();

    // Coll[Byte] = 14 (12 + 2)
    try std.testing.expectEqual(@as(TypeCode, 14), pool.getTypeCode(TypePool.COLL_BYTE));
    // Coll[Int] = 16 (12 + 4)
    try std.testing.expectEqual(@as(TypeCode, 16), pool.getTypeCode(TypePool.COLL_INT));
    // Coll[Long] = 17 (12 + 5)
    try std.testing.expectEqual(@as(TypeCode, 17), pool.getTypeCode(TypePool.COLL_LONG));
    // Coll[Coll[Byte]] = 26 (24 + 2)
    try std.testing.expectEqual(@as(TypeCode, 26), pool.getTypeCode(TypePool.COLL_COLL_BYTE));
    // Option[Int] = 40 (36 + 4)
    try std.testing.expectEqual(@as(TypeCode, 40), pool.getTypeCode(TypePool.OPTION_INT));
    // Option[Coll[Byte]] = 50 (48 + 2)
    try std.testing.expectEqual(@as(TypeCode, 50), pool.getTypeCode(TypePool.OPTION_COLL_BYTE));
}

test "types: TypePool add and lookup" {
    var pool = TypePool.init();

    // Add a new pair type
    const pair_idx = try pool.getPair(TypePool.INT, TypePool.LONG);
    const pair_type = pool.get(pair_idx);
    try std.testing.expect(pair_type == .pair);
    try std.testing.expectEqual(TypePool.INT, pair_type.pair.first);
    try std.testing.expectEqual(TypePool.LONG, pair_type.pair.second);

    // Looking up same pair should return same index
    const pair_idx2 = try pool.getPair(TypePool.INT, TypePool.LONG);
    try std.testing.expectEqual(pair_idx, pair_idx2);
}

test "types: TypeCodeInfo parsing" {
    // Primitives
    try std.testing.expect(TypeCodeInfo.parse(1) == .primitive);
    try std.testing.expect(TypeCodeInfo.parse(4) == .primitive);

    // Coll[Primitive]
    const coll_byte = TypeCodeInfo.parse(14); // 12 + 2
    try std.testing.expect(coll_byte == .coll_primitive);
    try std.testing.expectEqual(@as(u8, 2), coll_byte.coll_primitive);

    // Option[Primitive]
    const opt_int = TypeCodeInfo.parse(40); // 36 + 4
    try std.testing.expect(opt_int == .option_primitive);
    try std.testing.expectEqual(@as(u8, 4), opt_int.option_primitive);

    // Object types
    try std.testing.expect(TypeCodeInfo.parse(99) == .object); // Box

    // Invalid
    try std.testing.expect(TypeCodeInfo.parse(0) == .invalid);
}

test "types: spec vectors - type serialization" {
    const pool = TypePool.init();

    // From vectors.json type_serialization section
    // Primitives
    try std.testing.expectEqual(@as(TypeCode, 0x01), pool.getTypeCode(TypePool.BOOLEAN));
    try std.testing.expectEqual(@as(TypeCode, 0x02), pool.getTypeCode(TypePool.BYTE));
    try std.testing.expectEqual(@as(TypeCode, 0x04), pool.getTypeCode(TypePool.INT));
    try std.testing.expectEqual(@as(TypeCode, 0x05), pool.getTypeCode(TypePool.LONG));
    try std.testing.expectEqual(@as(TypeCode, 0x06), pool.getTypeCode(TypePool.BIG_INT));
    try std.testing.expectEqual(@as(TypeCode, 0x07), pool.getTypeCode(TypePool.GROUP_ELEMENT));
    try std.testing.expectEqual(@as(TypeCode, 0x08), pool.getTypeCode(TypePool.SIGMA_PROP));

    // Collections: Coll[T] = T + 12
    try std.testing.expectEqual(@as(TypeCode, 0x0e), pool.getTypeCode(TypePool.COLL_BYTE)); // 2+12=14
    try std.testing.expectEqual(@as(TypeCode, 0x10), pool.getTypeCode(TypePool.COLL_INT)); // 4+12=16
    try std.testing.expectEqual(@as(TypeCode, 0x11), pool.getTypeCode(TypePool.COLL_LONG)); // 5+12=17

    // Nested: Coll[Coll[T]] = T + 24
    try std.testing.expectEqual(@as(TypeCode, 0x1a), pool.getTypeCode(TypePool.COLL_COLL_BYTE)); // 2+24=26

    // Options: Option[T] = T + 36
    try std.testing.expectEqual(@as(TypeCode, 0x28), pool.getTypeCode(TypePool.OPTION_INT)); // 4+36=40
    try std.testing.expectEqual(@as(TypeCode, 0x29), pool.getTypeCode(TypePool.OPTION_LONG)); // 5+36=41

    // Option[Coll[T]] = T + 48
    try std.testing.expectEqual(@as(TypeCode, 0x32), pool.getTypeCode(TypePool.OPTION_COLL_BYTE)); // 2+48=50

    // Objects
    try std.testing.expectEqual(@as(TypeCode, 0x63), pool.getTypeCode(TypePool.BOX)); // 99
    try std.testing.expectEqual(@as(TypeCode, 0x64), pool.getTypeCode(TypePool.AVL_TREE)); // 100
}

test "types: symmetric pair encoding" {
    var pool = TypePool.init();

    // (Int, Int) = 4 + 84 = 88 = 0x58
    const pair_int_int = try pool.getPair(TypePool.INT, TypePool.INT);
    try std.testing.expectEqual(@as(TypeCode, 0x58), pool.getTypeCode(pair_int_int));

    // (Byte, Byte) = 2 + 84 = 86 = 0x56
    const pair_byte_byte = try pool.getPair(TypePool.BYTE, TypePool.BYTE);
    try std.testing.expectEqual(@as(TypeCode, 0x56), pool.getTypeCode(pair_byte_byte));
}

test "types: asymmetric pair encoding" {
    var pool = TypePool.init();

    // (Int, Box) = Pair1: 4 + 60 = 64 = 0x40, then serialize(Box)
    const pair_int_box = try pool.getPair(TypePool.INT, TypePool.BOX);
    try std.testing.expectEqual(@as(TypeCode, 0x40), pool.getTypeCode(pair_int_box));

    // (Box, Int) = Pair2: 4 + 72 = 76 = 0x4C, then serialize(Box)
    const pair_box_int = try pool.getPair(TypePool.BOX, TypePool.INT);
    try std.testing.expectEqual(@as(TypeCode, 0x4c), pool.getTypeCode(pair_box_int));
}
