## Phase 2: Serialization Layer

### Prompt 2.1: Type Serialization

```
TASK: Implement type serialization matching ErgoTree specification exactly

CONTEXT (From Ergo Core Developers):
"Type serialization is tricky because of the embedded type optimization.
For example, Coll[Byte] is a SINGLE byte (0x0E = 12 + 2) not two bytes.
But Coll[(Int,Byte)] is multiple bytes: 0x0C then the pair type.

Study TypeSerializer.scala very carefully. The encoding is designed
for space efficiency, not readability."

PREREQUISITE KNOWLEDGE:
- Embeddable types (1-11) can be added to constructor base code
- Constructor base codes: Coll=12, CollColl=24, Option=36, etc.
- Function types: code = domain*12 + range + 112
- Pairs have special encoding for symmetric/embedded cases
- See ErgoTree Spec Section 5.1

REFERENCE (From Scala TypeSerializer):
```scala
def serialize(tpe: SType, w: SigmaByteWriter): Unit = tpe match {
  case p: SPrimType => w.put(p.typeCode)
  case SCollectionType(elemType) => serializeColl(elemType, w)
  case SOption(elemType) => serializeOption(elemType, w)
  case STuple(items) => serializeTuple(items, w)
  case SFunc(tDom, tRange, _) => serializeFunc(tDom, tRange, w)
  case _ => w.put(tpe.typeCode)
}
```

CREATE FILE: src/serialization/type_serializer.zig

IMPLEMENTATION:
```zig
pub const TypeSerializer = struct {
    
    /// Serialize type to bytes
    pub fn serialize(pool: *const TypePool, type_idx: TypeIndex, writer: anytype) !void {
        const stype = pool.get(type_idx);
        
        switch (stype) {
            .prim => |p| {
                try writer.writeByte(@intFromEnum(p));
            },
            .coll => |elem_idx| {
                try serializeColl(pool, elem_idx, writer);
            },
            .option => |inner_idx| {
                try serializeOption(pool, inner_idx, writer);
            },
            .tuple => |t| {
                try serializeTuple(pool, t, writer);
            },
            .func => |f| {
                try serializeFunc(pool, f, writer);
            },
            .predef => |p| {
                try writer.writeByte(@intFromEnum(p));
            },
        }
    }
    
    fn serializeColl(pool: *const TypePool, elem_idx: TypeIndex, writer: anytype) !void {
        const elem = pool.get(elem_idx);
        
        switch (elem) {
            .prim => |p| {
                // Embeddable: single byte = 12 + primCode
                try writer.writeByte(12 + @intFromEnum(p));
            },
            .coll => |inner_elem| {
                // Nested: check if inner element is embeddable
                const inner = pool.get(inner_elem);
                switch (inner) {
                    .prim => |p| {
                        // Coll[Coll[Prim]]: single byte = 24 + primCode
                        try writer.writeByte(24 + @intFromEnum(p));
                    },
                    else => {
                        // Coll[Coll[Complex]]: 24 then recurse
                        try writer.writeByte(24);
                        try serialize(pool, inner_elem, writer);
                    },
                }
            },
            else => {
                // Non-embeddable: 12 then element type
                try writer.writeByte(12);
                try serialize(pool, elem_idx, writer);
            },
        }
    }
    
    /// Deserialize type from bytes
    pub fn deserialize(pool: *TypePool, reader: anytype) !TypeIndex {
        const code = try reader.readByte();
        
        // Check for embeddable primitive
        if (code >= 1 and code <= 11) {
            return pool.getPrimitive(@enumFromInt(code));
        }
        
        // Check for predefined types
        if (code >= 97 and code <= 106) {
            return pool.getPredefined(@enumFromInt(code));
        }
        
        // Decode composite type
        if (code >= 12 and code <= 23) {
            // Coll[embeddable]
            const elem_code = code - 12;
            const elem_idx = pool.getPrimitive(@enumFromInt(elem_code));
            return pool.addColl(elem_idx);
        }
        
        // ... (continue for all type codes)
        
        return error.InvalidTypeCode;
    }
};
```

TESTS (From spec Table 7):
[ ] Byte → 0x02
[ ] Coll[Byte] → 0x0E (14 = 12 + 2)
[ ] Coll[Coll[Byte]] → 0x1A (26 = 24 + 2)
[ ] Option[Byte] → 0x26 (38 = 36 + 2)
[ ] (Int,Int) → 0x58 (88 = 84 + 4)
[ ] Int=>Boolean → 0xA1 (161 = 4*12 + 1 + 112)
[ ] Roundtrip all type combinations
```

### Prompt 2.2: Data Serialization

```
TASK: Implement data value serialization for all types

CONTEXT (From Cryptography Engineers):
"Pay close attention to:
1. BigInt: variable length, big-endian, two's complement
2. GroupElement: SEC1 compressed point (33 bytes), MUST validate on curve
3. SigmaProp: recursive tree structure with multiple variants
4. Collections: length-prefixed, elements serialized sequentially
5. Booleans in collections: bit-packed for efficiency

Never trust deserialized data. Validate everything."

PREREQUISITE KNOWLEDGE:
- Data serialization is type-directed (need type to deserialize)
- VLQ used for lengths
- ZigZag+VLQ for signed integers
- GroupElement is secp256k1 point
- See ErgoTree Spec Section 5.2

CREATE FILE: src/serialization/data_serializer.zig

IMPLEMENTATION:
```zig
pub const DataSerializer = struct {
    
    /// Serialize value based on type
    pub fn serialize(
        state: *const InterpreterState,
        type_idx: TypeIndex,
        value_ref: ValueRef,
        writer: anytype,
    ) !void {
        const stype = state.types.get(type_idx);
        
        switch (stype) {
            .prim => |p| switch (p) {
                .boolean => {
                    const b = state.stack.getBool(value_ref.slot);
                    try writer.writeByte(if (b) 1 else 0);
                },
                .byte => {
                    const v = @as(i8, @truncate(state.stack.getInt(value_ref.slot)));
                    try SignedVLQ.encode(i8, v, writer);
                },
                .short, .int, .long => {
                    const v = state.stack.getInt(value_ref.slot);
                    try SignedVLQ.encode(i64, v, writer);
                },
                .big_int => {
                    try serializeBigInt(state, value_ref, writer);
                },
                .group_element => {
                    try serializeGroupElement(state, value_ref, writer);
                },
                .sigma_prop => {
                    try serializeSigmaProp(state, value_ref, writer);
                },
            },
            .coll => |elem_type| {
                try serializeCollection(state, elem_type, value_ref, writer);
            },
            // ... other types
        }
    }
    
    fn serializeCollection(
        state: *const InterpreterState,
        elem_type: TypeIndex,
        coll_ref: ValueRef,
        writer: anytype,
    ) !void {
        const coll = state.collections.get(coll_ref.index);
        
        // Write length
        try VLQ.encodeUnsigned(u16, coll.len, writer);
        
        // Check for bit-packed booleans
        const elem_stype = state.types.get(elem_type);
        if (elem_stype == .prim and elem_stype.prim == .boolean) {
            try serializeBoolCollection(state, coll, writer);
            return;
        }
        
        // Check for byte array (common case, no VLQ encoding)
        if (elem_stype == .prim and elem_stype.prim == .byte) {
            try writer.writeAll(state.getByteSlice(coll));
            return;
        }
        
        // General case: serialize each element
        for (0..coll.len) |i| {
            const elem_ref = state.collections.getElement(coll, i);
            try serialize(state, elem_type, elem_ref, writer);
        }
    }
    
    fn serializeGroupElement(
        state: *const InterpreterState,
        value_ref: ValueRef,
        writer: anytype,
    ) !void {
        const ge_idx = state.stack.getRef(value_ref.slot);
        const encoded = state.constants.getGroupElement(ge_idx);
        
        // 33 bytes SEC1 compressed point
        std.debug.assert(encoded.len == 33);
        try writer.writeAll(encoded);
    }
    
    /// Deserialize value based on type
    pub fn deserialize(
        state: *InterpreterState,
        type_idx: TypeIndex,
        reader: anytype,
    ) !ValueRef {
        const stype = state.types.get(type_idx);
        
        switch (stype) {
            .prim => |p| switch (p) {
                .boolean => {
                    const b = try reader.readByte();
                    if (b > 1) return error.InvalidBoolean;
                    try state.stack.pushBool(b == 1);
                    return state.stack.topRef();
                },
                .byte => {
                    const v = try SignedVLQ.decode(i8, reader);
                    try state.stack.pushInt(v, @intFromEnum(PrimType.byte));
                    return state.stack.topRef();
                },
                // ... other primitives
            },
            // ... other types
        }
    }
};
```

CRITICAL TESTS:
[ ] BigInt: positive, negative, zero, max/min
[ ] GroupElement: valid point, point at infinity, invalid point (must reject)
[ ] Coll[Boolean]: bit packing correct
[ ] Coll[Byte]: direct copy (no VLQ per element)
[ ] Empty collections
[ ] Nested collections
```

### Prompt 2.3: Expression Serialization

```
TASK: Implement expression tree serialization

CONTEXT (From Ergo Core Developers):
"Expression serialization is where the opcode definitions come in.
Each opcode has a specific serialization format:
- Constants: opcode (which encodes type) + data
- Binary ops: opcode + left expr + right expr
- Collection ops: opcode + collection expr + lambda expr
- Blocks: opcode + num_vals + val_defs + body

The serializer table in Appendix C of the spec has all formats.
You'll need a dispatch table based on opcode."

PREREQUISITE KNOWLEDGE:
- Expressions form a tree structure
- Serialization is depth-first pre-order
- Each opcode determines what follows
- Some opcodes have variable-length operand lists
- See ErgoTree Spec Section 5.4 and Appendix C

CREATE FILE: src/serialization/expr_serializer.zig

IMPLEMENTATION:
```zig
pub const ExprSerializer = struct {
    
    /// Serialize expression tree
    pub fn serialize(
        state: *const InterpreterState,
        node_idx: NodeIndex,
        writer: anytype,
    ) !void {
        const opcode = state.expressions.getOpcode(node_idx);
        
        // Write opcode first
        try writer.writeByte(opcode);
        
        // Dispatch based on opcode
        if (OpCode.isConstant(opcode)) {
            try serializeConstant(state, node_idx, writer);
        } else {
            const op = @as(OpCode, @enumFromInt(opcode));
            try serializeOperation(state, node_idx, op, writer);
        }
    }
    
    fn serializeConstant(
        state: *const InterpreterState,
        node_idx: NodeIndex,
        writer: anytype,
    ) !void {
        // Constant: type is encoded in opcode, serialize data
        const const_idx = state.expressions.getConstRef(node_idx);
        const type_idx = state.constants.getType(const_idx);
        const value_ref = state.constants.getValueRef(const_idx);
        
        try DataSerializer.serialize(state, type_idx, value_ref, writer);
    }
    
    fn serializeOperation(
        state: *const InterpreterState,
        node_idx: NodeIndex,
        op: OpCode,
        writer: anytype,
    ) !void {
        switch (op) {
            // Binary operations: left, right
            .plus, .minus, .multiply, .division, .modulo,
            .lt, .le, .gt, .ge, .eq, .neq,
            .bin_and, .bin_or, .bin_xor,
            .xor, .min, .max, .append => {
                const operands = state.expressions.getOperands(node_idx);
                std.debug.assert(operands.len == 2);
                try serialize(state, operands[0], writer);
                try serialize(state, operands[1], writer);
            },
            
            // Unary operations
            .logical_not, .negation, .size_of,
            .extract_amount, .extract_id,
            .calc_blake2b256, .calc_sha256 => {
                const operands = state.expressions.getOperands(node_idx);
                std.debug.assert(operands.len == 1);
                try serialize(state, operands[0], writer);
            },
            
            // If-then-else
            .@"if" => {
                const operands = state.expressions.getOperands(node_idx);
                std.debug.assert(operands.len == 3);
                try serialize(state, operands[0], writer); // condition
                try serialize(state, operands[1], writer); // trueBranch
                try serialize(state, operands[2], writer); // falseBranch
            },
            
            // Collection operations with variable operands
            .concrete_collection => {
                try serializeConcreteCollection(state, node_idx, writer);
            },
            
            // Method call
            .method_call => {
                try serializeMethodCall(state, node_idx, writer);
            },
            
            // Block value
            .block_value => {
                try serializeBlock(state, node_idx, writer);
            },
            
            // Function value (lambda)
            .func_value => {
                try serializeFuncValue(state, node_idx, writer);
            },
            
            else => return error.UnsupportedOpcode,
        }
    }
    
    fn serializeConcreteCollection(
        state: *const InterpreterState,
        node_idx: NodeIndex,
        writer: anytype,
    ) !void {
        // Format: numItems:VLQ, elemType:Type, items[]:Expr
        const coll_meta = state.expressions.getCollMeta(node_idx);
        
        try VLQ.encodeUnsigned(u16, coll_meta.num_items, writer);
        try TypeSerializer.serialize(&state.types, coll_meta.elem_type, writer);
        
        const operands = state.expressions.getOperands(node_idx);
        for (operands) |operand_idx| {
            try serialize(state, operand_idx, writer);
        }
    }
    
    /// Deserialize expression tree
    pub fn deserialize(
        state: *InterpreterState,
        reader: anytype,
    ) !NodeIndex {
        const opcode = try reader.readByte();
        
        if (OpCode.isConstant(opcode)) {
            return deserializeConstant(state, opcode, reader);
        } else {
            return deserializeOperation(state, @enumFromInt(opcode), reader);
        }
    }
};
```

TESTS:
[ ] Roundtrip simple expressions: 1 + 2
[ ] Roundtrip nested: (1 + 2) * 3
[ ] Roundtrip if-then-else
[ ] Roundtrip collections
[ ] Roundtrip blocks with val definitions
[ ] Roundtrip lambdas
```

### Prompt 2.4: ErgoTree Container Serialization

```
TASK: Implement top-level ErgoTree serialization with header parsing

CONTEXT (From Ergo Core Developers):
"ErgoTree has a header byte that controls interpretation:
- Bits 0-2: Version (currently 0)
- Bit 3: Size included after header
- Bit 4: Constant segregation enabled
- Bits 5-7: Reserved

Constant segregation is the key optimization. It separates constants
from the tree structure so they can be substituted without reparsing.
Most mainnet scripts use constant segregation."

PREREQUISITE KNOWLEDGE:
- Header is 1+ bytes (VLQ if bit 7 set)
- Optional size field (u32 VLQ) if bit 3 set
- Constants array if bit 4 set
- Root expression follows
- See ErgoTree Spec Section 5.5 and Figure 12

CREATE FILE: src/serialization/ergotree_serializer.zig

IMPLEMENTATION:
```zig
pub const ErgoTreeHeader = struct {
    version: u3,
    has_size: bool,
    constant_segregation: bool,
    reserved_5: bool,
    reserved_6: bool,
    has_more: bool,
    
    pub fn fromByte(b: u8) ErgoTreeHeader {
        return .{
            .version = @truncate(b & 0x07),
            .has_size = (b & 0x08) != 0,
            .constant_segregation = (b & 0x10) != 0,
            .reserved_5 = (b & 0x20) != 0,
            .reserved_6 = (b & 0x40) != 0,
            .has_more = (b & 0x80) != 0,
        };
    }
    
    pub fn toByte(self: ErgoTreeHeader) u8 {
        var b: u8 = self.version;
        if (self.has_size) b |= 0x08;
        if (self.constant_segregation) b |= 0x10;
        if (self.reserved_5) b |= 0x20;
        if (self.reserved_6) b |= 0x40;
        if (self.has_more) b |= 0x80;
        return b;
    }
};

pub const ErgoTreeSerializer = struct {
    
    /// Deserialize ErgoTree from bytes
    pub fn deserialize(state: *InterpreterState, bytes: []const u8) !void {
        var fbs = std.io.fixedBufferStream(bytes);
        const reader = fbs.reader();
        
        // 1. Parse header
        const header_byte = try reader.readByte();
        const header = ErgoTreeHeader.fromByte(header_byte);
        
        // Validate version
        if (header.version > protocol.max_supported) {
            return error.UnsupportedVersion;
        }
        if (header.has_more) {
            return error.ExtendedHeaderNotSupported;
        }
        if (header.reserved_5 or header.reserved_6) {
            return error.ReservedBitsSet;
        }
        
        // 2. Parse size (if present)
        var remaining_size: ?usize = null;
        if (header.has_size) {
            remaining_size = try VLQ.decodeUnsigned(u32, reader);
            // Validate against actual remaining bytes
            const actual_remaining = bytes.len - fbs.pos;
            if (remaining_size.? != actual_remaining) {
                return error.SizeMismatch;
            }
        }
        
        // 3. Parse constants (if segregated)
        if (header.constant_segregation) {
            const num_constants = try VLQ.decodeUnsigned(u32, reader);
            
            // Validate capacity BEFORE parsing
            if (num_constants > Capacity.max_constants) {
                return error.TooManyConstants;
            }
            
            for (0..num_constants) |_| {
                // Each constant: type + data
                const type_idx = try TypeSerializer.deserialize(&state.types, reader);
                const value_ref = try DataSerializer.deserialize(state, type_idx, reader);
                try state.constants.add(type_idx, value_ref);
            }
        }
        
        // 4. Parse root expression
        state.root = try ExprSerializer.deserialize(state, reader);
        
        // 5. Verify all bytes consumed
        if (fbs.pos != bytes.len) {
            return error.TrailingBytes;
        }
    }
    
    /// Serialize ErgoTree to bytes
    pub fn serialize(state: *const InterpreterState, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();
        
        // Determine header flags
        const use_segregation = state.constants.count() > 0;
        const header = ErgoTreeHeader{
            .version = protocol.current,
            .has_size = true,  // Always include size for safety
            .constant_segregation = use_segregation,
            .reserved_5 = false,
            .reserved_6 = false,
            .has_more = false,
        };
        
        // Write header
        try writer.writeByte(header.toByte());
        
        // Placeholder for size (will backpatch)
        const size_pos = fbs.pos;
        try writer.writeAll(&[_]u8{0} ** 5);  // Max VLQ size
        
        const content_start = fbs.pos;
        
        // Write constants if segregated
        if (use_segregation) {
            try VLQ.encodeUnsigned(u32, state.constants.count(), writer);
            for (0..state.constants.count()) |i| {
                const const_idx = @as(ConstIndex, @intCast(i));
                const type_idx = state.constants.getType(const_idx);
                const value_ref = state.constants.getValueRef(const_idx);
                
                try TypeSerializer.serialize(&state.types, type_idx, writer);
                try DataSerializer.serialize(state, type_idx, value_ref, writer);
            }
        }
        
        // Write root expression
        try ExprSerializer.serialize(state, state.root, writer);
        
        // Backpatch size
        const content_size = fbs.pos - content_start;
        var size_buf: [5]u8 = undefined;
        var size_fbs = std.io.fixedBufferStream(&size_buf);
        const size_len = try VLQ.encodeUnsigned(u32, @intCast(content_size), size_fbs.writer());
        @memcpy(buffer[size_pos..][0..size_len], size_buf[0..size_len]);
        
        // Shift content if size encoding was shorter than placeholder
        if (size_len < 5) {
            const shift = 5 - size_len;
            std.mem.copyBackwards(
                u8,
                buffer[size_pos + size_len..],
                buffer[size_pos + 5..fbs.pos],
            );
            return buffer[0..fbs.pos - shift];
        }
        
        return buffer[0..fbs.pos];
    }
};
```

TESTS:
[ ] Parse header correctly
[ ] Reject unsupported version
[ ] Parse without constant segregation
[ ] Parse with constant segregation
[ ] Roundtrip test
[ ] Error on trailing bytes
[ ] Error on size mismatch
```

---
