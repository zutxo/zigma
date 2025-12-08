
## Phase 3: Core Interpreter

### Prompt 3.1: Execution Context

```
TASK: Implement blockchain execution context

CONTEXT (From Production Node Operators):
"The context is everything the script can access:
- INPUTS: boxes being spent
- OUTPUTS: boxes being created
- HEIGHT: current block height
- SELF: the box containing this script
- dataInputs: read-only reference boxes
- headers: last N block headers
- preHeader: current block header (partial)

Context is READ-ONLY during execution. Any mutation is a bug.
Context should be validated BEFORE execution starts."

PREREQUISITE KNOWLEDGE:
- Context provides the "environment" for script evaluation
- Box has registers R0-R9 (R0=value, R1=script, R2=tokens, R3=creationInfo)
- HEIGHT is block height where tx will be included
- Registers R4-R9 are user-defined
- See ErgoTree Spec Section A.12 (Context type)

CREATE FILE: src/interpreter/context.zig

IMPLEMENTATION:
```zig
/// Box register indices
pub const Register = enum(u4) {
    R0 = 0,  // Value (Long)
    R1 = 1,  // Script (Coll[Byte])
    R2 = 2,  // Tokens (Coll[(Coll[Byte], Long)])
    R3 = 3,  // CreationInfo ((Int, Coll[Byte]))
    R4 = 4,  // User-defined
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
};

/// Box representation (immutable view)
pub const BoxView = struct {
    /// Box ID (32 bytes Blake2b hash)
    id: [32]u8,
    /// Value in nanoERGs
    value: i64,
    /// ErgoTree bytes (proposition)
    proposition_bytes: []const u8,
    /// Creation height
    creation_height: u32,
    /// Transaction ID (32 bytes)
    tx_id: [32]u8,
    /// Output index in transaction
    index: u16,
    /// Tokens: (tokenId, amount) pairs
    tokens: []const struct { id: [32]u8, amount: i64 },
    /// Additional registers (R4-R9), serialized
    registers: [6]?[]const u8,
    
    pub fn getRegister(self: *const BoxView, reg: Register) ?[]const u8 {
        return switch (reg) {
            .R0 => null, // Value accessed via .value
            .R1 => self.proposition_bytes,
            .R2 => null, // Tokens accessed via .tokens
            .R3 => null, // Creation info computed
            else => self.registers[@intFromEnum(reg) - 4],
        };
    }
};

/// Block header view
pub const HeaderView = struct {
    id: [32]u8,
    version: u8,
    parent_id: [32]u8,
    ad_proofs_root: [32]u8,
    state_root: [44]u8,  // AvlTree digest
    transactions_root: [32]u8,
    timestamp: u64,
    n_bits: u64,
    height: u32,
    extension_root: [32]u8,
    miner_pk: [33]u8,
    pow_onetime_pk: [33]u8,
    pow_nonce: [8]u8,
    pow_distance: [32]u8,  // BigInt
    votes: [3]u8,
};

/// Pre-header (predictable parts of current block)
pub const PreHeaderView = struct {
    version: u8,
    parent_id: [32]u8,
    timestamp: u64,
    n_bits: u64,
    height: u32,
    miner_pk: [33]u8,
    votes: [3]u8,
};

/// Execution context (read-only)
pub const Context = struct {
    /// Input boxes being spent
    inputs: []const BoxView,
    /// Output boxes being created
    outputs: []const BoxView,
    /// Data input boxes (read-only references)
    data_inputs: []const BoxView,
    /// Index of SELF in inputs
    self_index: u16,
    /// Block height
    height: u32,
    /// Last N headers (newest first)
    headers: []const HeaderView,
    /// Pre-header for current block
    pre_header: PreHeaderView,
    /// Context variables (for executeFromVar)
    context_vars: [256]?[]const u8,
    /// Miner public key
    miner_pk: [33]u8,
    
    /// Get SELF box
    pub fn getSelf(self: *const Context) *const BoxView {
        return &self.inputs[self.self_index];
    }
    
    /// Get context variable
    pub fn getVar(self: *const Context, id: u8) ?[]const u8 {
        return self.context_vars[id];
    }
    
    /// Validate context consistency
    pub fn validate(self: *const Context) !void {
        // SELF index must be valid
        if (self.self_index >= self.inputs.len) {
            return error.InvalidSelfIndex;
        }
        
        // All input boxes must have valid structure
        for (self.inputs) |box| {
            if (box.value < 0) return error.NegativeBoxValue;
            if (box.proposition_bytes.len == 0) return error.EmptyProposition;
        }
        
        // Output values must not exceed input values (checked elsewhere)
        // Token conservation (checked elsewhere)
    }
};
```

TESTS:
[ ] Create context with valid data
[ ] Access SELF box
[ ] Access registers R4-R9
[ ] Access context variables
[ ] Validation catches invalid self_index
```

### Prompt 3.2: Value Representation

```
TASK: Implement runtime value representation

CONTEXT (From TigerBeetle Engineers):
"Values during evaluation need efficient representation:
1. Primitives: store directly (no indirection)
2. Collections: reference to pool
3. BigInt/GroupElement: reference to typed arena

Use tagged unions but be aware of size implications.
A 64-bit value + 8-bit tag = 9 bytes, but alignment makes it 16.
Consider separate arrays for tags and values."

PREREQUISITE KNOWLEDGE:
- Values are produced by expression evaluation
- Values can be pushed/popped on stack
- Values can be stored in collections
- Some values are lazy (functions, thunks)
- Values must support equality comparison

CREATE FILE: src/interpreter/values.zig

IMPLEMENTATION:
```zig
/// Value reference (index into value storage)
pub const ValueRef = struct {
    /// Slot in appropriate storage
    slot: u16,
    /// Type code for dispatch
    type_code: u8,
};

/// Runtime value representation
/// This is used for values that don't fit in the stack lanes
pub const Value = union(enum) {
    /// Unit value (singleton)
    unit: void,
    
    /// Boolean
    boolean: bool,
    
    /// Numeric values (stored inline)
    byte: i8,
    short: i16,
    int: i32,
    long: i64,
    
    /// BigInt (reference to arena)
    big_int: BigIntRef,
    
    /// GroupElement (reference to arena)
    group_element: GroupElementRef,
    
    /// SigmaProp (reference to sigma tree)
    sigma_prop: SigmaPropRef,
    
    /// Box (reference to context)
    box: BoxRef,
    
    /// Collection (reference to collection pool)
    collection: CollectionRef,
    
    /// Option (None or Some with inner value)
    option: ?ValueRef,
    
    /// Tuple (references to elements)
    tuple: TupleRef,
    
    /// Function (closure)
    function: FunctionRef,
    
    /// Compare two values for equality
    pub fn equals(self: Value, other: Value, state: *const InterpreterState) bool {
        if (@as(std.meta.Tag(Value), self) != @as(std.meta.Tag(Value), other)) {
            return false;
        }
        
        return switch (self) {
            .unit => true,
            .boolean => |b| b == other.boolean,
            .byte => |b| b == other.byte,
            .short => |s| s == other.short,
            .int => |i| i == other.int,
            .long => |l| l == other.long,
            .big_int => |bi| state.compareBigInt(bi, other.big_int),
            .group_element => |ge| state.compareGroupElement(ge, other.group_element),
            .collection => |c| state.compareCollection(c, other.collection),
            // ... other types
            else => false,
        };
    }
};

/// Reference types for heap-allocated values
pub const BigIntRef = u16;
pub const GroupElementRef = u16;
pub const SigmaPropRef = u16;
pub const BoxRef = struct { source: enum { input, output, data_input }, index: u16 };
pub const CollectionRef = u16;
pub const TupleRef = struct { start: u16, len: u8 };
pub const FunctionRef = u16;

/// Collection storage
pub const Collection = struct {
    /// Element type
    elem_type: TypeIndex,
    /// Number of elements
    len: u16,
    /// Start index in element storage
    first_elem: u32,
};

pub const CollectionPool = struct {
    /// Collection metadata
    collections: [Capacity.max_collections]Collection,
    /// Element references
    elements: [Capacity.max_collection_items]ValueRef,
    
    coll_count: u16,
    elem_count: u32,
    
    pub fn create(
        self: *CollectionPool,
        elem_type: TypeIndex,
        elements: []const ValueRef,
    ) !CollectionRef {
        if (self.coll_count >= Capacity.max_collections) {
            return error.PoolExhausted;
        }
        if (self.elem_count + elements.len > Capacity.max_collection_items) {
            return error.PoolExhausted;
        }
        
        const coll_idx = self.coll_count;
        self.collections[coll_idx] = .{
            .elem_type = elem_type,
            .len = @intCast(elements.len),
            .first_elem = self.elem_count,
        };
        
        @memcpy(
            self.elements[self.elem_count..][0..elements.len],
            elements,
        );
        
        self.coll_count += 1;
        self.elem_count += @intCast(elements.len);
        
        return coll_idx;
    }
    
    pub fn get(self: *const CollectionPool, ref: CollectionRef) Collection {
        return self.collections[ref];
    }
    
    pub fn getElements(self: *const CollectionPool, coll: Collection) []const ValueRef {
        return self.elements[coll.first_elem..][0..coll.len];
    }
};
```

TESTS:
[ ] Create values of each type
[ ] Value equality for primitives
[ ] Collection creation and access
[ ] Tuple creation and access
[ ] Pool exhaustion handling
```

### Prompt 3.3: Evaluation Loop

```
TASK: Implement main expression evaluation loop

CONTEXT (From TigerBeetle Engineers):
"The evaluation loop is the heart of the interpreter. Design for:
1. Iterative, not recursive (avoid stack overflow)
2. Cost checked BEFORE each operation
3. Deterministic (same inputs → same outputs always)
4. Assertions verify invariants continuously

Use an explicit work stack instead of recursion.
This gives you control over memory usage."

PREREQUISITE KNOWLEDGE:
- ErgoTree evaluation is call-by-value
- Expressions are evaluated depth-first
- Short-circuit evaluation for && and ||
- Lazy evaluation for if-then-else branches
- Functions are evaluated when applied
- See ErgoTree Spec Section 4

CREATE FILE: src/interpreter/evaluator.zig

IMPLEMENTATION:
```zig
pub const EvalError = error{
    CostLimitExceeded,
    StackOverflow,
    StackUnderflow,
    TypeMismatch,
    DivisionByZero,
    ArithmeticOverflow,
    IndexOutOfBounds,
    InvalidOpcode,
    AssertionFailed,
    BoxNotFound,
    RegisterNotFound,
};

/// Work item for iterative evaluation
const WorkItem = struct {
    node: NodeIndex,
    phase: enum {
        /// Evaluate this node (may push children)
        evaluate,
        /// All children evaluated, compute result
        compute,
    },
    /// For binary ops, tracks which operands are done
    operands_done: u8,
};

/// Main evaluator
pub const Evaluator = struct {
    state: *InterpreterState,
    context: *const Context,
    
    /// Work stack for iterative evaluation
    work_stack: [Capacity.max_stack]WorkItem,
    work_sp: u16,
    
    pub fn init(state: *InterpreterState, context: *const Context) Evaluator {
        return .{
            .state = state,
            .context = context,
            .work_stack = undefined,
            .work_sp = 0,
        };
    }
    
    /// Evaluate root expression to a value
    pub fn evaluate(self: *Evaluator) EvalError!ValueRef {
        // Push root node
        try self.pushWork(.{ .node = self.state.root, .phase = .evaluate, .operands_done = 0 });
        
        // Main evaluation loop
        while (self.work_sp > 0) {
            const work = self.popWork();
            
            switch (work.phase) {
                .evaluate => try self.evaluateNode(work),
                .compute => try self.computeNode(work),
            }
        }
        
        // Result is on value stack
        const result = try self.state.stack.peek();
        return .{ .slot = result.slot, .type_code = result.type_code };
    }
    
    fn evaluateNode(self: *Evaluator, work: WorkItem) EvalError!void {
        const opcode = self.state.expressions.getOpcode(work.node);
        
        // Check cost BEFORE evaluation
        const cost = opcodes.CostModel.getCost(@enumFromInt(opcode));
        try self.state.addCost(cost);
        
        if (opcodes.OpCode.isConstant(opcode)) {
            // Constants: push value directly
            try self.pushConstant(work.node);
        } else {
            const op = @as(opcodes.OpCode, @enumFromInt(opcode));
            try self.evaluateOperation(work, op);
        }
    }
    
    fn evaluateOperation(self: *Evaluator, work: WorkItem, op: opcodes.OpCode) EvalError!void {
        switch (op) {
            // Nullary operations
            .height => {
                try self.state.stack.pushInt(self.context.height, @intFromEnum(PrimType.int));
            },
            .self_box => {
                const self_box = self.context.getSelf();
                try self.state.stack.pushRef(
                    @intCast(self.context.self_index),
                    @intFromEnum(PredefType.box),
                );
            },
            .inputs => {
                // Create collection of input boxes
                try self.pushInputsCollection();
            },
            .outputs => {
                try self.pushOutputsCollection();
            },
            
            // Binary operations: evaluate children first
            .plus, .minus, .multiply, .division, .modulo,
            .lt, .le, .gt, .ge, .eq, .neq,
            .min, .max => {
                const operands = self.state.expressions.getOperands(work.node);
                std.debug.assert(operands.len == 2);
                
                // Push compute phase (will run after operands)
                try self.pushWork(.{ .node = work.node, .phase = .compute, .operands_done = 0 });
                // Push operands (right first, so left is evaluated first)
                try self.pushWork(.{ .node = operands[1], .phase = .evaluate, .operands_done = 0 });
                try self.pushWork(.{ .node = operands[0], .phase = .evaluate, .operands_done = 0 });
            },
            
            // Short-circuit AND
            .bin_and => {
                const operands = self.state.expressions.getOperands(work.node);
                // Push compute phase
                try self.pushWork(.{ .node = work.node, .phase = .compute, .operands_done = 0 });
                // Evaluate left operand first
                try self.pushWork(.{ .node = operands[0], .phase = .evaluate, .operands_done = 0 });
            },
            
            // If-then-else (lazy branches)
            .@"if" => {
                const operands = self.state.expressions.getOperands(work.node);
                // Push compute phase
                try self.pushWork(.{ .node = work.node, .phase = .compute, .operands_done = 0 });
                // Evaluate condition first
                try self.pushWork(.{ .node = operands[0], .phase = .evaluate, .operands_done = 0 });
            },
            
            else => return EvalError.InvalidOpcode,
        }
    }
    
    fn computeNode(self: *Evaluator, work: WorkItem) EvalError!void {
        const opcode = self.state.expressions.getOpcode(work.node);
        const op = @as(opcodes.OpCode, @enumFromInt(opcode));
        
        switch (op) {
            .plus => try self.computeAdd(),
            .minus => try self.computeSub(),
            .multiply => try self.computeMul(),
            .division => try self.computeDiv(),
            .modulo => try self.computeMod(),
            .lt => try self.computeLt(),
            .le => try self.computeLe(),
            .gt => try self.computeGt(),
            .ge => try self.computeGe(),
            .eq => try self.computeEq(),
            .neq => try self.computeNeq(),
            .bin_and => try self.computeAnd(work),
            .bin_or => try self.computeOr(work),
            .@"if" => try self.computeIf(work),
            else => return EvalError.InvalidOpcode,
        }
    }
    
    // Arithmetic implementations with overflow checking
    fn computeAdd(self: *Evaluator) EvalError!void {
        const b = try self.state.stack.pop();
        const a = try self.state.stack.pop();
        
        if (a.type_code != b.type_code) return EvalError.TypeMismatch;
        
        const a_val = self.state.stack.getInt(a.slot);
        const b_val = self.state.stack.getInt(b.slot);
        
        const result = switch (a.type_code) {
            @intFromEnum(PrimType.byte) => blk: {
                const av: i8 = @truncate(a_val);
                const bv: i8 = @truncate(b_val);
                if (@addWithOverflow(av, bv)[1] != 0) return EvalError.ArithmeticOverflow;
                break :blk @as(i64, av +% bv);
            },
            @intFromEnum(PrimType.short) => blk: {
                const av: i16 = @truncate(a_val);
                const bv: i16 = @truncate(b_val);
                if (@addWithOverflow(av, bv)[1] != 0) return EvalError.ArithmeticOverflow;
                break :blk @as(i64, av +% bv);
            },
            @intFromEnum(PrimType.int) => blk: {
                const av: i32 = @truncate(a_val);
                const bv: i32 = @truncate(b_val);
                if (@addWithOverflow(av, bv)[1] != 0) return EvalError.ArithmeticOverflow;
                break :blk @as(i64, av +% bv);
            },
            @intFromEnum(PrimType.long) => blk: {
                if (@addWithOverflow(a_val, b_val)[1] != 0) return EvalError.ArithmeticOverflow;
                break :blk a_val +% b_val;
            },
            else => return EvalError.TypeMismatch,
        };
        
        try self.state.stack.pushInt(result, a.type_code);
    }
    
    fn computeDiv(self: *Evaluator) EvalError!void {
        const b = try self.state.stack.pop();
        const a = try self.state.stack.pop();
        
        const b_val = self.state.stack.getInt(b.slot);
        if (b_val == 0) return EvalError.DivisionByZero;
        
        const a_val = self.state.stack.getInt(a.slot);
        
        // Note: Ergo uses truncated division (rounds toward zero)
        const result = @divTrunc(a_val, b_val);
        try self.state.stack.pushInt(result, a.type_code);
    }
    
    fn computeIf(self: *Evaluator, work: WorkItem) EvalError!void {
        const operands = self.state.expressions.getOperands(work.node);
        
        // Condition is on stack
        const cond = try self.state.stack.pop();
        const cond_val = self.state.stack.getBool(cond.slot);
        
        // Evaluate only the taken branch (lazy)
        if (cond_val) {
            try self.pushWork(.{ .node = operands[1], .phase = .evaluate, .operands_done = 0 });
        } else {
            try self.pushWork(.{ .node = operands[2], .phase = .evaluate, .operands_done = 0 });
        }
    }
    
    // Helper methods
    fn pushWork(self: *Evaluator, item: WorkItem) EvalError!void {
        if (self.work_sp >= Capacity.max_stack) return EvalError.StackOverflow;
        self.work_stack[self.work_sp] = item;
        self.work_sp += 1;
    }
    
    fn popWork(self: *Evaluator) WorkItem {
        std.debug.assert(self.work_sp > 0);
        self.work_sp -= 1;
        return self.work_stack[self.work_sp];
    }
};
```

TESTS:
[ ] Evaluate constant
[ ] Evaluate 1 + 2 = 3
[ ] Evaluate nested: (1 + 2) * 3 = 9
[ ] Division by zero error
[ ] Overflow detection
[ ] Short-circuit && (false && X doesn't evaluate X)
[ ] If-then-else only evaluates taken branch
[ ] Cost accumulation
[ ] Cost limit exceeded error
```

### Prompt 3.4: Cost Accounting

```
TASK: Implement precise cost accounting matching Scala implementation

CONTEXT (From Ergo Core Developers):
"Cost accounting changed significantly between v4 and v5. 
v5 introduced JIT costing which is more precise but complex.

For initial implementation, use v4 costing model from CostTable.scala.
You can upgrade to v5 (JitCost.scala) later.

Key insight: some costs are fixed, some depend on data size.
Collection.fold costs = base + (perItem * collection.length)"

PREREQUISITE KNOWLEDGE:
- Cost is measured in abstract "cost units"
- Maximum cost per script is protocol parameter
- Costs must match reference implementation exactly
- Costs may vary by protocol version
- See sigmastate.eval.CostTable

CREATE FILE: src/interpreter/cost.zig

IMPLEMENTATION:
```zig
/// Cost model version
pub const CostVersion = enum {
    v4,  // Original costing
    v5,  // JIT costing (more precise)
};

/// Fixed costs for operations (v4 model)
pub const FixedCost = struct {
    // Comparison
    pub const lt: u32 = 36;
    pub const le: u32 = 36;
    pub const gt: u32 = 36;
    pub const ge: u32 = 36;
    pub const eq: u32 = 36;
    pub const neq: u32 = 36;
    
    // Arithmetic
    pub const plus: u32 = 36;
    pub const minus: u32 = 36;
    pub const multiply: u32 = 36;
    pub const division: u32 = 36;
    pub const modulo: u32 = 36;
    pub const negation: u32 = 30;
    
    // Logical
    pub const and_op: u32 = 20;  // Per item
    pub const or_op: u32 = 20;   // Per item
    pub const logical_not: u32 = 30;
    pub const bin_and: u32 = 36;
    pub const bin_or: u32 = 36;
    
    // Collections
    pub const size_of: u32 = 14;
    pub const by_index: u32 = 30;
    pub const slice: u32 = 30;  // Plus per-item
    pub const append: u32 = 30; // Plus per-item
    
    // Box operations
    pub const extract_amount: u32 = 12;
    pub const extract_script_bytes: u32 = 12;
    pub const extract_bytes: u32 = 12;
    pub const extract_id: u32 = 12;
    pub const extract_register: u32 = 50;
    
    // Crypto
    pub const blake2b256: u32 = 4200;
    pub const sha256: u32 = 4200;
    pub const decode_point: u32 = 4500;
    pub const exponentiate: u32 = 6500;
    pub const multiply_group: u32 = 3500;
    pub const prove_dlog: u32 = 45000;
    pub const prove_dh_tuple: u32 = 85000;
    
    // Context
    pub const height: u32 = 5;
    pub const inputs: u32 = 10;
    pub const outputs: u32 = 10;
    pub const self_box: u32 = 10;
    pub const get_var: u32 = 30;
};

/// Per-item costs for collection operations
pub const PerItemCost = struct {
    pub const fold: u32 = 10;
    pub const map: u32 = 10;
    pub const filter: u32 = 10;
    pub const exists: u32 = 10;
    pub const forall: u32 = 10;
    pub const slice: u32 = 2;
    pub const append: u32 = 2;
    pub const and_op: u32 = 20;
    pub const or_op: u32 = 20;
};

/// Type-dependent costs
pub const TypeCost = struct {
    /// BigInt operations cost more
    pub fn arithmeticMultiplier(type_code: u8) u32 {
        return if (type_code == @intFromEnum(PrimType.big_int)) 10 else 1;
    }
    
    /// Collection element comparison cost
    pub fn comparisonCost(type_code: u8) u32 {
        return switch (type_code) {
            @intFromEnum(PrimType.big_int) => 100,
            @intFromEnum(PrimType.group_element) => 200,
            else => 10,
        };
    }
};

/// Cost calculator
pub const CostCalculator = struct {
    version: CostVersion,
    accumulated: u64,
    limit: u64,
    
    pub fn init(limit: u64, version: CostVersion) CostCalculator {
        return .{
            .version = version,
            .accumulated = 0,
            .limit = limit,
        };
    }
    
    /// Add fixed cost
    pub fn addFixed(self: *CostCalculator, cost: u32) !void {
        const new_cost = self.accumulated +| cost;
        if (new_cost > self.limit) return error.CostLimitExceeded;
        self.accumulated = new_cost;
    }
    
    /// Add size-dependent cost
    pub fn addPerItem(self: *CostCalculator, base: u32, per_item: u32, count: usize) !void {
        const total = @as(u64, base) + @as(u64, per_item) * @as(u64, count);
        const new_cost = self.accumulated +| total;
        if (new_cost > self.limit) return error.CostLimitExceeded;
        self.accumulated = new_cost;
    }
    
    /// Get cost for opcode
    pub fn getOpCost(self: *const CostCalculator, op: opcodes.OpCode) u32 {
        _ = self;
        return switch (op) {
            .plus => FixedCost.plus,
            .minus => FixedCost.minus,
            .multiply => FixedCost.multiply,
            .division => FixedCost.division,
            .modulo => FixedCost.modulo,
            .lt => FixedCost.lt,
            .le => FixedCost.le,
            .gt => FixedCost.gt,
            .ge => FixedCost.ge,
            .eq => FixedCost.eq,
            .neq => FixedCost.neq,
            .calc_blake2b256 => FixedCost.blake2b256,
            .calc_sha256 => FixedCost.sha256,
            .exponentiate => FixedCost.exponentiate,
            .multiply_group => FixedCost.multiply_group,
            else => 10, // Default
        };
    }
};
```

VALIDATION:
[ ] Compare costs against CostTable.scala for each operation
[ ] Test cost accumulation
[ ] Test limit enforcement
[ ] Verify overflow safety
```

---
