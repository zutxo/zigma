● I'll help you identify all the files needed to understand the JIT costing mechanism in the sigmastate interpreter. Let me launch explore agents to thoroughly investigate this.

● 3 Explore agents finished (ctrl+o to expand)
   ├─ Find JIT costing files · 53 tool uses · 80.2k tokens
   │  ⎿  Done
   ├─ Explore zigma codebase · 32 tool uses · 65.6k tokens
   │  ⎿  Done
   └─ Locate sigmastate repo · 41 tool uses · 45.4k tokens
      ⎿  Done

● I've completed a thorough exploration. Here's the comprehensive list of files you need to review to fully understand the JIT costing mechanism:

  Complete File List for JIT Costing Mechanism

  Core Cost Abstractions (CRITICAL - Read First)

  | File                                                                                            | Lines | Purpose                                                 |
  |-------------------------------------------------------------------------------------------------|-------|---------------------------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/JitCost.scala       | ~50   | JitCost value type (10x scale), arithmetic ops          |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/CostKind.scala      | ~150  | FixedCost, PerItemCost, TypeBasedCost, DynamicCost      |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/CostItem.scala      | ~100  | FixedCostItem, TypeBasedCostItem, SeqCostItem           |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/OperationDesc.scala | ~80   | CompanionDesc, MethodDesc, NamedDesc, OperationCostInfo |

  Cost Accumulation & Evaluation Engine (CRITICAL)

  | File                                                                                                                     | Lines | Purpose                                                       |
  |--------------------------------------------------------------------------------------------------------------------------|-------|---------------------------------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/interpreter/CostAccumulator.scala    | ~150  | CostCounter, CostAccumulator, Scope stack FSM                 |
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/interpreter/CErgoTreeEvaluator.scala | ~1000 | Main JIT interpreter with all cost methods                    |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/eval/ErgoTreeEvaluator.scala                     | ~200  | Abstract evaluator interface (addSeqCost, addFixedCost, etc.) |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/eval/CostDetails.scala                           | ~100  | TracedCost, GivenCost result types                            |

  Operation & Method Cost Tables (CRITICAL)

  | File                                                                                           | Lines | Purpose                                                |
  |------------------------------------------------------------------------------------------------|-------|--------------------------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/methods.scala      | ~2000 | ALL method cost definitions (50+ methods)              |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/trees.scala        | ~2500 | ALL operation node costs (100+ ops)                    |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/transformers.scala | ~800  | Collection transformer costs (Map, Filter, Fold, etc.) |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/SMethod.scala      | ~500  | SMethod with costKind and costFunc fields              |

  Profiling Infrastructure

  | File                                                                                                     | Lines | Purpose                               |
  |----------------------------------------------------------------------------------------------------------|-------|---------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/eval/Profiler.scala              | ~50   | Abstract Profiler interface           |
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/eval/CProfiler.scala | ~300  | Concrete profiler with StatCollection |

  Configuration & Settings

  | File                                                                                                     | Lines | Purpose                                            |
  |----------------------------------------------------------------------------------------------------------|-------|----------------------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/eval/EvalSettings.scala          | ~50   | EvalSettings (cost limits, modes, profiler config) |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/exceptions/SigmaExceptions.scala | ~100  | CostLimitException                                 |

  Interpreter Integration

  | File                                                                                                                     | Lines | Purpose                            |
  |--------------------------------------------------------------------------------------------------------------------------|-------|------------------------------------|
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/interpreter/Interpreter.scala        | ~400  | Base interpreter with evalSettings |
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/interpreter/InterpreterContext.scala | ~150  | Context with cost state            |

  Supporting Files

  | File                                                                                                      | Lines | Purpose                    |
  |-----------------------------------------------------------------------------------------------------------|-------|----------------------------|
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/values.scala                  | ~1500 | Value nodes with cost info |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/ast/Operations.scala              | ~800  | Generated operation info   |
  | /home/mark/ergo/sigmastate-interpreter/data/shared/src/main/scala/sigma/serialization/OpCodes.scala       | ~300  | OpCode definitions         |
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/main/scala/sigmastate/eval/Extensions.scala | ~200  | addCostChecked helper      |

  Tests & Benchmarks

  | File                                                                                                           | Purpose            |
  |----------------------------------------------------------------------------------------------------------------|--------------------|
  | /home/mark/ergo/sigmastate-interpreter/interpreter/shared/src/test/scala/sigmastate/JitCostSpecification.scala | JitCost unit tests |
  | /home/mark/ergo/sigmastate-interpreter/sc/jvm/src/test/scala/sigmastate/ErgoTreeBenchmarks.scala               | JMH benchmarks     |

  Your Zigma Implementation (Reference)

  | File                                                      | Lines | Purpose                                 |
  |-----------------------------------------------------------|-------|-----------------------------------------|
  | /home/mark/orgs/zutxo/zigma/src/interpreter/evaluator.zig | 7962  | Current JIT cost tables (lines 220-380) |
  | /home/mark/orgs/zutxo/zigma/src/core/opcodes.zig          | 531   | OpInfo with cost fields                 |
  | /home/mark/orgs/zutxo/zigma/docs/INTERPRETER_DESIGN.md    | -     | Architecture documentation              |

  ---
  Reading Order Recommendation

  1. JitCost.scala → Understand the cost value type (10x scale)
  2. CostKind.scala → Understand FixedCost, PerItemCost, TypeBasedCost
  3. CostAccumulator.scala → Understand scope-based cost tracking FSM
  4. ErgoTreeEvaluator.scala (abstract) → Understand the interface
  5. CErgoTreeEvaluator.scala → The main implementation
  6. methods.scala → All method costs (this is huge, ~2000 lines)
  7. trees.scala → All operation node costs

  Shall I start reading the critical files to begin drafting the formal specification?
  
  ===
  
   Of course. Breaking down large files is a common step to improve maintainability. Let's explore how evaluator.zig could be refactored, keeping idiomatic Zig, Data-Oriented
    Programming, and Tigerstyle conventions in mind.
  
    The existing evaluator.zig file is very large and contains several distinct logical components. Splitting it up can improve readability and separation of concerns.
  
    Analysis of evaluator.zig
  
    The file can be broken down into these main parts:
     1. Core Data Structures & Errors: EvalError, WorkItem, WorkPhase.
     2. Cost Model: A large, self-contained system for calculating operation costs (CostOp, JIT_COSTS, PerItemCost, etc.).
     3. Value Utilities: The pooledValueToValue function.
     4. The `Evaluator` struct: The central state for the evaluation process.
     5. Core Evaluation Logic: The main evaluate() loop and the evaluateNode/computeNode dispatch functions.
     6. Operation Implementations: A large number of compute... helper functions that implement the logic for each ExprTag (e.g., computeHash, computeBinOp, computeOptionGet).
     7. Debugging Utilities: The StateSnapshot struct and its methods.
  
    Proposed Refactoring Strategy
  
    A good approach is to group these components into new files within a new src/interpreter/evaluator/ directory. This makes the evaluator a distinct module within the interpreter.
  
    Here is a recommended way to split the file:
  
    1. Create a new directory:
    src/interpreter/evaluator/
  
    2. Move distinct components into their own files:
  
     * `src/interpreter/evaluator/cost.zig`: The entire cost model is a perfect candidate for extraction. It's a pure, self-contained utility.
         * CostOp
         * JIT_COSTS, AOT_COSTS
         * getCost, FixedCost
         * PerItemCost, CollectionCost, AvlTreeCost, HashCost
  
     * `src/interpreter/evaluator/error.zig`: The EvalError set can live here. As the evaluator is split, this error set will be needed by multiple files.
         * EvalError
  
     * `src/interpreter/evaluator/ops.zig`: This is the most significant change. The large computeNode function and the many compute<OpName> helper functions can be moved here. These
       functions all operate on the *Evaluator state.
         * computeNode
         * computeBinOp
         * computeHash
         * computeOptionGet
         * ... and all other operation implementation functions.
         * This file would import error.zig and cost.zig and contain the bulk of the logic.
  
     * `src/interpreter/evaluator/main.zig` (or `mod.zig`): The original evaluator.zig would be trimmed down to this main file, which defines the core Evaluator struct and the main
       evaluation loop.
         * WorkItem, WorkPhase (or they could go into a types.zig)
         * Evaluator struct definition.
         * init, initWithVersion, setCostLimit, setDeadline.
         * The main evaluate() loop.
         * evaluateNode() (which would remain the primary dispatcher for the first phase).
         * The various stack and utility helpers (pushWork, popValue, findSubtreeEnd, etc.).
         * This file would @import("ops.zig") and call ops.computeNode(...).
  
    3. The new file structure would look like this:
  
     1 src/interpreter/
     2 ├── evaluator/
     3 │   ├── main.zig      # Defines Evaluator struct and the main `evaluate` loop
     4 │   ├── ops.zig       # Implements all the `compute...` functions
     5 │   ├── cost.zig      # The cost model
     6 │   └── error.zig     # The EvalError set
     7 └── ...
    The original src/interpreter/evaluator.zig would be removed.
  
    Is This Best Practice?
  
    Yes, for a file of this size and complexity, this refactoring is a best practice. Here’s why:
  
     * Separation of Concerns: The cost model is a different concern from cryptographic operations or the main evaluation loop. Separating them makes the codebase easier to reason about.
     * Readability & Maintainability: When a developer needs to fix a bug in a specific operation (e.g., Fold), they can go directly to ops.zig instead of searching through a monolithic
       file. This significantly reduces cognitive load.
     * Adherence to "Tigerstyle": While Tigerstyle and data-oriented design can lead to large, cohesive files, a 2000+ line file with dozens of distinct operations stretches the
       definition of "cohesive". The Evaluator struct is the cohesive data structure, but the operations (ops.zig) and the cost model (cost.zig) are distinct systems that operate on that
       data. This split aligns well with data-oriented principles by separating the data (main.zig) from the transformations (ops.zig).
     * Scalability: If more operations are added to the language, they can be added to ops.zig without making the core main.zig file more complex.
  
    The primary trade-off is a small amount of indirection (having to look in ops.zig for implementations), but the benefits in clarity and maintainability for a file of this scale are
    substantial. This refactoring makes the evaluator module more organized and approachable.
  
  > write a complete an actionable plan and specification document for the refactoring of the evaluator.zig file.
  
  ✦ Here is a complete and actionable plan for the refactoring of the evaluator.zig file.
  
    Refactoring Specification: `evaluator.zig`
  
    1. Objective
  
    The primary goal of this refactoring is to improve the maintainability, readability, and modularity of the ErgoTree expression evaluator. The current implementation in
    src/interpreter/evaluator.zig is monolithic, making it difficult to navigate and maintain.
  
    This refactoring will decompose the evaluator into a collection of smaller, more focused files, adhering to the principle of Separation of Concerns. This will align the code with best
    practices for managing large-scale Zig projects, making future development and debugging more efficient.
  
    2. Current State Analysis
  
     * Single File Architecture: All evaluator logic, including state management, cost accounting, operation implementations, error definitions, and debugging utilities, is contained
       within the single src/interpreter/evaluator.zig file, which exceeds 1,500 lines.
     * Low Cohesion of Concerns: While the functions are all related to evaluation, concerns like cost calculation are distinct systems that can and should be isolated.
     * High Cognitive Load: Navigating and understanding the complete evaluation flow requires processing the entire file, making it difficult for developers to focus on specific
       components.
  
    3. Proposed Architecture
  
    I will create a new evaluator module located at src/interpreter/evaluator/. The monolithic file will be broken down as follows:
  
     * `src/interpreter/evaluator/`: A new directory to house the evaluator module.
         * `main.zig`: This will become the core of the evaluator. It will define the Evaluator struct, the main evaluate() loop, the evaluateNode dispatcher, and stack/state management
           helpers. It will represent the "data" and state machine of the evaluator.
         * `ops.zig`: This file will contain the implementations for the "compute" phase of evaluation. It will house the computeNode function and all the compute<OpName>() helper
           functions it calls.
         * `cost.zig`: This file will fully encapsulate the cost model, including cost tables (JIT_COSTS, AOT_COSTS), CostOp enum, and helper functions like getCost.
         * `error.zig`: This will define the public EvalError set, which can be imported by other files in the module.
         * `types.zig`: This will contain shared data structures used across the module, such as WorkItem, WorkPhase, and HashAlgorithm.
         * `debug.zig`: This will isolate the StateSnapshot struct and its associated functions, separating debugging concerns from the core logic.
  
    The original src/interpreter/evaluator.zig will be removed and replaced by this new modular structure.
  
    4. API Specification
  
    The public interface for each new file will be as follows:
  
     * `error.zig`:
     1     pub const EvalError = error{...};
  
     * `types.zig`:
  
     1     pub const WorkPhase = enum(u8) {...};
     2     pub const WorkItem = struct {...};
     3     pub const HashAlgorithm = enum { blake2b256, sha256 };
  
     * `cost.zig`:
  
     1     pub const CostOp = enum(u8) {...};
     2     pub const FixedCost = struct {...};
     3     pub const PerItemCost = struct {...};
     4     // ... other cost-related structs and constants
     5     pub fn getCost(version_ctx: VersionContext, op: CostOp) u32;
  
     * `debug.zig`:
  
     1     pub const StateSnapshot = struct {
     2         pub fn fromEvaluator(eval: *const @import("main.zig").Evaluator) StateSnapshot;
     3         pub fn verifyChecksum(self: *const StateSnapshot) bool;
     4         // ... other pub methods
     5     };
  
     * `ops.zig`:
  
     1     // Forward-declaration of Evaluator may be needed if there are circular dependencies
     2     const Evaluator = @import("main.zig").Evaluator;
     3     const EvalError = @import("error.zig").EvalError;
     4
     5     pub fn computeNode(eval: *Evaluator, node_idx: u16) EvalError!void;
  
     * `main.zig`:
  
      1     pub const Evaluator = struct {
      2         // ... fields
      3
      4         pub fn init(tree: *const ExprTree, ctx: *const Context) Evaluator;
      5         pub fn initWithVersion(...) Evaluator;
      6         pub fn setCostLimit(self: *Evaluator, limit: u64) void;
      7         pub fn setDeadline(self: *Evaluator, timeout_ms: u64) void;
      8         pub fn evaluate(self: *Evaluator) !Value;
      9         pub fn snapshot(self: *const Evaluator) @import("debug.zig").StateSnapshot;
     10     };
  
    5. Actionable Plan
  
    I will perform the refactoring in the following sequence to ensure a safe and verifiable transition:
  
     1. Directory and File Creation:
         * Create the new directory: mkdir -p src/interpreter/evaluator.
         * Create the empty files: touch src/interpreter/evaluator/{main,ops,cost,error,types,debug}.zig.
     2. Move and Rename:
         * Move the existing src/interpreter/evaluator.zig to src/interpreter/evaluator/main.zig.
     3. Component Extraction:
         * Sequentially cut the logic for each component (EvalError, WorkItem, Cost Model, StateSnapshot) from main.zig and paste it into the corresponding new file (error.zig, types.zig,
           cost.zig, debug.zig).
         * Update main.zig and other files to use @import() to access the moved types and functions, qualifying names where necessary (e.g., cost.getCost).
     4. Isolate Operation Logic:
         * Cut the computeNode function and all its compute<OpName>() helper functions from main.zig.
         * Paste these functions into ops.zig.
         * Refactor the pasted functions: change their signatures to accept eval: *Evaluator as the first parameter instead of being methods.
         * Update all internal calls within ops.zig from self.method() to eval.method().
         * In main.zig, modify the now-empty computeNode method to be a simple dispatcher: return @import("ops.zig").computeNode(self, node_idx);.
     5. Build System Integration:
         * I will analyze build.zig to understand how modules are defined.
         * I will modify build.zig to replace the reference to the old evaluator.zig with a new module pointing to src/interpreter/evaluator/main.zig.
     6. Finalization:
         * Review all new files to ensure correct imports and remove unused ones.
         * Run zig fmt on the entire src/interpreter/evaluator/ directory.
  
    6. Validation
  
    The success of the refactoring will be verified by:
  
     1. Successful Compilation: The project must compile without errors using the zig build command.
     2. Passing Tests: All existing tests must pass. I will execute the test suite using the command defined in build.zig (typically zig build test).
  
    This plan provides a clear and structured path to refactor the evaluator, resulting in a more modular and maintainable codebase.
    
    ===
    
    
  Completed Work

  Task 1: ErgoTree v3 Specification Features

  1.1 v6 Version Gating for getVarFromInput (src/interpreter/evaluator.zig:3711)
  - Added isV6Activated() check in computeGetVarFromInput()
  - Returns soft-fork accept (treated as true per Scala semantics) when v6 not active
  - Added test verifying v2 context returns true, v3 context works normally

  1.2 4KB ErgoTree Size Limit (src/serialization/ergotree_serializer.zig)
  - Added max_ergo_tree_size = 4096 constant
  - Added TreeTooBig error to DeserializeError enum
  - Added size check at start of deserialize() function
  - Added 3 tests (exact limit, over limit, large input rejected)

  Task 2: Cryptographic Validation Hardening (src/crypto/secp256k1.zig)

  - Added PointNotInSubgroup error
  - Added verifySubgroup() method for defense-in-depth validation
  - Added decodeStrict() variant that includes subgroup check
  - Added comprehensive validation tests:
    - Invalid prefix tests (0x05, 0x01, 0x00 with non-zero x)
    - Field element >= p test
    - Point not on curve (x=5 has no valid y)
    - Documented infinity acceptance per Scala reference

  Task 3: Property-Based Tests (tests/property/main.zig)

  - Created property test file with 6 tests:
    - true_leaf evaluates consistently
    - false_leaf evaluates consistently
    - Height returns context height for random heights
    - Evaluation is deterministic
    - Cost is always consumed
    - Cost limit of 1 fails for non-trivial ops
  - Updated build.zig to include property tests in test step

  Task 4: Production Observability Metrics

  - Created src/interpreter/metrics.zig with Metrics struct
  - Atomic counters: evaluations_total, evaluation_errors_total, evaluation_cost_total, evaluation_success_total
  - Added optional metrics field to Evaluator struct
  - Instrumented evaluate() function to record metrics on start, success, and error
  - Added 4 tests for metrics functionality

  All tests pass (./zig/zig build test exits with code 0).
