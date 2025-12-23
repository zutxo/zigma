# Zigma DST Production-Ready Enhancement Plan

 Overview

 Enhance zigma's deterministic simulation testing framework to production-ready quality, implementing the recommendations from DST_ZIGMA_ADAPTATION.md.

 Project: zigma (/home/mark/orgs/zutxo/zigma)
 Tracking: Create beads during implementation phase

 User Confirmed:

 - Scope: All phases (1-3) - complete feature set
 - Expr Gen: Full implementation - all collection + crypto operations
 - Validation: Run DST after each change to verify implementations

 ---
 Current State Assessment

 Production-Ready Components

 | Component                          | Status      | Notes                                   |
 |------------------------------------|-------------|-----------------------------------------|
 | src/dst/prng.zig                   | ✅ Complete | XoShiro256++, Ratio type, git SHA seeds |
 | src/dst/generators/context_gen.zig | ✅ Complete | Full context generation                 |
 | src/dst/checkers/determinism.zig   | ✅ Complete | Critical safety check                   |
 | Simulator structure                | ✅ Solid    | Clean architecture                      |

 Needs Enhancement

 | Component                            | Status        | Issue                           |
 |--------------------------------------|---------------|---------------------------------|
 | src/dst/generators/expr_gen.zig      | ⚠️ Limited    | Missing collection/crypto ops   |
 | src/dst/checkers/cost_checker.zig    | ⚠️ Basic      | Limited invariants              |
 | src/dst/checkers/type_checker.zig    | ⚠️ Partial    | Never called                    |
 | src/dst/fault_injection/injector.zig | ❌ Unused     | Defined but never invoked       |
 | src/dst/trace/recorder.zig           | ❌ Skeleton   | Not integrated                  |
 | src/dst/dst.zig                      | ⚠️ Incomplete | No fault pipeline, basic output |

 ---
 Phase 1: Critical Path (Must Have)

 1.1 Enable Fault Injection Pipeline

 Files: src/dst/dst.zig, src/dst/fault_injection/injector.zig

 Tasks:
 1. Wire FaultInjector into main tick loop
 2. Add fault injection probability configuration
 3. Track fault injection statistics
 4. Verify evaluator handles faults gracefully (returns error, not crash)

 Implementation:
 // In Options:
 fault_injection_probability: Ratio = .{ .numerator = 10, .denominator = 100 },

 // In tick():
 if (self.prng.chance(self.options.fault_injection_probability)) {
     const inject_result = self.fault_injector.injectRandom(&self.tree);
     self.faults_injected += 1;
     if (inject_result == .success) {
         // Evaluate faulty tree - should error, not crash
     }
 }

 1.2 Complete Expression Generator

 File: src/dst/generators/expr_gen.zig

 Tasks:
 1. Implement collection operations
   - fold, map, filter, exists, forall
   - size, getOrElse, slice, append
 2. Implement crypto operations
   - blake2b256, sha256
   - Point operations (if applicable)
 3. Add box/input/output accessor generation
   - SELF, INPUTS, OUTPUTS, DATA_INPUTS
 4. Generate more diverse expression shapes

 Effort: ~3 days

 1.3 End-to-End Fault Tests

 File: src/dst/dst.zig (tests section)

 Tasks:
 1. Test that injects boundary faults and verifies error return
 2. Test that injects invalid opcodes and verifies no crash
 3. Test that injects zero-divisor and verifies proper error
 4. Test for determinism under fault injection

 ---
 Phase 2: Enhanced Verification (Should Have)

 2.1 Integrate Trace Recording

 Files: src/dst/trace/recorder.zig, src/dst/dst.zig

 Tasks:
 1. Initialize TraceRecorder in simulator
 2. Record pre-evaluation state on each tick
 3. Record post-evaluation state
 4. On divergence in determinism check, dump trace comparison
 5. Add trace serialization (JSON format) for debugging

 2.2 Enhance Cost Checker

 File: src/dst/checkers/cost_checker.zig

 Tasks:
 1. Add opcode-specific cost verification
   - Verify each opcode costs what it should
 2. Add cost regression detection
   - Track cost changes between evaluations
 3. Integrate cost limit boundary testing
   - Use checkExactLimitEnforcement in tick loop

 2.3 Complete Type Checker Integration

 Files: src/dst/checkers/type_checker.zig, src/dst/dst.zig

 Tasks:
 1. Fix tree traversal for operand type verification
 2. Add type checker to main tick loop
 3. Track type violations in statistics

 ---
 Phase 3: Coverage & Output (Nice to Have)

 3.1 Add Coverage Tracker

 File: New: src/dst/checkers/coverage.zig

 Tasks:
 1. Track opcode hits
 2. Track type hits
 3. Track expression depth distribution
 4. Report coverage percentage

 Implementation:
 pub const CoverageTracker = struct {
     opcode_hits: [@typeInfo(ExprTag).Enum.fields.len]u64,
     type_hits: [128]u64,

     pub fn record_evaluation(self: *CoverageTracker, tree: *ExprTree) void {
         for (tree.nodes[0..tree.node_count]) |node| {
             self.opcode_hits[@intFromEnum(node.tag)] += 1;
             self.type_hits[node.result_type] += 1;
         }
     }

     pub fn coverage_percentage(self: *CoverageTracker) f32 {
         const total = @typeInfo(ExprTag).Enum.fields.len;
         var covered: u32 = 0;
         for (self.opcode_hits) |hits| {
             if (hits > 0) covered += 1;
         }
         return @as(f32, @floatFromInt(covered)) / @as(f32, @floatFromInt(total)) * 100.0;
     }
 };

 3.2 Enhanced CLI Output

 File: src/dst/dst.zig

 Tasks:
 1. Add TigerBeetle-style progress output
 2. Show swarm configuration parameters
 3. Display coverage statistics
 4. Add timing information (ticks/sec)

 Target Output:
 ========================================
     ZIGMA Deterministic Simulation Testing
 ========================================

 SEED=8675309
 mode=swarm
 ticks_max=10000

 Options:
   max_depth=12
   max_nodes=150
   collection_weight=50
   crypto_weight=30

 Progress:
   tick 5000/10000 | 2500 ticks/s
   evals: 5000 (4800 ok, 200 err)
   det_checks: 5000 (0 fail)
   faults_injected: 500 (500 handled)
   coverage: 65/128 opcodes (51%)

 ========================================
 PASSED (10000 ticks)
 ========================================

 3.3 Swarm Configuration Generator

 File: src/dst/dst.zig

 Tasks:
 1. Generate random expression weights using PRNG
 2. Generate random context parameters
 3. Generate random fault probabilities
 4. Track which configurations find bugs

 ---
 Phase 4: Advanced Features (Future)

 4.1 Expand Fault Types

 File: src/dst/fault_injection/injector.zig

 Tasks:
 1. Add stack overflow injection (deep recursion)
 2. Add OOM injection (memory limit)
 3. Add invalid box index injection
 4. Add register corruption
 5. Add cost limit boundary testing

 4.2 Conformance Testing Framework

 File: New: src/dst/checkers/conformance.zig

 Tasks:
 1. Load test vectors from reference implementation
 2. Compare zigma output with expected
 3. Track conformance percentage
 4. Report mismatches with details

 4.3 CI Integration

 Tasks:
 1. Add GitHub Actions workflow for DST
 2. Use git commit hash as seed
 3. Store failure seeds for regression
 4. Track coverage trends

 ---
 Critical Files to Modify

 | File                                 | Changes                                 |
 |--------------------------------------|-----------------------------------------|
 | src/dst/dst.zig                      | Fault pipeline, coverage, output format |
 | src/dst/generators/expr_gen.zig      | Collection/crypto ops                   |
 | src/dst/fault_injection/injector.zig | New fault types                         |
 | src/dst/trace/recorder.zig           | Full integration                        |
 | src/dst/checkers/cost_checker.zig    | Enhanced invariants                     |
 | src/dst/checkers/type_checker.zig    | Tree traversal fix                      |
 | NEW: src/dst/checkers/coverage.zig   | Coverage tracking                       |

 ---
 Beads Structure

 During implementation, create these beads:

 zigma-dst-prod                    # Parent issue
 ├── dst-fault-pipeline            # Phase 1.1
 ├── dst-expr-gen-complete         # Phase 1.2
 ├── dst-fault-tests               # Phase 1.3
 ├── dst-trace-integration         # Phase 2.1
 ├── dst-cost-checker-enhance      # Phase 2.2
 ├── dst-type-checker-integrate    # Phase 2.3
 ├── dst-coverage-tracker          # Phase 3.1
 ├── dst-cli-output                # Phase 3.2
 └── dst-swarm-config              # Phase 3.3

 ---
 Success Criteria

 Phase 1 Complete When:

 - Fault injection runs in every tick (probabilistically)
 - Expression generator covers collection and crypto operations
 - All fault types handled gracefully (error return, not crash)
 - 100K ticks complete without panic

 Phase 2 Complete When:

 - Trace recording captures divergences
 - Cost checker verifies opcode costs
 - Type checker runs in main loop

 Phase 3 Complete When:

 - Coverage tracker shows opcode coverage
 - CLI output matches TigerBeetle style
 - Swarm config randomizes all parameters

 ---
 Estimated Effort

 | Phase                      | Effort | Dependencies |
 |----------------------------|--------|--------------|
 | Phase 1.1 (Fault Pipeline) | 4h     | None         |
 | Phase 1.2 (Expr Gen)       | 8h     | None         |
 | Phase 1.3 (Fault Tests)    | 4h     | 1.1          |
 | Phase 2.1 (Trace)          | 6h     | 1.1, 1.3     |
 | Phase 2.2 (Cost)           | 4h     | None         |
 | Phase 2.3 (Type)           | 3h     | None         |
 | Phase 3.1 (Coverage)       | 4h     | None         |
 | Phase 3.2 (CLI)            | 3h     | 3.1          |
 | Phase 3.3 (Swarm)          | 3h     | None         |

 Total: 39 hours (1 week focused work)

 ---
 Reference Documentation

 - /home/mark/orgs/zutxo/zigma/docs/specs/VOPR_SPEC.md - TigerBeetle DST specification
 - /home/mark/orgs/zutxo/zigma/docs/design/DST_DESIGN_REFERENCE.md - Design patterns
 - /home/mark/orgs/zutxo/zigma/docs/design/DST_ZIGMA_ADAPTATION.md - Adaptation guide

 ---
 Plan Status: Ready for implementation
