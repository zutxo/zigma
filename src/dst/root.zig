//! Deterministic Simulation Testing (DST) Framework
//!
//! TigerBeetle-inspired DST for the zigma sigma-state interpreter.
//! Verifies interpreter correctness through exhaustive seed-based testing.
//!
//! Usage:
//!   ./zig/zig build dst                     # Run with random seed
//!   ./zig/zig build dst -- --seed=12345     # Run with specific seed
//!   ./zig/zig build dst -- --seed=$(git rev-parse HEAD)  # CI mode

pub const prng = @import("prng.zig");

// Re-export core types
pub const PRNG = prng.PRNG;
pub const Ratio = prng.Ratio;
pub const parse_seed = prng.parse_seed;
pub const parse_seed_or_panic = prng.parse_seed_or_panic;
pub const random_enum_weights = prng.random_enum_weights;

// Generators
pub const expr_gen = @import("generators/expr_gen.zig");
pub const context_gen = @import("generators/context_gen.zig");
// pub const value_gen = @import("generators/value_gen.zig");

// Re-export generator types
pub const ExprGenerator = expr_gen.ExprGenerator;
pub const ExprGenOptions = expr_gen.ExprGenOptions;
pub const ContextGenerator = context_gen.ContextGenerator;
pub const ContextGenOptions = context_gen.ContextGenOptions;

// Checkers
pub const determinism = @import("checkers/determinism.zig");
pub const cost_checker = @import("checkers/cost_checker.zig");
pub const type_checker = @import("checkers/type_checker.zig");
// pub const conformance = @import("checkers/conformance.zig");

// Main simulator
pub const dst = @import("dst.zig");

// Re-export checker types
pub const DeterminismChecker = determinism.DeterminismChecker;
pub const DeterminismResult = determinism.DeterminismResult;
pub const EvalResult = determinism.EvalResult;
pub const CostChecker = cost_checker.CostChecker;
pub const CostCheckResult = cost_checker.CostCheckResult;

// Fault injection
pub const fault_injector = @import("fault_injection/injector.zig");

// Re-export fault injector types
pub const FaultInjector = fault_injector.FaultInjector;
pub const FaultKind = fault_injector.FaultKind;
pub const InjectionResult = fault_injector.InjectionResult;

// Trace
pub const trace_recorder = @import("trace/recorder.zig");

// Re-export trace types
pub const TraceRecorder = trace_recorder.TraceRecorder;
pub const TraceEntry = trace_recorder.TraceEntry;
pub const TraceResult = trace_recorder.TraceResult;
pub const Divergence = trace_recorder.Divergence;
pub const traceEvaluation = trace_recorder.traceEvaluation;

// Re-export type checker types
pub const TypeChecker = type_checker.TypeChecker;
pub const TypeCheckResult = type_checker.TypeCheckResult;
pub const TypeViolation = type_checker.TypeViolation;

test {
    // Run all DST tests
    _ = prng;
    _ = expr_gen;
    _ = context_gen;
    _ = determinism;
    _ = cost_checker;
    _ = type_checker;
    _ = fault_injector;
    _ = trace_recorder;
    _ = dst;
}
