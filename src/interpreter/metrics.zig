//! Production Observability Metrics
//!
//! Prometheus-style metrics for evaluator instrumentation.
//! Uses atomic operations for thread-safe updates.
//!
//! Reference: TigerBeetle metrics patterns

const std = @import("std");
const assert = std.debug.assert;

/// Prometheus-style metrics for evaluator instrumentation
/// All counters use atomic operations for thread-safe updates
pub const Metrics = struct {
    /// Total evaluations started
    evaluations_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Total evaluations that returned errors
    evaluation_errors_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Total cost units consumed across all evaluations
    evaluation_cost_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Total successful evaluations
    evaluation_success_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // ============================================================================
    // Counter Operations
    // ============================================================================

    /// Increment total evaluations counter
    pub fn incEvaluations(self: *Metrics) void {
        // INVARIANT: Counter only increases
        _ = self.evaluations_total.fetchAdd(1, .monotonic);
    }

    /// Increment error counter
    pub fn incErrors(self: *Metrics) void {
        // INVARIANT: Counter only increases
        _ = self.evaluation_errors_total.fetchAdd(1, .monotonic);
    }

    /// Increment success counter
    pub fn incSuccess(self: *Metrics) void {
        // INVARIANT: Counter only increases
        _ = self.evaluation_success_total.fetchAdd(1, .monotonic);
    }

    /// Add cost units to total
    pub fn addCost(self: *Metrics, cost: u64) void {
        // INVARIANT: Counter only increases
        _ = self.evaluation_cost_total.fetchAdd(cost, .monotonic);
    }

    // ============================================================================
    // Snapshot Operations
    // ============================================================================

    /// Get current values (for testing/export)
    /// Returns a consistent snapshot of all metrics
    pub fn snapshot(self: *const Metrics) MetricsSnapshot {
        return .{
            .evaluations_total = self.evaluations_total.load(.monotonic),
            .evaluation_errors_total = self.evaluation_errors_total.load(.monotonic),
            .evaluation_cost_total = self.evaluation_cost_total.load(.monotonic),
            .evaluation_success_total = self.evaluation_success_total.load(.monotonic),
        };
    }

    /// Reset all counters to zero (for testing)
    pub fn reset(self: *Metrics) void {
        self.evaluations_total.store(0, .monotonic);
        self.evaluation_errors_total.store(0, .monotonic);
        self.evaluation_cost_total.store(0, .monotonic);
        self.evaluation_success_total.store(0, .monotonic);
    }
};

/// Immutable snapshot of metrics values
pub const MetricsSnapshot = struct {
    evaluations_total: u64,
    evaluation_errors_total: u64,
    evaluation_cost_total: u64,
    evaluation_success_total: u64,

    /// Calculate success rate (0.0 - 1.0)
    /// Returns null if no evaluations have been recorded
    pub fn successRate(self: MetricsSnapshot) ?f64 {
        if (self.evaluations_total == 0) return null;
        return @as(f64, @floatFromInt(self.evaluation_success_total)) /
            @as(f64, @floatFromInt(self.evaluations_total));
    }

    /// Calculate average cost per evaluation
    /// Returns null if no evaluations have been recorded
    pub fn avgCost(self: MetricsSnapshot) ?f64 {
        if (self.evaluations_total == 0) return null;
        return @as(f64, @floatFromInt(self.evaluation_cost_total)) /
            @as(f64, @floatFromInt(self.evaluations_total));
    }
};

// ============================================================================
// Tests
// ============================================================================

test "metrics: basic increment operations" {
    var metrics = Metrics{};

    metrics.incEvaluations();
    metrics.incEvaluations();
    metrics.incSuccess();
    metrics.incErrors();
    metrics.addCost(100);
    metrics.addCost(50);

    const snap = metrics.snapshot();
    try std.testing.expectEqual(@as(u64, 2), snap.evaluations_total);
    try std.testing.expectEqual(@as(u64, 1), snap.evaluation_success_total);
    try std.testing.expectEqual(@as(u64, 1), snap.evaluation_errors_total);
    try std.testing.expectEqual(@as(u64, 150), snap.evaluation_cost_total);
}

test "metrics: reset clears all counters" {
    var metrics = Metrics{};

    metrics.incEvaluations();
    metrics.incSuccess();
    metrics.addCost(100);

    metrics.reset();

    const snap = metrics.snapshot();
    try std.testing.expectEqual(@as(u64, 0), snap.evaluations_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_success_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_cost_total);
}

test "metrics: success rate calculation" {
    var metrics = Metrics{};

    // No evaluations - returns null
    try std.testing.expectEqual(@as(?f64, null), metrics.snapshot().successRate());

    // 100% success
    metrics.incEvaluations();
    metrics.incSuccess();
    try std.testing.expectApproxEqRel(@as(f64, 1.0), metrics.snapshot().successRate().?, 0.001);

    // 50% success
    metrics.incEvaluations();
    metrics.incErrors();
    try std.testing.expectApproxEqRel(@as(f64, 0.5), metrics.snapshot().successRate().?, 0.001);
}

test "metrics: average cost calculation" {
    var metrics = Metrics{};

    // No evaluations - returns null
    try std.testing.expectEqual(@as(?f64, null), metrics.snapshot().avgCost());

    // Single evaluation with cost 100
    metrics.incEvaluations();
    metrics.addCost(100);
    try std.testing.expectApproxEqRel(@as(f64, 100.0), metrics.snapshot().avgCost().?, 0.001);

    // Two evaluations with total cost 250
    metrics.incEvaluations();
    metrics.addCost(150);
    try std.testing.expectApproxEqRel(@as(f64, 125.0), metrics.snapshot().avgCost().?, 0.001);
}

test "metrics: initial state is all zeros" {
    const metrics = Metrics{};
    const snap = metrics.snapshot();

    try std.testing.expectEqual(@as(u64, 0), snap.evaluations_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_errors_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_cost_total);
    try std.testing.expectEqual(@as(u64, 0), snap.evaluation_success_total);
}
