const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library
    const lib = b.addStaticLibrary(.{
        .name = "zigma",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Unit tests
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Conformance tests (against Scala sigmastate-interpreter)
    const conformance_tests = b.addTest(.{
        .root_source_file = b.path("tests/conformance/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Add root module so tests can import src/interpreter/ops.zig
    conformance_tests.root_module.addImport("zigma", lib.root_module);
    const run_conformance_tests = b.addRunArtifact(conformance_tests);
    const conformance_step = b.step("conformance", "Run conformance tests");
    conformance_step.dependOn(&run_conformance_tests.step);

    // Include conformance tests in main test step
    test_step.dependOn(&run_conformance_tests.step);

    // Documentation
    const lib_docs = lib.getEmittedDocs();
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib_docs,
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    // Benchmarks (placeholder for future)
    const bench_step = b.step("bench", "Run benchmarks");
    _ = bench_step;
}
