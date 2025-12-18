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

    // Mainnet conformance tests (full ErgoTree evaluation)
    const mainnet_tests = b.addTest(.{
        .root_source_file = b.path("tests/conformance/mainnet.zig"),
        .target = target,
        .optimize = optimize,
    });
    mainnet_tests.root_module.addImport("zigma", lib.root_module);
    const run_mainnet_tests = b.addRunArtifact(mainnet_tests);
    const mainnet_step = b.step("mainnet", "Run mainnet conformance tests");
    mainnet_step.dependOn(&run_mainnet_tests.step);

    // Include mainnet tests in conformance and main test step
    conformance_step.dependOn(&run_mainnet_tests.step);
    test_step.dependOn(&run_mainnet_tests.step);

    // Property-based tests (invariants and metamorphic properties)
    const property_tests = b.addTest(.{
        .root_source_file = b.path("tests/property/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    property_tests.root_module.addImport("zigma", lib.root_module);
    const run_property_tests = b.addRunArtifact(property_tests);
    const property_step = b.step("property", "Run property-based tests");
    property_step.dependOn(&run_property_tests.step);

    // Include property tests in main test step
    test_step.dependOn(&run_property_tests.step);

    // CLI executable
    const cli_exe = b.addExecutable(.{
        .name = "zigma",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(cli_exe);

    // CLI run step
    const run_cli = b.addRunArtifact(cli_exe);
    if (b.args) |args| {
        run_cli.addArgs(args);
    }
    const cli_step = b.step("cli", "Run zigma CLI");
    cli_step.dependOn(&run_cli.step);

    // Documentation
    const lib_docs = lib.getEmittedDocs();
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib_docs,
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    // Benchmarks
    const bench_exe = b.addExecutable(.{
        .name = "zigma-bench",
        .root_source_file = b.path("benchmarks/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_exe.root_module.addImport("zigma", lib.root_module);
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| {
        run_bench.addArgs(args);
    }
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);

    // DST (Deterministic Simulation Testing) - Unit tests
    const dst_tests = b.addTest(.{
        .root_source_file = b.path("src/dst/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    dst_tests.root_module.addImport("zigma", lib.root_module);
    const run_dst_tests = b.addRunArtifact(dst_tests);
    const dst_test_step = b.step("dst-test", "Run DST unit tests");
    dst_test_step.dependOn(&run_dst_tests.step);

    // DST Executable - Main simulator
    const dst_exe = b.addExecutable(.{
        .name = "zigma-dst",
        .root_source_file = b.path("src/dst/dst.zig"),
        .target = target,
        .optimize = optimize,
    });
    dst_exe.root_module.addImport("zigma", lib.root_module);
    b.installArtifact(dst_exe);

    // DST run step
    const run_dst = b.addRunArtifact(dst_exe);
    if (b.args) |args| {
        run_dst.addArgs(args);
    }
    const dst_step = b.step("dst", "Run deterministic simulation testing");
    dst_step.dependOn(&run_dst.step);
}
