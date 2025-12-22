# Zigma Quick Reference

## Build Commands

```bash
./zig/zig build                    # Debug build
./zig/zig build test               # Run all tests (required before commit)
./zig/zig fmt src/                 # Format (required before commit)
./zig/zig build bench -Doptimize=ReleaseFast  # Benchmarks
```

## CLI Usage

```bash
./zig-out/bin/zigma version
./zig-out/bin/zigma eval <hex> [--height=N]
./zig-out/bin/zigma deserialize <hex>
./zig-out/bin/zigma hash blake2b256|sha256 <hex>
```

## Task Management (bd)

```bash
bd ready                           # Available work
bd show <id>                       # Issue details
bd update <id> --status=in_progress   # Claim
bd close <id>                      # Complete
bd stats                           # Project overview
bd blocked                         # Blocked issues
```

## DST (Deterministic Simulation Testing)

```bash
./zig/zig build dst
./zig-out/bin/zigma-dst --seed=12345 --ticks=10000
./zig-out/bin/zigma-dst --seed=$(git rev-parse HEAD)  # CI mode
```

## Key File Locations

| What | File |
|------|------|
| Main evaluator | `src/interpreter/evaluator.zig` |
| Expression parsing | `src/serialization/expr_serializer.zig` |
| Type system | `src/core/types.zig` |
| Elliptic curve | `src/crypto/secp256k1.zig` |
| BigInt | `src/crypto/bigint.zig` |
| AVL tree | `src/crypto/avl_tree.zig` |
| Sigma verification | `src/sigma/verifier.zig` |
| CLI | `src/main.zig` |

## Type Codes

| Code | Type |
|------|------|
| 0 | Unit |
| 1 | Boolean |
| 2 | Byte |
| 3 | Short |
| 4 | Int |
| 5 | Long |
| 6 | BigInt |
| 7 | GroupElement |
| 8 | SigmaProp |
| 12 | Coll[Byte] |
| 99 | Box |
| 104 | Header |
| 105 | PreHeader |

## Common Errors

| Error | Meaning |
|-------|---------|
| InvalidTypeCode | Byte stream misaligned |
| InvalidConstantIndex | Constant pool OOB |
| CostLimitExceeded | Script too complex |
| ArithmeticOverflow | Integer overflow |
| TypeMismatch | Wrong operand types |
| DivisionByZero | Division by 0 |

## Cost Model (JIT/v2)

| Operation | Cost |
|-----------|------|
| Constant | 5 |
| Arithmetic | 15 |
| Comparison | 20 |
| Height | 26 |
| DecodePoint | 300 |
| Exponentiate | 900 |

## Git Workflow

```bash
# Before commit
./zig/zig fmt src/
./zig/zig build test

# Commit (no Claude credits!)
git add <files>
git commit -m "Short description"

# Check beads sync
bd sync --from-main
```

## Critical Rules

1. Use `./zig/zig` not system zig
2. Run `./zig/zig fmt src/` before commit
3. Run `./zig/zig build test` before commit
4. No dynamic allocation during evaluation
5. No recursion in interpreter
6. Min 3 assertions per function
7. Handle all errors explicitly
