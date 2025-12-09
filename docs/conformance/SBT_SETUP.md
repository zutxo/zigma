# SBT Test Runner Setup for sigmastate-interpreter

## Overview

The Scala sigmastate-interpreter test suite is located at:
`/home/mark/ergotree-research/scala/sigmastate/`

## Prerequisites

- SBT 1.11.1+ (installed via SDKMAN)
- Java 11+

## Project Structure

The project uses SBT with cross-compilation for JVM/JS:
- `core` - Type system (SType, opcodes)
- `interpreter` - Evaluation engine
- `sc` - Compiler and test suite (main tests here)

## Commands

### Compile Tests
```bash
cd /home/mark/ergotree-research/scala/sigmastate
sbt "scJVM/Test/compile"
```

### Run All Language Spec Tests
```bash
sbt "scJVM/testOnly special.sigma.LanguageSpecificationV5"
# Takes ~4 minutes, runs 210 tests
```

### Run Specific Tests
```bash
# Filter by test name
sbt "scJVM/testOnly special.sigma.LanguageSpecificationV5 -- -z \"BinXor\""
sbt "scJVM/testOnly special.sigma.LanguageSpecificationV5 -- -z \"Byte methods\""
```

### Other Test Suites
```bash
sbt "scJVM/testOnly special.sigma.LanguageSpecificationV6"  # v6 features
sbt "scJVM/testOnly sigmastate.ErgoTreeSpecification"        # Serialization
sbt "scJVM/testOnly sigmastate.TypesSpecification"           # Types
```

## Key Test Files

| File | Package | Purpose |
|------|---------|---------|
| `LanguageSpecificationV5.scala` | `special.sigma` | Main v5 language tests (210 tests) |
| `LanguageSpecificationV6.scala` | `special.sigma` | v6 soft-fork tests |
| `SigmaDslTesting.scala` | `special.sigma` | Test infrastructure |
| `TypesSpecification.scala` | `sigmastate` | Type system tests |
| `ErgoTreeSpecification.scala` | `sigmastate` | Serialization tests |

## Test Case Format

Tests use property-based testing with explicit test vectors:

```scala
// Boolean operations
val cases = Seq(
  (true, true) -> Expected(Success(false), cost, costDetails, newCost, ...),
  (true, false) -> Expected(Success(true), cost, costDetails, newCost, ...),
)

// Arithmetic with overflow checking
Seq(
  ((-128.toByte, -128.toByte), Expected(new ArithmeticException("Byte overflow"))),
  ((-103.toByte, 1.toByte), success((-102.toByte, (-104.toByte, (-103.toByte, (-103.toByte, 0.toByte)))))),
  // Returns tuple: (plus, (minus, (mul, (div, mod))))
)
```

## Categories of Test Vectors Available

1. **Boolean Operations**: BinXor, And, Or, Not
2. **Byte Arithmetic**: Plus, Minus, Multiply, Divide, Modulo (with overflow checking)
3. **Short Arithmetic**: Same operations for Short type
4. **Int Arithmetic**: Same operations for Int type
5. **Long Arithmetic**: Same operations for Long type
6. **BigInt Arithmetic**: Operations on 256-bit integers
7. **Type Conversions**: Upcast, Downcast between numeric types
8. **Comparisons**: LT, GT, LE, GE, EQ, NEQ for all types
9. **Collections**: Map, Filter, Fold, Size, ByIndex, Slice, Append
10. **Crypto**: blake2b256, sha256, GroupElement operations
11. **Sigma Protocols**: proveDlog, proveDHTuple, atLeast, allOf, anyOf

## Next Steps

1. Create Python script to parse Scala test files and extract vectors
2. Output JSON test vectors for consumption by Zig test framework
3. Build Zig conformance test runner that loads JSON vectors
