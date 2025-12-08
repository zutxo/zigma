## Phase 0: Research & Specification Extraction

### Prompt 0.1: Clone and Analyze Reference Implementations

```
TASK: Set up research environment with all reference implementations

CONTEXT (From Ergo Core Developers):
"There are THREE implementations you need to study:
1. sigmastate-interpreter (Scala) - The canonical reference
2. sigma-rust - Production Rust implementation, better for non-JVM reference
3. ergo-lib-wasm - WebAssembly version with simplified API

The Scala code has the most comments and test coverage. The Rust code
is cleaner for understanding data structures. Use both."

PREREQUISITE KNOWLEDGE:
- ErgoTree is the bytecode format, ErgoScript is the source language
- The interpreter does NOT compile - it only evaluates pre-compiled trees
- Ergo uses UTXO model like Bitcoin, but boxes have richer structure
- All arithmetic must be deterministic across platforms

Here's an improved prompt that ensures Claude Code finds and documents the latest implementation:

```markdown
# Phase 0.1: Repository Cloning & Version Discovery

OBJECTIVE: Clone reference implementations and establish CURRENT specification state.
The ErgoTree PDF spec (March 2020) is OUTDATED. The authoritative source is the code itself.

## COMMANDS:

```bash
# Create workspace
mkdir -p ~/ergotree-research/{scala,rust,specs,vectors}
cd ~/ergotree-research

# ============================================
# SCALA REFERENCE (Canonical Implementation)
# ============================================
git clone https://github.com/ergoplatform/sigmastate-interpreter.git scala/sigmastate
cd scala/sigmastate

# CRITICAL: Use develop branch (where active development happens)
git checkout develop
git pull origin develop

# Document exact state
echo "=== SCALA REPO STATE ===" > ~/ergotree-research/RESEARCH_LOG.md
echo "Date: $(date -Iseconds)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Branch: $(git branch --show-current)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Commit: $(git rev-parse HEAD)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Commit date: $(git log -1 --format=%ci)" >> ~/ergotree-research/RESEARCH_LOG.md
git describe --tags --always >> ~/ergotree-research/RESEARCH_LOG.md 2>/dev/null || echo "No tags" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# List recent tags to understand version landscape
echo "=== RECENT RELEASES ===" >> ~/ergotree-research/RESEARCH_LOG.md
git tag --sort=-creatordate | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# RUST REFERENCE (Cleaner for non-JVM impl)
# ============================================
cd ~/ergotree-research
git clone https://github.com/ergoplatform/sigma-rust.git rust/sigma-rust
cd rust/sigma-rust
git checkout develop 2>/dev/null || git checkout main

echo "=== RUST REPO STATE ===" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Branch: $(git branch --show-current)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Commit: $(git rev-parse HEAD)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "Commit date: $(git log -1 --format=%ci)" >> ~/ergotree-research/RESEARCH_LOG.md
git describe --tags --always >> ~/ergotree-research/RESEARCH_LOG.md 2>/dev/null
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# SPECIFICATION VERSION ANALYSIS (CRITICAL)
# ============================================
cd ~/ergotree-research/scala/sigmastate

echo "=== ERGOTREE VERSION CONSTANTS ===" >> ~/ergotree-research/RESEARCH_LOG.md

# Find ALL version-related constants
grep -rn "VersionContext\|ErgoTreeVersion\|ScriptVersion\|ActivatedVersion\|BlockVersion" \
  --include="*.scala" core/ data/ interpreter/ 2>/dev/null | \
  grep -v "test\|Test" | head -40 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# Find the VersionContext file specifically (this defines protocol versions)
echo "=== VersionContext.scala (Protocol Version Definitions) ===" >> ~/ergotree-research/RESEARCH_LOG.md
find . -name "VersionContext.scala" -exec cat {} \; >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# Find current max supported version
echo "=== MAX SUPPORTED VERSIONS ===" >> ~/ergotree-research/RESEARCH_LOG.md
grep -rn "MaxSupportedScriptVersion\|maxVersion\|V6\|v6\|version.*=.*[0-9]" \
  --include="*.scala" core/ 2>/dev/null | grep -i version | head -20 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# IDENTIFY V5 vs V6 DIFFERENCES (CRITICAL)
# ============================================
echo "=== V6 PROTOCOL CHANGES ===" >> ~/ergotree-research/RESEARCH_LOG.md

# Find v6-specific code paths
grep -rn "isV6Activated\|V6SoftFork\|version.*>=.*3\|ScriptVersionForV6" \
  --include="*.scala" 2>/dev/null | head -30 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# Find NEW opcodes/methods added in v6
echo "=== NEW V6 FEATURES ===" >> ~/ergotree-research/RESEARCH_LOG.md
grep -rn "sinceVersion.*=.*3\|@since.*6\.0\|v6.*new\|6\.0.*feature" \
  --include="*.scala" 2>/dev/null | head -30 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# DOWNLOAD PDF (but note it's outdated)
# ============================================
cd ~/ergotree-research/specs
curl -O https://ergoplatform.org/docs/ErgoTree.pdf 2>/dev/null || echo "PDF download failed - use code as source of truth"

echo "=== PDF SPEC WARNING ===" >> ~/ergotree-research/RESEARCH_LOG.md
echo "The ErgoTree.pdf is from March 2020 and covers ErgoTree v0/v1 only." >> ~/ergotree-research/RESEARCH_LOG.md
echo "Current protocol supports v0, v1, v2 (5.0), and v3 (6.0)." >> ~/ergotree-research/RESEARCH_LOG.md
echo "USE CODE AS SOURCE OF TRUTH for v2+ features." >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# KEY FILE IDENTIFICATION
# ============================================
cd ~/ergotree-research/scala/sigmastate

echo "=== KEY SCALA FILES ===" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Type System" >> ~/ergotree-research/RESEARCH_LOG.md
find . -path "*/shared/src/main/*" -name "*.scala" | xargs grep -l "sealed.*SType\|case.*extends.*SType" 2>/dev/null | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Serialization" >> ~/ergotree-research/RESEARCH_LOG.md
find . -path "*/shared/src/main/*" -name "*Serializer*.scala" | grep -v test | head -15 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Operations/Opcodes" >> ~/ergotree-research/RESEARCH_LOG.md
find . -path "*/shared/src/main/*" -name "*.scala" | xargs grep -l "OpCode\|opCode.*=" 2>/dev/null | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Interpreter" >> ~/ergotree-research/RESEARCH_LOG.md
find . -path "*/shared/src/main/*" -name "*Interpreter*.scala" -o -name "*Evaluator*.scala" | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Cost Model" >> ~/ergotree-research/RESEARCH_LOG.md
find . -path "*/shared/src/main/*" -name "*.scala" | xargs grep -l "CostTable\|JitCost\|costOf" 2>/dev/null | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# RUST key files
cd ~/ergotree-research/rust/sigma-rust

echo "=== KEY RUST FILES ===" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Type System" >> ~/ergotree-research/RESEARCH_LOG.md
find . -name "*.rs" | xargs grep -l "enum SType\|SType {" 2>/dev/null | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Serialization" >> ~/ergotree-research/RESEARCH_LOG.md
find . -name "*serial*.rs" | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

echo "## Operations" >> ~/ergotree-research/RESEARCH_LOG.md
find . -name "*.rs" | xargs grep -l "OpCode\|pub enum Op" 2>/dev/null | grep -v test | head -10 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# RECENT CHANGES CHECK
# ============================================
cd ~/ergotree-research/scala/sigmastate

echo "=== RECENT COMMITS (Last 30 days) ===" >> ~/ergotree-research/RESEARCH_LOG.md
git log --oneline --since="30 days ago" | head -20 >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# Check for any breaking changes or important notes
echo "=== CHANGELOG/BREAKING CHANGES ===" >> ~/ergotree-research/RESEARCH_LOG.md
find . -name "CHANGELOG*" -o -name "BREAKING*" -o -name "MIGRATION*" | head -5 >> ~/ergotree-research/RESEARCH_LOG.md
cat CHANGELOG.md 2>/dev/null | head -100 >> ~/ergotree-research/RESEARCH_LOG.md || echo "No CHANGELOG.md found"
echo "" >> ~/ergotree-research/RESEARCH_LOG.md

# ============================================
# SUMMARY
# ============================================
echo "=== RESEARCH SUMMARY ===" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md
echo "## Active Protocol Versions:" >> ~/ergotree-research/RESEARCH_LOG.md
echo "- v0: Original (pre-4.0 hard fork)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "- v1: Post 4.0 hard fork (AOT interpreter)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "- v2: Ergo 5.0 soft fork (JIT interpreter)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "- v3: Ergo 6.0 soft fork (EIP-50)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md
echo "## Implementation Priority:" >> ~/ergotree-research/RESEARCH_LOG.md
echo "1. Support v2 (current mainnet) as primary target" >> ~/ergotree-research/RESEARCH_LOG.md
echo "2. Add v3 support for future compatibility" >> ~/ergotree-research/RESEARCH_LOG.md
echo "3. v0/v1 support optional (legacy)" >> ~/ergotree-research/RESEARCH_LOG.md
echo "" >> ~/ergotree-research/RESEARCH_LOG.md
echo "## Reference Priority:" >> ~/ergotree-research/RESEARCH_LOG.md
echo "1. sigma-rust: Cleaner data structures, better for Zig port" >> ~/ergotree-research/RESEARCH_LOG.md
echo "2. sigmastate-interpreter: Canonical/authoritative, check for edge cases" >> ~/ergotree-research/RESEARCH_LOG.md
echo "3. ErgoTree.pdf: Background concepts only, DO NOT trust for v2+ details" >> ~/ergotree-research/RESEARCH_LOG.md
```

## OUTPUT REQUIREMENTS:

Create `~/ergotree-research/RESEARCH_LOG.md` containing:

1. **Exact Repo State**
   - Commit hashes (full SHA)
   - Branch names
   - Commit dates
   - Latest tags

2. **Version Landscape**
   - All ErgoTree/Script version constants found
   - Which versions are currently active on mainnet
   - What version 6.0 adds vs 5.0

3. **Key Files Map**
   - Type system files (Scala + Rust paths)
   - Serialization files
   - Opcode/Operation files
   - Interpreter/Evaluator files
   - Cost model files

4. **Spec Discrepancies**
   - Note that PDF is from 2020
   - List features in code NOT in PDF
   - List any deprecated features

5. **Implementation Guidance**
   - Which reference to use for what
   - Known gotchas from recent commits

## VALIDATION:
After completing, verify by running:
```bash
# Confirm we have the latest
cd ~/ergotree-research/scala/sigmastate
git fetch origin
git status  # Should say "up to date with origin/develop"

# Confirm v6 code exists
grep -r "V6\|v6\|version.*3" --include="*.scala" | wc -l  # Should be > 0
```



### Prompt 0.2: Extract Complete Type System Specification

```
TASK: Extract and document complete type system from reference implementations

CONTEXT (From Zig Experts):
"The type system is your foundation. Get it wrong and everything breaks.
Pay special attention to:
- Recursive types (Coll, Option, Tuple, Function)
- Type coercion rules (subtyping with Any)
- Serialization codes (they encode the type compactly)

In Zig, you cannot have recursive struct types with pointers easily.
You'll need to use indices into a type pool instead."

PREREQUISITE KNOWLEDGE:
- ErgoTree types are reified (available at runtime)
- Type codes 1-11 are "embeddable" (can be encoded in parent type code)
- Type codes 12-111 are data types with various constructors
- Type codes 112-255 are function types (12×12 = 144 combinations)
- See ErgoTree Spec Section 5.1 for encoding details

COMMANDS:
```bash
cd ~/ergotree-research/scala/sigmastate

# Find type definitions
echo "=== Core Type Hierarchy ===" 
grep -rn "sealed trait SType\|case object.*extends.*SType\|case class.*extends.*SType" \
  --include="*.scala" | head -50

# Find type codes
echo -e "\n=== Type Codes ==="
grep -rn "val typeCode\|TypeCode\s*=" --include="*.scala" -A 2 | head -100

# Find embeddable types
echo -e "\n=== Embeddable Types ==="
grep -rn "embeddable\|isEmbeddable\|SPrimType" --include="*.scala" -A 3

# Find type serialization
echo -e "\n=== Type Serializer ==="
find . -name "*TypeSerializer*" -exec cat {} \;

# Find subtyping rules
echo -e "\n=== Subtyping ==="
grep -rn "isSubtype\|canBeSubstituted\|commonType" --include="*.scala" -B 2 -A 5

# FROM RUST (cleaner definitions)
cd ~/ergotree-research/rust/sigma-rust
echo -e "\n=== Rust Type Definitions ==="
find . -name "*.rs" | xargs grep -l "SType\|enum.*Type" | head -5
grep -rn "pub enum SType\|pub struct.*Type" --include="*.rs" -A 20
```

CREATE FILE: ~/ergotree-research/specs/TYPE_SYSTEM.md

FORMAT:
```markdown
# ErgoTree Type System Specification

## Primitive Types (Embeddable)
| Code | Name | Zig Type | Size | Notes |
|------|------|----------|------|-------|
| 1 | Boolean | bool | 1 byte | |
| 2 | Byte | i8 | 1 byte | Signed! |
| 3 | Short | i16 | 2 bytes | Big-endian |
| 4 | Int | i32 | 4 bytes | Big-endian |
| 5 | Long | i64 | 8 bytes | Big-endian |
| 6 | BigInt | [32]u8 | ≤256 bits | Two's complement |
| 7 | GroupElement | [33]u8 | 33 bytes | SEC1 compressed |
| 8 | SigmaProp | varies | varies | Sigma tree |

## Composite Types
[Document each with serialization format]

## Type Coercion Rules
[Document subtyping lattice]
```
```

### Prompt 0.3: Extract Complete Opcode Catalog

```
TASK: Extract every opcode with its semantics, serialization, and cost

CONTEXT (From Ergo Core Developers):
"The opcode list has grown over time. Some opcodes are versioned -
they behave differently depending on protocol version. Check
VersionContext.scala for version-dependent behavior.

Also note that opcodes 0x00-0x80 encode constants directly.
The opcode IS the type in that range. This is a space optimization."

PREREQUISITE KNOWLEDGE:
- OpCodes are single bytes (0x00 - 0xFF)
- 0x00-0x80: Constants (type encoded in opcode)
- 0x81-0xFF: Operations
- Each operation has: inputs, output type, cost, serialization format
- Some operations are "soft-forked" (added in later versions)

COMMANDS:
```bash
cd ~/ergotree-research/scala/sigmastate

# Find all opcode definitions
echo "=== OpCode Constants ==="
grep -rn "val.*Code.*=.*0x\|val.*Code.*:.*Byte\s*=" --include="*.scala" | \
  grep -v test | sort | uniq

# Find OpCodes object
echo -e "\n=== OpCodes Object ==="
find . -name "OpCodes.scala" -exec cat {} \;

# Find operation implementations
echo -e "\n=== Operation Implementations ==="
find . -name "*Operations*.scala" -path "*/src/main/*" -exec basename {} \;

# Find cost model
echo -e "\n=== Cost Definitions ==="
grep -rn "CostOf\|OperationCost\|JitCost" --include="*.scala" -A 3 | head -100

# Find serializers for each opcode
echo -e "\n=== Value Serializers ==="
find . -name "*Serializer.scala" -path "*/serialization/*" | head -20

# Find version-dependent behavior
echo -e "\n=== Version Context ==="
grep -rn "VersionContext\|isV5\|isV6\|sinceV" --include="*.scala" -A 2 | head -50

# FROM RUST
cd ~/ergotree-research/rust/sigma-rust
echo -e "\n=== Rust Opcodes ==="
grep -rn "OpCode\|op_code\|= 0x" --include="*.rs" | head -100
```

CREATE FILE: ~/ergotree-research/specs/OPCODES.md

FORMAT:
```markdown
# ErgoTree Opcode Catalog

## Constants (0x00 - 0x80)
Opcodes in this range encode constants directly.
Format: [opcode: 1 byte] [data: varies by type]

## Operations

### Arithmetic
| Code | Hex | Name | Inputs | Output | Cost | Since |
|------|-----|------|--------|--------|------|-------|
| 153 | 0x99 | Minus | T, T | T | 10 | v1 |
| 154 | 0x9A | Plus | T, T | T | 10 | v1 |

### Serialization Format
For each opcode, document:
1. OpCode byte
2. Operand serialization order
3. Type constraints
4. Special encoding rules

[Continue for all 100+ opcodes]
```
```

### Prompt 0.4: Generate Test Vectors

```
TASK: Extract and generate comprehensive test vectors from reference implementations

CONTEXT (From Formal Methods Researchers):
"Test vectors are your specification. If you pass all test vectors
from both Scala and Rust implementations, you have high confidence
in correctness. Generate vectors for:
1. Serialization roundtrips
2. Expression evaluation
3. Type checking
4. Cost calculation
5. Error conditions"

PREREQUISITE KNOWLEDGE:
- Scala tests are in src/test/scala
- Rust tests use proptest for property-based testing
- Real mainnet transactions provide integration test cases
- Edge cases: overflow, division by zero, empty collections

COMMANDS:
```bash
cd ~/ergotree-research

# Find Scala test files
echo "=== Scala Tests ==="
find scala/sigmastate -name "*Spec.scala" -o -name "*Test.scala" | head -30

# Extract serialization test cases
echo -e "\n=== Serialization Tests ==="
grep -rn "serialize\|deserialize" \
  scala/sigmastate/src/test --include="*.scala" -A 5 | head -100

# Find hex-encoded test vectors
echo -e "\n=== Hex Test Vectors ==="
grep -rn "fromHex\|toHex\|\"[0-9a-fA-F]\{20,\}\"" \
  scala/sigmastate/src/test --include="*.scala" | head -50

# Extract evaluation test cases
echo -e "\n=== Evaluation Tests ==="
grep -rn "eval\|reduce\|verify" \
  scala/sigmastate/src/test --include="*.scala" -B 2 -A 10 | head -200

# FROM RUST - often cleaner test structure
cd rust/sigma-rust
echo -e "\n=== Rust Tests ==="
find . -name "*.rs" -path "*/tests/*" | head -20
grep -rn "#\[test\]\|proptest!" --include="*.rs" -A 10 | head -200

# Find test data files
echo -e "\n=== Test Data Files ==="
find . -name "*.json" -o -name "*.hex" | head -20
```

CREATE SCRIPT: ~/ergotree-research/vectors/generate_vectors.sh
```bash
#!/bin/bash
# Generate test vectors by running Scala tests with output capture

cd ~/ergotree-research/scala/sigmastate

# Run specific test suites and capture output
sbt "testOnly sigmastate.serialization.*Spec" 2>&1 | tee ../vectors/serialization.log
sbt "testOnly sigmastate.eval.*Spec" 2>&1 | tee ../vectors/evaluation.log

# Parse logs to extract test vectors
# (This would need a custom parser based on test output format)
```

CREATE FILE: ~/ergotree-research/vectors/vectors.json
FORMAT:
```json
{
  "serialization": {
    "types": [
      {"input": {"type": "Int"}, "expected_hex": "04"},
      {"input": {"type": "Coll[Byte]"}, "expected_hex": "0e"}
    ],
    "values": [
      {"type": "Int", "value": 42, "expected_hex": "..."},
      {"type": "Long", "value": -1, "expected_hex": "..."}
    ],
    "expressions": [
      {"desc": "1 + 2", "hex": "...", "result": 3}
    ]
  },
  "evaluation": [
    {
      "name": "simple_addition",
      "ergotree_hex": "...",
      "context": {...},
      "expected_result": {"type": "Int", "value": 3},
      "expected_cost": 20
    }
  ],
  "errors": [
    {
      "name": "division_by_zero",
      "ergotree_hex": "...",
      "expected_error": "ArithmeticException"
    }
  ]
}
```
```

---
