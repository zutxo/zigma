# ErgoTree Interpreter v3+ Specification & Conformance Checklist

**Document Version:** 1.0
**Date:** 2025-12-13
**Target: ErgoTree v3+** (Corresponds to EIP-50 / Ergo Protocol v6.0+)

## 1. Overview & Goals

This document specifies the new features, semantic changes, and conformance requirements for version 3 and later of the ErgoTree interpreter. The primary goals of this upgrade are to enhance scriptability, improve cryptographic capabilities, and provide more powerful tools for contract developers.

This specification is derived from the canonical `sigmastate-interpreter` (Scala) and `sigma-rust` reference implementations, along with associated research logs and test vectors.

## 2. Core Language & Type System Enhancements

### 2.1. New Primitive Types

#### 2.1.1. `SUnsignedBigInt`
- **Description:** A 256-bit unsigned integer type for handling large numbers without sign extension, critical for interfacing with hash functions and other cryptographic primitives.
- **Type Code:** `9` (Embeddable)
- **Serialization:** Follows the same VLQ-based serialization as `SBigInt`.
- **Key Operations:**
    - Standard arithmetic (`+`, `-`, `*`, `/`, `%`)
    - Bitwise operations (`|`, `&`, `^`, `~`, `<<`, `>>`)
    - Modular arithmetic: `plusMod`, `subtractMod`, `multiplyMod`, `modInverse`, `mod`.

#### 2.1.2. `SFunc`
- **Description:** A first-class function type, allowing functions to be created, passed as arguments, and returned from other functions. This enables higher-order programming constructs directly in ErgoScript.
- **Type Code:** `112` (Non-Embeddable)
- **Serialization Format:** `[0x70, len(tpeParams), <...tpeParams>, len(tDom), <...tDom>, serialize(tRange)]`
    - `tpeParams`: Type parameters for generic functions.
    - `tDom`: A collection of domain (argument) types.
    - `tRange`: The range (return) type.

### 2.2. Context & State Access Enhancements

#### 2.2.1. Cross-Input Variable Access
- **Opcode:** `GetVar` (0xE3)
- **Function Signature:** `CONTEXT.getVarFromInput[T](inputIndex: Short, varId: Byte): Option[T]`
- **Description:** Extends the existing context variable mechanism. Previously, scripts could only access variables from the `SELF` box's context extension. This feature allows a script to access context variables from *any* input box in the transaction by providing its index. This is a major enhancement for multi-stage contracts.
- **Conformance Requirement:**
    - Must correctly retrieve a variable from the context extension of the box at `INPUTS(inputIndex)`.
    - Must return `None` if `inputIndex` is out of bounds.
    - Must return `None` if the variable `varId` does not exist in the target context extension.
    - Must fail the script if the type `T` does not match the deserialized type of the variable.

## 3. New Operations & Semantics

### 3.1. General Purpose Opcodes

| Opcode | Name | Hex | Category | Signature | Description |
|---|---|---|---|---|---|
| `SubstConstants` | Substitute Constants | 0x74 | Transform | `(script: Coll[Byte], pos: Coll[Int], new: Coll[T]) -> Coll[Byte]` | Replaces constants in a serialized script with new values. Essential for script templating. |
| `BitInversion` | Bitwise Inversion | 0xF1 | Bitwise | `~T -> T` | Performs a bitwise NOT on a numeric type. |
| `BitOr` | Bitwise OR | 0xF2 | Bitwise | `(T, T) -> T` | Performs a bitwise OR on two numeric types. |
| `BitAnd` | Bitwise AND | 0xF3 | Bitwise | `(T, T) -> T` | Performs a bitwise AND on two numeric types. |
| `BitXor` | Bitwise XOR | 0xF5 | Bitwise | `(T, T) -> T` | Performs a bitwise XOR on two numeric types. |
| `BitShiftRight`| Arithmetic Shift Right | 0xF6 | Bitwise | `(T, Int) -> T` | `>>` with sign extension. |
| `BitShiftLeft` | Logical Shift Left | 0xF7 | Bitwise | `(T, Int) -> T` | `<<`. |
| `BitShiftRightZeroed` | Logical Shift Right | 0xF8 | Bitwise | `(T, Int) -> T` | `>>>` without sign extension. |

### 3.2. Modular Arithmetic Opcodes (for `SBigInt` and `SUnsignedBigInt`)

| Opcode | Name | Hex | Category | Signature | Description |
|---|---|---|---|---|---|
| `ModQ` | Modulo Group Order | 0xE7 | Crypto | `BigInt -> BigInt` | Reduces a `BigInt` modulo the secp256k1 group order `q`. |
| `PlusModQ` | Modular Addition | 0xE8 | Crypto | `(BigInt, BigInt) -> BigInt` | `(a + b) mod q`. |
| `MinusModQ` | Modular Subtraction | 0xE9 | Crypto | `(BigInt, BigInt) -> BigInt` | `(a - b) mod q`. |

### 3.3. Script Execution Opcodes

These opcodes allow for dynamic execution of scripts stored on-chain, enabling powerful composability patterns.

| Function | Description |
|---|---|
| `executeFromVar[T](id: Byte): T` | Executes a script from a context variable. |
| `executeFromSelfReg[T](id: Int): T` | Executes a script from one of `SELF`'s registers. |
| `executeFromSelfRegWithDefault[T](id: Int, default: T): T` | Executes a script from a register, with a fallback value. |

## 4. Conformance Checklist

An interpreter is v3+ compliant if and only if it passes all specified test vectors and implements the following features according to the reference semantics.

### 4.1. Type System Conformance

- [ ] **TC-TYPE-001:** Implement `SUnsignedBigInt` (Type Code 9).
- [ ] **TC-TYPE-002:** `SUnsignedBigInt` must pass all relevant test vectors in `vectors/evaluation/arithmetic.json` for overflow and boundary conditions.
- [ ] **TC-TYPE-003:** Implement `SFunc` (Type Code 112).
- [ ] **TC-TYPE-004:** Implement correct serialization and deserialization for `SFunc` with varying numbers of type parameters and domain/range types, as specified in `specs/TYPE_SYSTEM.md`.
- [ ] **TC-TYPE-005:** Correctly handle `upcast` and `downcast` operations between all numeric types (`Byte` < `Short` < `Int` < `Long` < `BigInt` < `UnsignedBigInt`).

### 4.2. Opcode & Semantics Conformance

#### 4.2.1. State Access
- [ ] **TC-OP-001:** `GetVar` (0xE3) must correctly access context variables from other inputs in the transaction, as specified by `getVarFromInput`.
- [ ] **TC-OP-002:** `GetVar` must pass all test vectors involving cross-input context lookups.

#### 4.2.2. Bitwise Operations
- [ ] **TC-OP-003:** Implement `BitInversion` (0xF1) for all numeric types.
- [ ] **TC-OP-004:** Implement `BitOr` (0xF2), `BitAnd` (0xF3), `BitXor` (0xF5) for all numeric types.
- [ ] **TC-OP-005:** Implement `BitShiftRight` (0xF6), `BitShiftLeft` (0xF7), `BitShiftRightZeroed` (0xF8) for all numeric types.
- [ ] **TC-OP-006:** All bitwise operations must pass the relevant test vectors in `vectors/evaluation/arithmetic.json` and `logical.json`.

#### 4.2.3. Modular Arithmetic
- [ ] **TC-OP-007:** Implement `ModQ` (0xE7).
- [ ] **TC-OP-008:** Implement `PlusModQ` (0xE8).
- [ ] **TC-OP-009:** Implement `MinusModQ` (0xE9).
- [ ] **TC-OP-010:** All modular arithmetic operations must pass the relevant test vectors in `vectors/crypto/*`.

#### 4.2.4. Script Execution & Templating
- [ ] **TC-OP-011:** Implement `SubstConstants` (0x74). It must fail if the type of the new value does not match the type of the constant being replaced.
- [ ] **TC-OP-012:** Implement `executeFromVar`, `executeFromSelfReg`, and `executeFromSelfRegWithDefault`. The execution must happen within the *current* context, not the context where the script was defined.

### 4.3. Costing Conformance

- [ ] **TC-COST-001:** The interpreter must distinguish between pre- and post-v5.0 (`isJitActivated`) contexts and apply the correct `AOT_COSTS` or `JIT_COSTS`.
- [ ] **TC-COST-002:** Costs for new v3+ opcodes must be defined and applied.
- [ ] **TC-COST-003:** Costs for size-dependent operations (e.g., `MapCollection`, `Fold`, `CalcBlake2b256`) must be calculated dynamically based on the size of the input data, matching the `PerItemCost` model from the reference implementation.

### 4.4. Test Vector Conformance

A fully compliant interpreter **must** pass 100% of the test cases defined in the `vectors/` directory.

| Category | File | Required |
|---|---|:---:|
| Common | `common.json` | ✔ |
| Serialization | `serialization/constants.json` | ✔ |
| | `serialization/collections.json` | ✔ |
| | `serialization/options.json` | ✔ |
| | `serialization/tuples.json` | ✔ |
| Evaluation | `evaluation/arithmetic.json` | ✔ |
| | `evaluation/comparison.json` | ✔ |
| | `evaluation/logical.json` | ✔ |
| Crypto | `crypto/blake2b256.json` | ✔ |
| | `crypto/signing.json` | ✔ |
| Cost Model | `cost_model/*` | ✔ |

The conformance runner located in `conformance/` should be used as the final arbiter of compliance.

---
**End of Specification**
