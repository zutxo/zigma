

## Phase 6: Sigma Protocols

### Prompt 6.1: SigmaBoolean Tree

```
TASK: Implement SigmaBoolean tree representation

CONTEXT (From Ergo Core Developers):
"SigmaBoolean is the core of Ergo's authentication language.
It represents propositions that can be proven via Σ-protocols:
- ProveDlog: knowledge of discrete log
- ProveDHTuple: knowledge of DH tuple
- AND/OR/THRESHOLD: logical connectives

The tree is evaluated during script reduction to produce
either a SigmaBoolean (needs proof) or TrivialProp (always true/false)."

PREREQUISITE KNOWLEDGE:
- SigmaBoolean is a tree structure
- Leaves are crypto primitives (ProveDlog, ProveDHTuple)
- Internal nodes are connectives (AND, OR, THRESHOLD)
- TrivialProp represents known true/false
- See ErgoTree Spec Figure 13 (Section A.7)

CREATE FILE: src/sigma/sigma_tree.zig

IMPLEMENTATION:
```zig
/// SigmaBoolean tree node
pub const SigmaBoolean = union(enum) {
    /// Always true
    trivial_true: void,
    
    /// Always false
    trivial_false: void,
    
    /// Knowledge of discrete log: PK = g^x, prove knowledge of x
    prove_dlog: ProveDlog,
    
    /// Knowledge of DH tuple: prove knowledge of x where u = g^x and v = h^x
    prove_dh_tuple: ProveDHTuple,
    
    /// AND of children (all must be proven)
    cand: struct {
        children: []const *const SigmaBoolean,
    },
    
    /// OR of children (at least one must be proven)
    cor: struct {
        children: []const *const SigmaBoolean,
    },
    
    /// THRESHOLD: k of n children must be proven
    cthreshold: struct {
        k: u16,
        children: []const *const SigmaBoolean,
    },
    
    /// Check if this is a trivial proposition
    pub fn isTrivial(self: SigmaBoolean) bool {
        return self == .trivial_true or self == .trivial_false;
    }
    
    /// Check if trivially true
    pub fn isTrue(self: SigmaBoolean) bool {
        return self == .trivial_true;
    }
    
    /// Check if trivially false
    pub fn isFalse(self: SigmaBoolean) bool {
        return self == .trivial_false;
    }
    
    /// Reduce tree (simplify trivial branches)
    pub fn reduce(self: *const SigmaBoolean) SigmaBoolean {
        switch (self.*) {
            .trivial_true, .trivial_false, .prove_dlog, .prove_dh_tuple => return self.*,
            
            .cand => |and_node| {
                // If any child is false, result is false
                // If all children are true, result is true
                var all_true = true;
                for (and_node.children) |child| {
                    const reduced = child.reduce();
                    if (reduced.isFalse()) return .trivial_false;
                    if (!reduced.isTrue()) all_true = false;
                }
                if (all_true) return .trivial_true;
                return self.*;
            },
            
            .cor => |or_node| {
                // If any child is true, result is true
                // If all children are false, result is false
                var all_false = true;
                for (or_node.children) |child| {
                    const reduced = child.reduce();
                    if (reduced.isTrue()) return .trivial_true;
                    if (!reduced.isFalse()) all_false = false;
                }
                if (all_false) return .trivial_false;
                return self.*;
            },
            
            .cthreshold => |th| {
                // Count trivially true children
                var true_count: u16 = 0;
                var false_count: u16 = 0;
                for (th.children) |child| {
                    const reduced = child.reduce();
                    if (reduced.isTrue()) true_count += 1;
                    if (reduced.isFalse()) false_count += 1;
                }
                
                // If enough are true, whole thing is true
                if (true_count >= th.k) return .trivial_true;
                // If too many are false, whole thing is false
                if (false_count > th.children.len - th.k) return .trivial_false;
                
                return self.*;
            },
        }
    }
};

/// ProveDlog: prove knowledge of x where PK = g^x
pub const ProveDlog = struct {
    /// Public key (generator^secret)
    public_key: [33]u8,  // SEC1 compressed GroupElement
};

/// ProveDHTuple: prove knowledge of x where u = g^x and v = h^x
pub const ProveDHTuple = struct {
    g: [33]u8,  // Generator
    h: [33]u8,  // Another point
    u: [33]u8,  // g^x
    v: [33]u8,  // h^x
};
```

TESTS:
[ ] Create ProveDlog
[ ] Create ProveDHTuple
[ ] AND reduction with true child
[ ] AND reduction with false child
[ ] OR reduction with true child
[ ] THRESHOLD reduction
[ ] Nested tree reduction
```

### Prompt 6.2-6.5: Sigma Protocol Verification

```
TASK: Implement Σ-protocol proof verification

CONTEXT (From Cryptography Engineers):
"Σ-protocol verification is the final step of transaction validation.
The prover generates a proof tree matching the SigmaBoolean structure.
The verifier:
1. Reconstructs commitments from challenges and responses
2. Computes Fiat-Shamir challenge from message and commitments
3. Verifies challenge equals computed challenge

This is non-trivial cryptography. Study the Scala implementation
carefully and ensure constant-time operations where secrets are involved."

PREREQUISITE KNOWLEDGE:
- Schnorr protocol for ProveDlog
- Chaum-Pedersen for ProveDHTuple
- Fiat-Shamir transform for non-interactive proofs
- AND/OR proof composition
- See sigmastate/src/main/scala/sigmastate/interpreter/ProverInterpreter.scala

CREATE FILE: src/sigma/verifier.zig

KEY COMPONENTS:
1. UncheckedTree - proof tree matching SigmaBoolean structure
2. Challenge computation - Fiat-Shamir from message + commitments
3. Dlog verification - Schnorr signature check
4. DHT verification - Chaum-Pedersen check
5. AND/OR/THRESHOLD - composite verification

This is complex. Reference implementation carefully:
```bash
# Find verification logic
grep -rn "verify\|Verifier\|UncheckedTree" \
  --include="*.scala" -A 30 | head -500
```
```

---
