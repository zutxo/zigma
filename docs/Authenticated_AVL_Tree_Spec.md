# Authenticated AVL+ Tree: Complete Specification

**Document Version:** 1.0
**Date:** 2025-12-13

## 1. Overview

Ergo's state is authenticated using a dynamically updatable authenticated dictionary built upon an AVL+ Tree. This allows for efficient, verifiable proofs of state transitions (UTXO set changes) without requiring a verifier to hold the entire state.

An "authenticated" tree is one where the digest (hash) of the root node depends on the digest of all its children, recursively down to the leaves. Any change to a leaf node will alter the digest of its parent, which alters its grandparent, and so on, ultimately changing the root digest.

The verifier, who only knows the root digest, can be convinced that an operation (e.g., an `insert`) was performed correctly by being given a **proof**. The proof contains the node digests along the path of the operation, allowing the verifier to re-calculate the new root digest and check that it matches the expected result.

This document provides a complete specification for verifying these operations.

## 2. Data Structures

### 2.1. `AvlTreeData` (On-Chain Representation)

This is the compact, on-chain representation of an entire authenticated tree.

| Field | Type | Description |
|---|---|---|
| `digest` | `Coll[Byte]` | The 33-byte root digest of the tree. It is composed of the 32-byte root node's label (hash) concatenated with a 1-byte tree height. |
| `treeFlags`| `Byte` | A single byte encoding enabled operations: `isInsertAllowed` (0x01), `isUpdateAllowed` (0x02), `isRemoveAllowed` (0x04). |
| `keyLength` | `Int` | The fixed length of all keys in the tree. |
| `valueLengthOpt`| `Option[Int]`| An optional fixed length for all values in the tree. If `None`, values can have variable lengths. |

### 2.2. Node Representations (Logical)

During verification, nodes are reconstructed from the proof. They are not stored permanently by the verifier.

#### 2.2.1. `LeafNode`
Represents a terminal node in the tree containing a key-value pair.

| Field | Type | Description |
|---|---|---|
| `key` | `Coll[Byte]` | The key of the element. |
| `value` | `Coll[Byte]` | The value of the element. |
| `next_leaf_key` | `Coll[Byte]` | The key of the next leaf in an in-order traversal. This allows proving non-existence of a key. |
| **Label (Digest)** | `Coll[Byte]` | `blake2b256(key ++ value ++ next_leaf_key)` |

#### 2.2.2. `InternalNode`
Represents a non-terminal node that connects two sub-trees.

| Field | Type | Description |
|---|---|---|
| `left_child_label` | `Coll[Byte]` | The 32-byte digest of the left child node. |
| `right_child_label`| `Coll[Byte]` | The 32-byte digest of the right child node. |
| `balance` | `Byte` | The balance factor: `Height(right) - Height(left)`. Valid values are -1, 0, or 1 for a balanced tree. |
| `height` | `Byte` | The height of the subtree rooted at this node. `1 + max(Height(left), Height(right))`. |
| **Label (Digest)** | `Coll[Byte]` | `blake2b256(left_child_label ++ right_child_label ++ [balance] ++ [height])` |

### 2.3. Proof Structure

A proof is a serialized byte array that allows the verifier to reconstruct the parts of the tree necessary to validate an operation.

1.  **Post-Order Traversal:** The proof contains all the nodes on the lookup path(s) and their siblings, serialized in post-order.
    - A leaf is serialized as: `[LEAF_FLAG] ++ key ++ next_leaf_key ++ [value_len (if variable)] ++ value`.
    - An internal node is serialized as: `[balance_byte]`, where the node itself is implicitly defined by its two children already processed in the post-order traversal.
    - A non-visited node (a sibling needed for a parent hash calculation but not on the direct path) is serialized as: `[LABEL_FLAG] ++ label`.
2.  **End of Tree Marker:** A special byte `END_OF_TREE_IN_PACKAGED_PROOF` marks the end of the node data.
3.  **Directions:** A bit-packed string that guides the verifier's traversal down the tree for each operation. `1` means traverse left, `0` means traverse right.

## 3. Core Algorithms

The verifier begins with a `starting_digest` and a `proof`. It first reconstructs the pre-operation tree root from the proof and verifies its digest matches `starting_digest`. Then, for each operation, it simulates the modification and re-calculates a new root digest.

### 3.1. Read Operation: `get(key, proof)`

This is the simplest operation.

1.  **Traversal:** Starting at the reconstructed root, consume one bit from the proof's `directions` stream.
    - If the bit is `1`, descend to the left child.
    - If the bit is `0`, descend to the right child.
2.  **Verification:** At each step, verify that the hash of the child node matches the `left_child_label` or `right_child_label` stored in the parent.
3.  **Termination:** The traversal ends at a `LeafNode`.
4.  **Result:**
    - If `key == leaf.key`, the key exists. Return `Some(leaf.value)`.
    - If `key != leaf.key`, the verifier checks that `leaf.key < key < leaf.next_leaf_key`. If this holds, the key does not exist. Return `None`.
    - If neither of the above is true, the proof is invalid.

### 3.2. Write Operation: `insert(key, value, proof)`

Insertion is simulated via a recursive helper function, `modify_helper`.

1.  **Traversal:** Descend the tree as in `get`, guided by the proof's `directions`.
2.  **Action at Leaf:** When a `LeafNode` is reached:
    - The verifier must prove non-existence, so `key` must be between `leaf.key` and `leaf.next_leaf_key`.
    - A new `InternalNode` is created with the old leaf on one side and a new leaf (for the inserted key-value pair) on the other.
    - This modification increases the subtree height by 1. A `(height_increased = true)` flag is returned up the recursive stack.
3.  **Rebalancing on Ascent:** As the recursion unwinds, each parent node receives the new digest of its modified child and the `height_increased` flag.
    - The parent's `balance` factor is updated.
    - **If `height_increased` is true and the balance factor becomes -2 or +2, a rotation is triggered.** The specific rotation depends on the balance factor of the child node.

### 3.3. Write Operation: `remove(key, proof)`

Removal is the most complex operation, performed in two conceptual passes.

#### Pass 1: Find and Mark for Deletion (`modify_helper`)
1.  **Traversal:** Descend the tree, guided by the `directions` stream, to find the leaf corresponding to `key`.
2.  **Marking:** When the leaf is found (`key == leaf.key`), instead of modifying the tree, the function returns a `to_delete = true` flag up the recursive stack. This pass confirms the key's existence and identifies the path.

#### Pass 2: Perform Deletion and Rebalance (`delete_helper`)
1.  **Re-Traversal:** The `delete_helper` function is called on the root. It re-descends the same path taken in Pass 1, guided by replaying the proof directions (`replay_comparison`).
2.  **Deletion Logic:**
    - **Case 1 (Simple): Node has a leaf child.** The target node is removed and replaced by its other child. If a leaf was removed, the `next_leaf_key` of its predecessor must be updated by recursively finding the predecessor and replacing its `next_leaf_key`.
    - **Case 2 (Complex): Node has two internal children.**
        a. The algorithm does not delete this node directly. Instead, it initiates a `delete_max` operation on the node's **left subtree**.
        b. `delete_helper` is called recursively on the left subtree with `delete_max = true`. It descends to the rightmost leaf of that subtree.
        c. This max leaf is removed, and its `key` and `value` are saved.
        d. Upon returning to the original node, its key and value are **replaced** with the saved key/value from the max leaf that was just removed.
        e. Additionally, the `next_leaf_key` of the *newly* replaced node must be propagated to the rightmost leaf of its left subtree to maintain list integrity.
3.  **Rebalancing on Ascent:** As the recursion unwinds from the deletion, if a subtree's height has *decreased*, it can cause an imbalance (`balance` becomes -2 or +2). This triggers rebalancing rotations, which are symmetric to the insertion rotations.

## 4. Rebalancing and Rotations (Complete Algorithms)

This is the core of maintaining the AVL property. Balance is `Height(right) - Height(left)`.

### 4.1. Single Right Rotation
- **Trigger:** An insertion into the *left* subtree of the *left child* of a node `k2` (which was balanced) causes its balance factor to become -2.
- **Condition:** `balance(k2) == -2` and `balance(k1) == -1`, where `k1` is the left child of `k2`.
- **Algorithm:**
  1. `k1` becomes the new root.
  2. `k2` becomes the right child of `k1`.
  3. The right child of `k1` (subtree `Y`) becomes the new left child of `k2`.
  4. **Update Balances:** `balance(k1) = 0`, `balance(k2) = 0`.
  5. **Update Heights:** Recalculate from the new children.

  ```
      k2 (-2)           k1 (0)
     /  \             /   \
    k1 (-1)  Z   -->   X     k2 (0)
   /  \
  X    Y                 Y     Z
  ```

### 4.2. Single Left Rotation
- **Trigger:** An insertion into the *right* subtree of the *right child* of a node `k1` (which was balanced) causes its balance factor to become +2.
- **Condition:** `balance(k1) == +2` and `balance(k2) == +1`, where `k2` is the right child of `k1`.
- **Algorithm:**
  1. `k2` becomes the new root.
  2. `k1` becomes the left child of `k2`.
  3. The left child of `k2` (subtree `Y`) becomes the new right child of `k1`.
  4. **Update Balances:** `balance(k1) = 0`, `balance(k2) = 0`.
  5. **Update Heights:** Recalculate from the new children.

  ```
    k1 (+2)             k2 (0)
   /  \               /   \
  X    k2 (+1)  -->  k1 (0)   Z
      /  \
     Y    Z         X     Y
  ```

### 4.3. Double Left-Right Rotation
- **Trigger:** An insertion into the *right* subtree of the *left child* of `k3` causes its balance to become -2.
- **Condition:** `balance(k3) == -2` and `balance(k1) == +1`, where `k1` is the left child of `k3`.
- **Algorithm:** This is a Left Rotation on `k1` followed by a Right Rotation on `k3`.
  1. `k2` (the right child of `k1`) becomes the new root.
  2. A new `k1` is formed from the old `k1` and `k2`'s left child.
  3. A new `k3` is formed from the old `k3` and `k2`'s right child.
  4. `k2`'s children become the new `k1` and `k3`.
  5. **Update Balances:** The new balances for `k1` and `k3` depend on the original balance of `k2`.
     - If `balance(k2_orig) == 0`: `balance(k1_new)=0`, `balance(k3_new)=0`.
     - If `balance(k2_orig) == -1`: `balance(k1_new)=0`, `balance(k3_new)=+1`.
     - If `balance(k2_orig) == +1`: `balance(k1_new)=-1`, `balance(k3_new)=0`.
     - The new root `k2` will always have a balance of `0`.

  ```
      k3 (-2)                k2 (0)
     /  \                  /    \
    k1 (+1)  D            k1      k3
   /  \        -->      / \     / \
  A    k2              A   B   C   D
      / \
     B   C
  ```

### 4.4. Double Right-Left Rotation
- **Trigger:** An insertion into the *left* subtree of the *right child* of `k1` causes its balance to become +2.
- **Condition:** `balance(k1) == +2` and `balance(k3) == -1`, where `k3` is the right child of `k1`.
- **Algorithm:** This is a Right Rotation on `k3` followed by a Left Rotation on `k1`. It is the mirror image of the Left-Right rotation.
  1. `k2` (the left child of `k3`) becomes the new root.
  2. **Update Balances:** Similar logic to the Left-Right rotation, but mirrored.
     - If `balance(k2_orig) == 0`: `balance(k1_new)=0`, `balance(k3_new)=0`.
     - If `balance(k2_orig) == +1`: `balance(k1_new)=0`, `balance(k3_new)=-1`.
     - If `balance(k2_orig) == -1`: `balance(k1_new)=+1`, `balance(k3_new)=0`.
     - The new root `k2` will always have a balance of `0`.

---
**End of Specification**
