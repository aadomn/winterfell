# Aggregated Threshold Lamport+ Signatures

## Overview

This directory contains the design and implementation framework for **aggregated threshold Lamport+ signatures** using STARK proofs. This feature combines two existing capabilities:

1. **Signature Aggregation** (from `../aggregate/`): Verifying multiple signatures from different signers on different messages
2. **Threshold Signatures** (from `../threshold/`): Verifying k-of-n signatures where multiple parties sign the same message

The combined feature enables verification of multiple threshold signature groups in a single STARK proof, where each group can sign a different message.

## Status

**Current Status:** Design and Feasibility Study Complete

A comprehensive technical report is available in the repository root:
`../../AGGREGATE_THRESHOLD_TECHNICAL_REPORT.md`

### Key Findings from Feasibility Study

✅ **Feasible:** The combination is mathematically sound and cryptographically secure  
✅ **Proof Size:** Estimated 10-20% increase over threshold-only signatures  
✅ **Implementation Complexity:** Moderate (11-16 days for production-quality code)  
✅ **Security:** No new vulnerabilities introduced when properly implemented  

## Use Cases

### Multi-Organizational Approvals
- Multiple organizations, each with their own set of signers
- Each organization has threshold requirements (e.g., 5-of-7 approval)
- Each organization signs a different document/decision
- Single proof verifies all organizational approvals

**Example:**
```
Organization A (7 members, needs 5): Signs contract amendment A
Organization B (5 members, needs 3): Signs contract amendment B  
Organization C (9 members, needs 6): Signs contract amendment C
→ One STARK proof verifies all three threshold signatures
```

### Hierarchical Authorization
- Different security levels with different thresholds
- Zone admins (3-of-5) approve server config changes
- Zone operators (2-of-3) approve deployment parameters
- Zone auditors (5-of-7) approve compliance report
- Single proof for complete multi-zone authorization

### DAO Governance with Sub-Committees
- Main DAO has multiple committees
- Each committee votes on different proposals
- Each committee has threshold requirements
- Aggregate proof of all committee decisions

## Technical Design

### Trace Structure

**Trace Width:** 34 columns (vs 28 for threshold-only)

```
Columns [0-5]:   Secret key 1 hasher (Rescue state)
Columns [6-11]:  Secret key 2 hasher (Rescue state)
Columns [12-17]: Public key aggregation hasher
Columns [18-23]: Within-group Merkle path verifier
Columns [24-29]: Group-level Merkle path verifier  
Column  [30]:    Within-group Merkle index bit
Column  [31]:    Within-group index accumulator
Column  [32]:    Group-level Merkle index bit
Column  [33]:    Signature counter
```

### Public Inputs

```rust
pub struct PublicInputs {
    pub group_roots: Vec<[BaseElement; 2]>,        // Merkle root per group
    pub messages: Vec<[BaseElement; 2]>,            // One message per group
    pub num_signers_per_group: Vec<usize>,          // Group sizes
    pub thresholds: Vec<usize>,                     // k for each k-of-n group
    pub multi_group_root: [BaseElement; 2],         // Root of all group roots
}
```

### Key Design Elements

1. **Two-Level Merkle Trees:**
   - **Level 1:** Within each group, public keys are in a Merkle tree
   - **Level 2:** Group roots are aggregated into a master Merkle tree

2. **Message Binding:**
   - Each group is cryptographically bound to its specific message
   - Constraints prevent message confusion between groups

3. **Threshold Enforcement:**
   - Signature counter per group
   - Assertions verify threshold is met for each group
   - Cannot satisfy one group's threshold with another's signatures

4. **Group Isolation:**
   - Clear boundaries between groups in execution trace
   - Index accumulators reset at group transitions
   - Prevents signature leakage between groups

## Implementation Files

### Completed
- ✅ `signature.rs` - Data structures for multi-group public keys
- ✅ `README.md` - This file

### To Be Implemented
- ⏳ `air.rs` - AIR constraints for combined verification
- ⏳ `prover.rs` - Execution trace generation
- ⏳ `mod.rs` - Example interface and CLI integration

## Building Blocks from Existing Code

### From `../aggregate/`
- Message handling for multiple different messages
- Public key aggregation using hashing
- Parallel trace generation for multiple signatures

### From `../threshold/`
- Merkle tree structure for public key sets
- Threshold counting and verification
- Index tracking for Merkle path verification

### New Components Needed
- Second-level Merkle tree for group aggregation
- Group transition logic in trace generation
- Per-group threshold assertions
- Group-message binding constraints

## Performance Estimates

Based on the technical analysis:

### Proof Size
| Groups × Signers | Threshold-Only | Aggregate Threshold | Overhead |
|------------------|----------------|---------------------|----------|
| 4 × 4 (2-of-4)   | ~52 KB         | ~58-62 KB          | +12-19%  |
| 4 × 8 (5-of-8)   | ~58 KB         | ~65-70 KB          | +12-21%  |
| 8 × 8 (5-of-8)   | ~64 KB         | ~72-77 KB          | +12-20%  |

### Proving Time
Expected to scale linearly with total number of signatures, similar to existing implementations.

**Example:** 4 groups of 8 signers each → ~2-3 seconds proof generation time

### Verification Time
Expected to remain in the **1-2ms range** regardless of configuration (STARK verification is fast!)

## Security Considerations

### Guaranteed Properties
1. ✅ **Signature Unforgeability:** Cannot forge individual Lamport signatures
2. ✅ **Threshold Security:** Cannot satisfy threshold with fewer than k signatures
3. ✅ **Group Integrity:** Cannot mix signatures from different groups
4. ✅ **Message Binding:** Each group verifies against its specific message only

### Implementation Risks & Mitigations
- **Index Wrapping:** Ensure indices don't wrap between groups → Use assertions at boundaries
- **Counter Manipulation:** Protect signature counters → Use strict constraint checks
- **Message Confusion:** Prevent cross-group message use → Cryptographically bind groups to messages

## Next Steps for Implementation

### Phase 1: Proof of Concept (3-4 days)
1. Implement basic AIR with simplified constraints
2. Create minimal working example with 2 groups
3. Validate constraint correctness
4. Preliminary testing

### Phase 2: Full Implementation (4-5 days)
1. Complete AIR with all optimizations
2. Implement efficient trace generation
3. Add concurrent execution support
4. CLI integration

### Phase 3: Testing & Validation (3-4 days)
1. Comprehensive unit tests
2. Integration tests with various configurations
3. Security audit of constraints
4. Performance benchmarking

### Phase 4: Documentation (1-2 days)
1. Update main README
2. Add API documentation
3. Create usage examples
4. Document performance characteristics

## How to Use (When Implemented)

```rust
use examples::lamport::aggregate_threshold::*;

// Create multiple groups of signers
let group1 = PublicKeyGroup::new(keys_a, 5); // 5-of-7 threshold
let group2 = PublicKeyGroup::new(keys_b, 3); // 3-of-5 threshold
let group3 = PublicKeyGroup::new(keys_c, 6); // 6-of-9 threshold

// Create multi-group key
let multi_key = MultiGroupPublicKey::new(vec![group1, group2, group3]);

// Each group signs their own message
let msg1 = b"Approve budget amendment";
let msg2 = b"Approve deployment plan";
let msg3 = b"Approve security audit";

let sigs1 = collect_signatures(&group1, msg1); // 5 signatures
let sigs2 = collect_signatures(&group2, msg2); // 3 signatures
let sigs3 = collect_signatures(&group3, msg3); // 6 signatures

// Generate proof for all groups
let proof = prove_aggregate_threshold(
    &multi_key,
    &[msg1, msg2, msg3],
    &[sigs1, sigs2, sigs3]
);

// Verify with single proof
assert!(verify_aggregate_threshold(proof, &multi_key, &[msg1, msg2, msg3]));
```

## References

- **Technical Report:** `../../AGGREGATE_THRESHOLD_TECHNICAL_REPORT.md`
- **Paper:** https://eprint.iacr.org/2021/1048 (Aggregate and Threshold Lamport Signatures)
- **Aggregate Implementation:** `../aggregate/`
- **Threshold Implementation:** `../threshold/`

## Contributing

When implementing this feature, please ensure:

1. ✅ All constraints are proven sound
2. ✅ Comprehensive test coverage (>90%)
3. ✅ Security review by cryptography expert
4. ✅ Performance benchmarks documented
5. ✅ API documentation complete

## License

This project is MIT licensed. See the LICENSE file in the root directory.
