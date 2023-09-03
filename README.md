# Memory trace structure

The memory trace consists of the trace records according to the time log :

$Instruction (address, time\_log, stack\_depth, value)$

+ $Instruction$ : can be WRITE, READ, PUSH or POP
+ $address$ : the address in the memory (`u256, u64, u32`).
+ $time\_log$ : fixed type `u64`.
+ $stack\_depth$ : fixed type `usize`.
+ $value$ : the value of the memory at the address (`u256, u64, u32`).

# Merkle Tree and Merkle Proof

```text=
                        --------
                        | Root |
              ----------------------- 
             |                      |
        -----------           ----------- 
        |    HAB  |          |   HCD   |
        -----------           -----------
       |          |          |          |
    -------    -------    -------    -------
    | HA  |    | HB  |    | HC  |    | HD  |
    -------    -------    -------    -------
      A          B          C          D
```

The leaves of the tree contains hashes of private elements, and the non-leaf node's hash is $H(xy) = H(x) \oplus H(y)$

In the example, to prove the existence of B, then the proof is $H_A, H_{CD}$. Together with $H_B$, the Verifier can calculate and expect the original and the calculated Merkle proof is the same.

$$H_B\;proof:=\{H_A, H_{CD}\}$$

# Idea for Merkle Proof

## Hash the record

Hash all contents in a memory trace's record to put in the Merkle tree.

2 possible ways :

+ Convert all content in to bytes, then concatenate them and calculate the hash.
$$H(trace\_record_{i}) = H(Instruction + address + time\_log + stack\_depth + value)$$

Can be easily implemented, the hash of instruction can be `H(b"WRITE")` or some constant value representing WRITE.

+ Convert all content in to bytes, XOR them and calculate the hash (I use this method in my implementation)

$$H(trace\_record_{i}) = H(Instruction \oplus address \oplus time\_log \oplus stack\_depth \oplus value)$$

Need a fixed length of each operator to perform XOR.

## Build up the Merkle Tree and proof idea

After we got the hashes of all records in the memory trace, we put them in the leaves of the Merkle Tree. Since the memory initial state is all $0$ in every cell, the state of the memory at the time $t$ is the set of all records in the memory trace up to the time $t$.

Therefore, to prove the memory state at the time $t$, we need to prove all $t$ leaves in the Merkle Tree.

## Implementation idea

### 1. Build functions to hash the records in the memory trace.

First, build struct `DummyTraceRecord`

```Rust
enum Instruction {
    Write = 1,
    Read = 2,
    Push = 3,
    Pop = 4,
}

struct DummyTraceRecord {
    instruction: Instruction,
    address: u64,
    time_log: u64,
    stack_depth: usize,
    value: u64,
}
```

In order to do XOR the component of the record, we need to evaluate the `Instruction` enum element. In case of all other components (address, time_log, ...) are small values, we can evaluate the enum elements as big fixed values.

Next, we define the struct `MemoryTrace` and its utilities:

```Rust=
struct MemoryTrace {
    trace: Vec<DummyTraceRecord>,
    hash_trace_sha256: Vec<[u8; 32]>,
}
trait MemoryTraceOp {
    fn new() -> Self;
    /// Push a record after RAM program execution
    fn push_record(&mut self, record: DummyTraceRecord);
    /// Show the trace record at time t
    fn show_record_by_time_log(&mut self, time_log: usize) -> DummyTraceRecord;
    /// Get the memory trace
    fn expose_trace(&mut self) -> Vec<DummyTraceRecord>;
    /// Get the records' hashes
    fn expose_hashes(&mut self) -> Vec<[u8; 32]>;
    /// Convert the record to bytes array using XOR
    fn record_bytes(&mut self, record: DummyTraceRecord) -> [u8; 8];
    /// Create Merkle proof and return Merkle root to prove the memory state at time t
    fn create_merkle_proof(&mut self, time_log: u64) -> (Vec<u8>, [u8; 32]);
    /// Verify the proof for the memory state at the time t
    fn merkle_verify_proof(&mut self, merkle_root: [u8; 32], merkle_proof: Vec<u8>, time_log: u64) -> bool;
}
```

The value we use to hash in my implementation is : 

$$H(trace\_record_{i}) = H(Instruction \oplus address \oplus time\_log \oplus stack\_depth \oplus value)$$

and I will use the hash function SHA256 in my implementation.

The method `record_bytes` return the XOR result of all components of a record. Then we push its hash right after we push the record to the memory trace : 

```Rust=
    fn push_record(&mut self, record: DummyTraceRecord) {
        self.trace.push(record);
        let record_hash: [u8; 8] = self.record_bytes(record);
        self.hash_trace_sha256.push(Sha256::hash(&record_hash));
    }
```

To build up the Merkle Tree, I use the crate `rs_merkle`, which, in documentation, is the most advanced Merkle tree library for Rust.

Finally, I implement the last methods `create_merkle_proof` and `merkle_verify_proof`

```Rust=
    fn create_merkle_proof(&mut self, time_log: u64) -> (Vec<u8>, [u8; 32]) {
        let hashes: Vec<[u8; 32]> = self.expose_hashes();
        let indices_to_prove: Vec<usize> = Vec::from_iter(0..time_log as usize);
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&hashes);
        let merkle_proof = merkle_tree.proof(&indices_to_prove);
        let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").unwrap();
        // Serialize proof to pass it to the client
        let proof_bytes = merkle_proof.to_bytes();
        (proof_bytes, merkle_root) 
    }

    fn merkle_verify_proof(&mut self, merkle_root: [u8; 32], merkle_proof: Vec<u8>, time_log: u64) -> bool {
        let hashes = self.expose_hashes();
        let indices_to_prove: Vec<usize> = Vec::from_iter(0..time_log as usize);
        let leaves_to_prove = hashes.get(0..time_log as usize).ok_or("can't get leaves to prove").unwrap();
        let proof = MerkleProof::<Sha256>::try_from(merkle_proof).unwrap();
        proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, hashes.len())
    }
```

This is my test in function main :

```Rust=
fn main() {

    // Create the memory trace
    let mut mem_trace = MemoryTrace::new();

    // Push records, which are results after each execution line
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Write, address: 3u64, time_log: 1u64, stack_depth: 0usize, value: 0x2345u64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Read, address: 8u64, time_log: 2u64, stack_depth: 0usize, value: 0xffu64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Write, address: 16u64, time_log: 3u64, stack_depth: 0usize, value: 0xaau64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Read, address: 24u64, time_log: 4u64, stack_depth: 0usize, value: 0xccu64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Push, address: 0xffu64, time_log: 5u64, stack_depth: 1usize, value: 0x502u64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Push, address: 0xffu64, time_log: 6u64, stack_depth: 2usize, value: 0x205u64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Pop, address: 0xffu64, time_log: 7u64, stack_depth: 1usize, value: 0x205u64 });
    mem_trace.push_record(DummyTraceRecord { instruction: Instruction::Pop, address: 0xffu64, time_log: 8u64, stack_depth: 0usize, value: 0x502u64 });

    // We want to prove the memory state at time 7
    let (merkle_proof, merkle_root) = mem_trace.create_merkle_proof(6);
    assert_eq!(mem_trace.merkle_verify_proof(merkle_root, merkle_proof, 6), true);

}
```



