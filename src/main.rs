use rs_merkle::{
     algorithms::Sha256,
    MerkleTree,
    MerkleProof, Hasher
};

#[derive(Copy, Clone, Debug)]
/// Instruction enum
enum Instruction {
    Write,
    Read,
    Push,
    Pop,
}

#[derive(Copy, Clone, Debug)]
/// A trace record in the memory trace
struct DummyTraceRecord {
    instruction: Instruction,
    address: u64,
    time_log: u64,
    stack_depth: usize,
    value: u64,
}

#[derive(Clone, Debug)]
/// A struct holding all trace records sorted on time_log and their hashes
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

impl MemoryTraceOp for MemoryTrace {
    fn new() -> Self {
        Self { trace: (Vec::new()), hash_trace_sha256: (Vec::new()) }
    }

    fn record_bytes(&mut self, record: DummyTraceRecord) -> [u8; 8] {
        let mut buffer = [0u8; 8];
        // Assign each instruction (now encoded as constant big values) to the buffer
        match record.instruction {
            Instruction::Write => {
                let write_bytes = 0x65d2d12df4c07a2au64;
                buffer.copy_from_slice(&write_bytes.to_be_bytes());
            },
            Instruction::Read => {
                let read_bytes = 0xaa9d1ae3be49091eu64;
                buffer.copy_from_slice(&read_bytes.to_be_bytes());
            },
            Instruction::Pop => {
                let pop_bytes = 0x9d981645f1878deeu64;
                buffer.copy_from_slice(&pop_bytes.to_be_bytes());
            },
            Instruction::Push => {
                let push_bytes = 0x9b1ad71a2d961307u64;
                buffer.copy_from_slice(&push_bytes.to_be_bytes());
            },
        };

        // buffer <- buffer xor address
        let mut xor_result: Vec<u8> = buffer.iter().zip(record.address.to_be_bytes()).map(|(x, y)| x ^ y).collect();
        let temp: [u8; 8] = xor_result.try_into().unwrap();
        buffer.copy_from_slice(&temp);

        // buffer <- buffer xor time_log
        xor_result = buffer.iter().zip(record.time_log.to_be_bytes()).map(|(x, y)| x ^ y).collect();
        let temp: [u8; 8] = xor_result.try_into().unwrap();
        buffer.copy_from_slice(&temp);

        // buffer <- buffer xor stack_depth
        xor_result = buffer.iter().zip(record.stack_depth.to_be_bytes()).map(|(x, y)| x ^ y).collect();
        let temp: [u8; 8] = xor_result.try_into().unwrap();
        buffer.copy_from_slice(&temp);

        // buffer <- buffer xor value
        xor_result = buffer.iter().zip(record.value.to_be_bytes()).map(|(x, y)| x ^ y).collect();
        let temp: [u8; 8] = xor_result.try_into().unwrap();
        buffer.copy_from_slice(&temp);

        buffer
    }

    fn push_record(&mut self, record: DummyTraceRecord) {
        self.trace.push(record);
        let record_hash: [u8; 8] = self.record_bytes(record);
        self.hash_trace_sha256.push(Sha256::hash(&record_hash));
    }

    fn expose_trace(&mut self) -> Vec<DummyTraceRecord> {
        let result = &self.trace.clone();
        result.clone()
    }

    fn show_record_by_time_log(&mut self, time_log: usize) -> DummyTraceRecord {
        self.trace[time_log - 1]
    }

    fn expose_hashes(&mut self) -> Vec<[u8; 32]> {
        let result = &self.hash_trace_sha256.clone();
        result.clone()    
    }

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

    
}



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
