//! Chunked gated proofs with the reference hash-chain recursion boundary.

use magnetar_recursion::{
    AggregatedProof, ChunkPlan, ChunkProof, HashChainRecursion, RecursionBackend,
};
use magnetar_spec::Trace;

use crate::gated_bundle::{prove_gated_bundle_from_trace, P3GatedBundle};
use crate::RuntimeError;

#[derive(Clone, Debug)]
pub struct GatedChunkProof {
    pub index: usize,
    pub bundle: P3GatedBundle,
    pub recursion: ChunkProof,
}

#[derive(Clone, Debug)]
pub struct GatedChunkedProof {
    pub chunk_size: usize,
    pub chunks: Vec<GatedChunkProof>,
    pub aggregated: AggregatedProof,
}

fn digest_bundle(bundle: &P3GatedBundle) -> [u8; 32] {
    let cpu = bincode::serialize(&bundle.cpu).unwrap_or_default();
    let register = bincode::serialize(&bundle.register).unwrap_or_default();
    let aux = bincode::serialize(&bundle.aux).unwrap_or_default();
    let claims = bincode::serialize(&bundle.claims).unwrap_or_default();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&cpu);
    bytes.extend_from_slice(&register);
    bytes.extend_from_slice(&aux);
    bytes.extend_from_slice(&claims);
    magnetar_transcript::sha256(&bytes)
}

pub fn prove_gated_chunks(
    trace: &Trace,
    width: usize,
    chunk_size: usize,
) -> Result<GatedChunkedProof, RuntimeError> {
    let plan = ChunkPlan::new(trace.len(), chunk_size)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let mut chunks = Vec::new();
    for range in plan.ranges() {
        let mut chunk_trace = trace.clone();
        chunk_trace.rows = trace.rows[range.start..range.end].to_vec();
        if crate::simd_full::gated_rows_from_trace(&chunk_trace, width).is_err() {
            continue;
        }
        let bundle = prove_gated_bundle_from_trace(
            &chunk_trace,
            width,
            &magnetar_proof::DirectBitPcs::new(magnetar_pcs::P3SharedPcs::new(
                100,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )),
        )
        .map_err(|error| RuntimeError::Proof(format!("chunk {}: {error}", range.index)))?;
        let digest = digest_bundle(&bundle);
        chunks.push(GatedChunkProof {
            index: range.index,
            recursion: ChunkProof::new(range.index, range.len() as u64, digest, digest),
            bundle,
        });
    }
    let recursion_proofs = chunks
        .iter()
        .map(|chunk| chunk.recursion.clone())
        .collect::<Vec<_>>();
    let aggregated = HashChainRecursion
        .aggregate(&recursion_proofs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(GatedChunkedProof {
        chunk_size,
        chunks,
        aggregated,
    })
}

pub fn verify_gated_chunks(
    trace: &Trace,
    width: usize,
    proof: &GatedChunkedProof,
) -> Result<(), RuntimeError> {
    let plan = ChunkPlan::new(trace.len(), proof.chunk_size)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let ranges = plan.ranges();
    for chunk in &proof.chunks {
        let mut chunk_trace = trace.clone();
        let range = ranges
            .get(chunk.index)
            .ok_or_else(|| RuntimeError::Proof("chunk index out of range".into()))?;
        chunk_trace.rows = trace.rows[range.start..range.end].to_vec();
        let backend = magnetar_proof::DirectBitPcs::new(magnetar_pcs::P3SharedPcs::new(
            100,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
        crate::gated_bundle::verify_gated_bundle_from_trace(
            &chunk_trace,
            width,
            &chunk.bundle,
            &backend,
        )?;
        let digest = digest_bundle(&chunk.bundle);
        if digest != chunk.recursion.state_digest {
            return Err(RuntimeError::Proof("chunk digest mismatch".into()));
        }
    }
    let recursion_proofs = proof
        .chunks
        .iter()
        .map(|chunk| chunk.recursion.clone())
        .collect::<Vec<_>>();
    HashChainRecursion
        .verify(&proof.aggregated)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    let expected = HashChainRecursion
        .aggregate(&recursion_proofs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    if expected != proof.aggregated {
        return Err(RuntimeError::Proof("chunk aggregation mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn gated_chunks_aggregate() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Add,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Xor,
                    rd: 2,
                    rs1: 1,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Slli,
                    rd: 3,
                    rs1: 2,
                    rs2: 0,
                    imm: 0,
                    shamt: 2,
                }
                .encode(),
                Instruction {
                    op: Op::Slli,
                    rd: 4,
                    rs1: 3,
                    rs2: 0,
                    imm: 0,
                    shamt: 1,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        let trace = execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 100,
            },
        )
        .unwrap();
        let proof = prove_gated_chunks(&trace, 8, 2).unwrap();
        assert_eq!(proof.chunks.len(), 2);
        verify_gated_chunks(&trace, 8, &proof).unwrap();
    }
}
