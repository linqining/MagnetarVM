//! Shared-matrix SIMD proof for the uniform load/store row schema.

use magnetar_constraint::F2_128;
use magnetar_cpu::simd::{uniform_memory_row_layout, UniformMemoryRowLayout};
use magnetar_cpu::CpuVarKind;
use magnetar_pcs::{P3BinaryPcs, P3Commitment, P3Opening};
use magnetar_proof::spartan::MatrixPart;
use magnetar_proof::{
    prove_spartan_with_matrices, verify_spartan_with_matrices, witness_vector, SharedBlockMatrix,
    SpartanProof,
};

use crate::RuntimeError;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SimdMemoryProof {
    pub width: usize,
    pub cycles: usize,
    pub proof: SpartanProof<P3Commitment, P3Opening>,
}

fn matrices(
    layout: &UniformMemoryRowLayout,
    cycles: usize,
) -> Result<(SharedBlockMatrix, SharedBlockMatrix, SharedBlockMatrix), RuntimeError> {
    if cycles == 0 || !cycles.is_power_of_two() {
        return Err(RuntimeError::Proof(
            "SIMD memory cycle count must be a nonzero power of two".into(),
        ));
    }
    let base_cols = (layout.num_vars + 1).next_power_of_two();
    let groups = layout.var_groups();
    let pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::Pc)
        .ok_or_else(|| RuntimeError::Proof("memory row has no PC group".into()))?;
    let next_pc = groups
        .iter()
        .find(|group| group.kind == CpuVarKind::NextPc)
        .ok_or_else(|| RuntimeError::Proof("memory row has no NextPc group".into()))?;
    let mut extra_a = Vec::new();
    let mut extra_b = Vec::new();
    let mut extra_c = Vec::new();
    for instance in 0..cycles.saturating_sub(1) {
        for bit in 0..pc.vars.len() {
            extra_a.push(vec![(
                instance * base_cols + next_pc.vars[bit],
                F2_128::from(1u64),
            )]);
            extra_b.push(vec![(
                instance * base_cols + layout.num_vars,
                F2_128::from(1u64),
            )]);
            extra_c.push(vec![(
                (instance + 1) * base_cols + pc.vars[bit],
                F2_128::from(1u64),
            )]);
        }
    }
    let a = SharedBlockMatrix::from_system(&layout.system, MatrixPart::A, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_a);
    let b = SharedBlockMatrix::from_system(&layout.system, MatrixPart::B, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_b);
    let c = SharedBlockMatrix::from_system(&layout.system, MatrixPart::C, cycles)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?
        .with_extra_rows(extra_c);
    Ok((a, b, c))
}

pub fn prove_simd_memory_rows(
    width: usize,
    rows: &[magnetar_constraint::Witness],
) -> Result<SimdMemoryProof, RuntimeError> {
    if rows.is_empty() {
        return Err(RuntimeError::Proof("empty SIMD memory batch".into()));
    }
    let (_system, layout) = uniform_memory_row_layout(width);
    let (a, b, c) = matrices(&layout, rows.len())?;
    let mut z = Vec::new();
    for row in rows {
        z.extend(
            witness_vector(&layout.system, row)
                .map_err(|error| RuntimeError::Proof(error.to_string()))?,
        );
    }
    if z.len() != a.cols() {
        return Err(RuntimeError::Proof(
            "SIMD memory witness width mismatch".into(),
        ));
    }
    let pcs = P3BinaryPcs::new(100);
    let proof = prove_spartan_with_matrices(&z, &a, &b, &c, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))?;
    Ok(SimdMemoryProof {
        width,
        cycles: rows.len(),
        proof,
    })
}

pub fn verify_simd_memory_rows(proof: &SimdMemoryProof) -> Result<(), RuntimeError> {
    let (_system, layout) = uniform_memory_row_layout(proof.width);
    let (a, b, c) = matrices(&layout, proof.cycles)?;
    let pcs = P3BinaryPcs::new(100);
    verify_spartan_with_matrices(&a, &b, &c, &proof.proof, &pcs)
        .map_err(|error| RuntimeError::Proof(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simd_memory_rows_round_trip() {
        let (_system, layout) = uniform_memory_row_layout(16);
        let rows = [
            layout.witness(0x1000, 0x10, 2, 0x34, true),
            layout.witness(0x1004, 0x20, 4, 0x56, false),
        ];
        let proof = prove_simd_memory_rows(16, &rows).expect("prove");
        verify_simd_memory_rows(&proof).expect("verify");
    }
}
