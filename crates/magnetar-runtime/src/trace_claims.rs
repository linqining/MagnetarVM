//! Merkle commitment to the per-row CPU claim record.
//!
//! This is the first layer of the authenticated CPU claim design: a proof-only
//! verifier can check a row's claim record against the statement commitment
//! without rebuilding the trace.

use magnetar_spec::{Trace, TraceRow};

const LEAF_DOMAIN: &[u8] = b"magnetar-trace-claim-leaf";
const NODE_DOMAIN: &[u8] = b"magnetar-trace-claim-node";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceMemClaim {
    pub addr: u64,
    pub value: u64,
    pub width: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceClaim {
    pub pc: u64,
    pub next_pc: u64,
    pub instruction_word: u32,
    pub instruction_len: u8,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub rd_value: u64,
    pub rs1_value: u64,
    pub rs2_value: u64,
    pub memory: Vec<TraceMemClaim>,
}

impl TraceClaim {
    pub fn from_row(row: &TraceRow) -> Self {
        Self {
            pc: row.pc,
            next_pc: row.next_pc,
            instruction_word: row.instruction_word,
            instruction_len: row.instruction_len,
            rd: row.rd.unwrap_or(0) as u8,
            rs1: row.rs1.unwrap_or(0) as u8,
            rs2: row.rs2.unwrap_or(0) as u8,
            rd_value: row.rd_val,
            rs1_value: row.rs1_val,
            rs2_value: row.rs2_val,
            memory: row
                .mem
                .iter()
                .chain(row.extra_mem.iter())
                .map(|access| TraceMemClaim {
                    addr: access.addr,
                    value: access.value,
                    width: access.width,
                })
                .collect(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pc.to_le_bytes());
        bytes.extend_from_slice(&self.next_pc.to_le_bytes());
        bytes.extend_from_slice(&self.instruction_word.to_le_bytes());
        bytes.push(self.instruction_len);
        bytes.push(self.rd);
        bytes.push(self.rs1);
        bytes.push(self.rs2);
        bytes.extend_from_slice(&self.rd_value.to_le_bytes());
        bytes.extend_from_slice(&self.rs1_value.to_le_bytes());
        bytes.extend_from_slice(&self.rs2_value.to_le_bytes());
        for access in &self.memory {
            bytes.extend_from_slice(&access.addr.to_le_bytes());
            bytes.extend_from_slice(&access.value.to_le_bytes());
            bytes.push(access.width);
        }
        bytes
    }

    pub fn leaf(&self) -> [u8; 32] {
        hash(&[LEAF_DOMAIN, &self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceClaimOpening {
    pub index: usize,
    pub claim: TraceClaim,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct TraceClaimTree {
    claims: Vec<TraceClaim>,
    layers: Vec<Vec<[u8; 32]>>,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    magnetar_transcript::sha256(&bytes)
}

pub fn claim_leaf(row: &TraceRow) -> [u8; 32] {
    TraceClaim::from_row(row).leaf()
}

impl TraceClaimTree {
    pub fn build(trace: &Trace) -> Self {
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        let mut leaves = claims.iter().map(TraceClaim::leaf).collect::<Vec<_>>();
        let width = leaves.len().max(1).next_power_of_two();
        leaves.resize(width, [0u8; 32]);
        let mut layers = vec![leaves];
        while layers.last().map(Vec::len).unwrap_or(0) > 1 {
            let previous = layers.last().expect("layer");
            let next = previous
                .chunks_exact(2)
                .map(|pair| hash(&[NODE_DOMAIN, &pair[0], &pair[1]]))
                .collect::<Vec<_>>();
            layers.push(next);
        }
        Self { claims, layers }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers
            .last()
            .map(|layer| layer[0])
            .unwrap_or([0u8; 32])
    }

    pub fn len(&self) -> usize {
        self.layers.first().map(Vec::len).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn open(&self, index: usize) -> Option<TraceClaimOpening> {
        let mut position = index;
        let leaf = *self.layers.first()?.get(index)?;
        let mut siblings = Vec::with_capacity(self.layers.len().saturating_sub(1));
        for layer in self.layers.iter().take(self.layers.len().saturating_sub(1)) {
            siblings.push(*layer.get(position ^ 1)?);
            position /= 2;
        }
        Some(TraceClaimOpening {
            index,
            claim: self.claims.get(index)?.clone(),
            leaf,
            siblings,
        })
    }
}

pub fn verify_opening(root: [u8; 32], opening: &TraceClaimOpening) -> bool {
    if opening.claim.leaf() != opening.leaf {
        return false;
    }
    let mut node = opening.leaf;
    let mut position = opening.index;
    for sibling in &opening.siblings {
        node = if position & 1 == 0 {
            hash(&[NODE_DOMAIN, &node, sibling])
        } else {
            hash(&[NODE_DOMAIN, sibling, &node])
        };
        position /= 2;
    }
    node == root
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpuOutputClaim {
    pub pc: u64,
    pub next_pc: u64,
    pub instruction_len: u8,
    pub rd: Option<(u8, u64)>,
    pub rs1: Option<(u8, u64)>,
    pub rs2: Option<(u8, u64)>,
    pub memory: Vec<TraceMemClaim>,
}

impl CpuOutputClaim {
    pub fn from_claim(claim: &TraceClaim) -> Self {
        Self {
            pc: claim.pc,
            next_pc: claim.next_pc,
            instruction_len: claim.instruction_len,
            rd: (claim.rd != 0).then_some((claim.rd, claim.rd_value)),
            rs1: (claim.rs1 != 0).then_some((claim.rs1, claim.rs1_value)),
            rs2: (claim.rs2 != 0).then_some((claim.rs2, claim.rs2_value)),
            memory: claim.memory.clone(),
        }
    }
}

pub fn cpu_output_claims(claims: &[TraceClaim]) -> Vec<CpuOutputClaim> {
    claims.iter().map(CpuOutputClaim::from_claim).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimProof {
    pub root: [u8; 32],
    pub openings: Vec<TraceClaimOpening>,
}

impl ClaimProof {
    pub fn from_trace(trace: &Trace) -> Self {
        let tree = TraceClaimTree::build(trace);
        Self {
            root: tree.root(),
            openings: (0..trace.rows.len())
                .filter_map(|index| tree.open(index))
                .collect(),
        }
    }

    pub fn verify(&self) -> Option<Vec<TraceClaim>> {
        verify_claims(self.root, &self.openings)
    }
}

/// Verify a contiguous list of claim openings and return their payloads.
pub fn verify_claims(root: [u8; 32], openings: &[TraceClaimOpening]) -> Option<Vec<TraceClaim>> {
    let mut claims = Vec::with_capacity(openings.len());
    for (index, opening) in openings.iter().enumerate() {
        if opening.index != index || !verify_opening(root, opening) {
            return None;
        }
        claims.push(opening.claim.clone());
    }
    Some(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> Trace {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ebreak).encode(),
            ],
        );
        execute(
            &program,
            MachineConfig {
                entry: 0x1000,
                rom_base: 0x1000,
                ram_base: 0x1000_0000,
                ram_size: 0x40,
                stack_top: 0x1000_0040,
                max_cycles: 10,
            },
        )
        .unwrap()
    }

    #[test]
    fn every_row_opening_verifies() {
        let trace = trace();
        let tree = TraceClaimTree::build(&trace);
        for index in 0..trace.rows.len() {
            let opening = tree.open(index).unwrap();
            assert_eq!(opening.leaf, claim_leaf(&trace.rows[index]));
            assert!(verify_opening(tree.root(), &opening));
        }
    }

    #[test]
    fn tampered_leaf_is_rejected() {
        let trace = trace();
        let tree = TraceClaimTree::build(&trace);
        let mut opening = tree.open(0).unwrap();
        opening.leaf[0] ^= 1;
        assert!(!verify_opening(tree.root(), &opening));
    }

    #[test]
    fn verified_claims_recover_row_fields() {
        let trace = trace();
        let tree = TraceClaimTree::build(&trace);
        let openings = (0..trace.rows.len())
            .map(|index| tree.open(index).unwrap())
            .collect::<Vec<_>>();
        let claims = verify_claims(tree.root(), &openings).unwrap();
        assert_eq!(claims.len(), trace.rows.len());
        assert_eq!(claims[0].pc, 0x1000);
        assert_eq!(claims[0].instruction_len, 4);
        let mut bad = openings;
        bad[0].claim.instruction_len = 2;
        assert!(verify_claims(tree.root(), &bad).is_none());
    }

    #[test]
    fn cpu_output_claims_extract_register_and_memory() {
        let trace = trace();
        let proof = ClaimProof::from_trace(&trace);
        let claims = proof.verify().unwrap();
        let outputs = cpu_output_claims(&claims);
        assert_eq!(outputs[0].pc, 0x1000);
        assert_eq!(outputs[0].instruction_len, 4);
        assert_eq!(outputs[0].rd, Some((1, 5)));
        assert_eq!(outputs[1].instruction_len, 4);
    }

    #[test]
    fn claim_proof_round_trips_serde() {
        let trace = trace();
        let proof = ClaimProof::from_trace(&trace);
        let bytes = bincode::serialize(&proof).unwrap();
        let decoded: ClaimProof = bincode::deserialize(&bytes).unwrap();
        assert_eq!(proof, decoded);
        assert_eq!(decoded.verify().unwrap().len(), trace.rows.len());
    }

    #[test]
    fn tampered_claim_fields_are_rejected() {
        let trace = trace();
        let tree = TraceClaimTree::build(&trace);
        for mutate in [
            |claim: &mut TraceClaim| claim.instruction_len ^= 4,
            |claim: &mut TraceClaim| claim.rd_value ^= 1,
            |claim: &mut TraceClaim| {
                claim.memory.push(TraceMemClaim {
                    addr: 1,
                    value: 2,
                    width: 8,
                })
            },
        ] {
            let mut opening = tree.open(0).unwrap();
            mutate(&mut opening.claim);
            assert!(!verify_opening(tree.root(), &opening));
        }
    }

    #[test]
    fn root_changes_with_instruction_length() {
        let trace = trace();
        let root = TraceClaimTree::build(&trace).root();
        let mut changed = trace.clone();
        changed.rows[0].instruction_len = 2;
        assert_ne!(root, TraceClaimTree::build(&changed).root());
    }
}
