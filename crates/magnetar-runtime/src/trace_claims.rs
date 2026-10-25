//! Merkle commitment to the per-row CPU claim record.
//!
//! This is the first layer of the authenticated CPU claim design: a proof-only
//! verifier can check a row's claim record against the statement commitment
//! without rebuilding the trace.

use magnetar_spec::{Trace, TraceRow};

const LEAF_DOMAIN: &[u8] = b"magnetar-trace-claim-leaf";
const NODE_DOMAIN: &[u8] = b"magnetar-trace-claim-node";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceClaimOpening {
    pub index: usize,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct TraceClaimTree {
    layers: Vec<Vec<[u8; 32]>>,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    magnetar_transcript::sha256(&bytes).into()
}

pub fn claim_leaf(row: &TraceRow) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&row.pc.to_le_bytes());
    bytes.extend_from_slice(&row.next_pc.to_le_bytes());
    bytes.extend_from_slice(&row.instruction_word.to_le_bytes());
    bytes.push(row.instruction_len);
    bytes.push(row.rd.unwrap_or(0) as u8);
    bytes.push(row.rs1.unwrap_or(0) as u8);
    bytes.push(row.rs2.unwrap_or(0) as u8);
    bytes.extend_from_slice(&row.rd_val.to_le_bytes());
    bytes.extend_from_slice(&row.rs1_val.to_le_bytes());
    bytes.extend_from_slice(&row.rs2_val.to_le_bytes());
    for access in row.mem.iter().chain(row.extra_mem.iter()) {
        bytes.extend_from_slice(&access.addr.to_le_bytes());
        bytes.extend_from_slice(&access.value.to_le_bytes());
        bytes.push(access.width);
    }
    hash(&[LEAF_DOMAIN, &bytes])
}

impl TraceClaimTree {
    pub fn build(trace: &Trace) -> Self {
        let mut leaves = trace.rows.iter().map(claim_leaf).collect::<Vec<_>>();
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
        Self { layers }
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
            leaf,
            siblings,
        })
    }
}

pub fn verify_opening(root: [u8; 32], opening: &TraceClaimOpening) -> bool {
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
    fn root_changes_with_instruction_length() {
        let trace = trace();
        let root = TraceClaimTree::build(&trace).root();
        let mut changed = trace.clone();
        changed.rows[0].instruction_len = 2;
        assert_ne!(root, TraceClaimTree::build(&changed).root());
    }
}
