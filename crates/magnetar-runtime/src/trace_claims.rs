//! Merkle commitment to the per-row CPU claim record.
//!
//! This is the first layer of the authenticated CPU claim design: a proof-only
//! verifier can check a row's claim record against the statement commitment
//! without rebuilding the trace.

use bincode::Options as _;
use magnetar_spec::{Trace, TraceRow};

const LEAF_DOMAIN: &[u8] = b"magnetar-trace-claim-leaf";
const NODE_DOMAIN: &[u8] = b"magnetar-trace-claim-node";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceMemClaim {
    pub cycle: u64,
    pub addr: u64,
    pub value: u64,
    pub width: u8,
    pub is_write: bool,
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
    pub rd_present: bool,
    pub rs1_present: bool,
    pub rs2_present: bool,
    pub rd_value: u64,
    pub rs1_value: u64,
    pub rs2_value: u64,
    pub memory: Vec<TraceMemClaim>,
    pub syscall: Option<magnetar_spec::SyscallTrace>,
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
            rd_present: row.rd.is_some(),
            rs1_present: row.rs1.is_some(),
            rs2_present: row.rs2.is_some(),
            rd_value: row.rd_val,
            rs1_value: row.rs1_val,
            rs2_value: row.rs2_val,
            memory: row
                .mem
                .iter()
                .chain(row.extra_mem.iter())
                .map(|access| TraceMemClaim {
                    cycle: row.cycle,
                    addr: access.addr,
                    value: access.value,
                    width: access.width,
                    is_write: access.is_write,
                })
                .collect(),
            syscall: row.syscall,
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
        bytes.push(u8::from(self.rd_present));
        bytes.push(u8::from(self.rs1_present));
        bytes.push(u8::from(self.rs2_present));
        bytes.extend_from_slice(&self.rd_value.to_le_bytes());
        bytes.extend_from_slice(&self.rs1_value.to_le_bytes());
        bytes.extend_from_slice(&self.rs2_value.to_le_bytes());
        match self.syscall {
            Some(syscall) => {
                bytes.push(1);
                bytes.extend_from_slice(&syscall.number.to_le_bytes());
                for arg in syscall.args {
                    bytes.extend_from_slice(&arg.to_le_bytes());
                }
            }
            None => bytes.push(0),
        }
        for access in &self.memory {
            bytes.extend_from_slice(&access.cycle.to_le_bytes());
            bytes.extend_from_slice(&access.addr.to_le_bytes());
            bytes.extend_from_slice(&access.value.to_le_bytes());
            bytes.push(access.width);
            bytes.push(u8::from(access.is_write));
        }
        bytes
    }

    pub fn leaf(&self) -> [u8; 32] {
        // Encode straight into a stack buffer with the domain prefix, so the
        // per-row leaf costs one hash and no allocation. Larger-than-typical
        // rows (many memory accesses) fall back to the allocating path.
        let mut buffer = [0u8; LEAF_BUFFER];
        buffer[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
        let mut len = LEAF_DOMAIN.len();
        if encode_into(&mut buffer, &mut len, self) {
            return magnetar_transcript::sha256(&buffer[..len]);
        }
        hash(&[LEAF_DOMAIN, &self.encode()])
    }
}

const LEAF_BUFFER: usize = 384;

/// Encode the claim into `buffer` at `len`; `false` if it does not fit.
fn encode_into(buffer: &mut [u8], len: &mut usize, claim: &TraceClaim) -> bool {
    let mut put = |bytes: &[u8]| -> bool {
        if *len + bytes.len() > buffer.len() {
            return false;
        }
        buffer[*len..*len + bytes.len()].copy_from_slice(bytes);
        *len += bytes.len();
        true
    };
    put(&claim.pc.to_le_bytes())
        && put(&claim.next_pc.to_le_bytes())
        && put(&claim.instruction_word.to_le_bytes())
        && put(&[claim.instruction_len])
        && put(&[claim.rd])
        && put(&[claim.rs1])
        && put(&[claim.rs2])
        && put(&[u8::from(claim.rd_present)])
        && put(&[u8::from(claim.rs1_present)])
        && put(&[u8::from(claim.rs2_present)])
        && put(&claim.rd_value.to_le_bytes())
        && put(&claim.rs1_value.to_le_bytes())
        && put(&claim.rs2_value.to_le_bytes())
        && match claim.syscall {
            Some(syscall) => {
                put(&[1])
                    && put(&syscall.number.to_le_bytes())
                    && syscall.args.iter().all(|arg| put(&arg.to_le_bytes()))
            }
            None => put(&[0]),
        }
        && claim.memory.iter().all(|access| {
            put(&access.cycle.to_le_bytes())
                && put(&access.addr.to_le_bytes())
                && put(&access.value.to_le_bytes())
                && put(&[access.width])
                && put(&[u8::from(access.is_write)])
        })
}

/// One row of a complete claim proof: absolute row index plus the claim.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceClaimOpening {
    pub index: usize,
    pub claim: TraceClaim,
}

/// Claim-tree root. Leaves hash groups of `CLAIM_LEAF_GROUP` rows, which
/// amortizes the per-hash cost on both sides (a group costs one SHA-256
/// instead of one per row).
#[derive(Clone, Debug)]
pub struct TraceClaimTree {
    root: [u8; 32],
}

/// Rows per claim-tree leaf.
pub const CLAIM_LEAF_GROUP: usize = 8;

const GROUP_BUFFER: usize = 1024;

/// Hash of one group of consecutive claims: `LEAF_DOMAIN`, the group length
/// and each length-prefixed claim encoding.
fn claim_group_leaf(group: &[TraceClaim]) -> [u8; 32] {
    let mut buffer = [0u8; GROUP_BUFFER];
    buffer[..LEAF_DOMAIN.len()].copy_from_slice(LEAF_DOMAIN);
    let mut len = LEAF_DOMAIN.len() + 2;
    buffer[LEAF_DOMAIN.len()] = group.len() as u8;
    let mut fits = true;
    for claim in group {
        let start = len + 2;
        if start > buffer.len() {
            fits = false;
            break;
        }
        let mut end = start;
        if !encode_into(&mut buffer, &mut end, claim) {
            fits = false;
            break;
        }
        let size = (end - start) as u16;
        buffer[len..len + 2].copy_from_slice(&size.to_le_bytes());
        len = end;
    }
    if fits {
        return magnetar_transcript::sha256(&buffer[..len]);
    }
    let mut bytes = Vec::with_capacity(LEAF_DOMAIN.len() + group.len() * 128);
    bytes.extend_from_slice(LEAF_DOMAIN);
    bytes.extend_from_slice(&(group.len() as u16).to_le_bytes());
    for claim in group {
        let encoded = claim.encode();
        bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    magnetar_transcript::sha256(&bytes)
}

fn claim_group_leaves(claims: &[TraceClaim]) -> Vec<[u8; 32]> {
    claims.chunks(CLAIM_LEAF_GROUP).map(claim_group_leaf).collect()
}

/// Domain-separated hash of two 32-byte children, allocation-free.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buffer = [0u8; NODE_DOMAIN.len() + 64];
    buffer[..NODE_DOMAIN.len()].copy_from_slice(NODE_DOMAIN);
    buffer[NODE_DOMAIN.len()..NODE_DOMAIN.len() + 32].copy_from_slice(left);
    buffer[NODE_DOMAIN.len() + 32..].copy_from_slice(right);
    magnetar_transcript::sha256(&buffer)
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
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
        Self {
            root: claim_root_of(&claims),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }
}

fn claim_root_of(claims: &[TraceClaim]) -> [u8; 32] {
    if claims.is_empty() {
        return [0u8; 32];
    }
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1);
    reduce_claim_root(claim_group_leaves(claims), workers)
}

/// Trace-aware reference check: recovered claims must match the supplied rows.
pub fn verify_claims_against_trace(trace: &Trace, claims: &[TraceClaim]) -> bool {
    if claims.len() != trace.rows.len() {
        return false;
    }
    claims.iter().zip(&trace.rows).all(|(claim, row)| {
        let expected = TraceClaim::from_row(row);
        claim == &expected
    })
}

/// Rebuild a trace-shaped row set from authenticated claims for the
/// trace-free selected CPU verifier. Decoding uses the authenticated word.
pub fn claims_to_trace(
    statement: &crate::Statement,
    claims: &[TraceClaim],
) -> Result<Trace, crate::RuntimeError> {
    use magnetar_spec::{MemoryAccess, MicroOpKind, TraceRow};

    let mut rows = Vec::with_capacity(claims.len());
    for (index, claim) in claims.iter().enumerate() {
        let instruction = if claim.instruction_len == 2 {
            magnetar_spec::decode_compressed(claim.instruction_word as u16)
                .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
        } else {
            magnetar_spec::decode(claim.instruction_word)
                .map_err(|error| crate::RuntimeError::Proof(error.to_string()))?
        };
        let mut memory = claim.memory.iter();
        let first = memory.next().map(|event| MemoryAccess {
            addr: event.addr,
            value: event.value,
            width: event.width,
            is_write: event.is_write,
        });
        let extra_mem = memory
            .map(|event| MemoryAccess {
                addr: event.addr,
                value: event.value,
                width: event.width,
                is_write: event.is_write,
            })
            .collect();
        rows.push(TraceRow {
            cycle: index as u64,
            pc: claim.pc,
            micro_pc: claim.pc,
            micro_op: MicroOpKind::Execute,
            next_pc: claim.next_pc,
            instruction_word: claim.instruction_word,
            instruction_len: claim.instruction_len,
            instruction,
            rs1: claim.rs1_present.then_some(claim.rs1 as usize),
            rs2: claim.rs2_present.then_some(claim.rs2 as usize),
            rd: claim.rd_present.then_some(claim.rd as usize),
            rs1_val: claim.rs1_value,
            rs2_val: claim.rs2_value,
            rd_val: claim.rd_value,
            mem: first,
            extra_mem,
            reservation_before: None,
            reservation_after: None,
            syscall: claim.syscall,
        });
    }
    Ok(Trace {
        config: statement.config.clone(),
        rom: statement.rom.clone(),
        initial_state: statement.initial_state.clone(),
        final_state: statement.final_state.clone(),
        rows,
        memory_events: claims
            .iter()
            .flat_map(|claim| claim.memory.iter())
            .map(|event| magnetar_spec::MemoryEvent {
                cycle: event.cycle,
                access: MemoryAccess {
                    addr: event.addr,
                    value: event.value,
                    width: event.width,
                    is_write: event.is_write,
                },
            })
            .collect(),
        initial_ram: statement.initial_ram.clone(),
        halted: statement.halted,
        exit_code: statement.exit_code,
        io_output: Vec::new(),
        io_input: Vec::new(),
    })
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
            rd: claim.rd_present.then_some((claim.rd, claim.rd_value)),
            rs1: claim.rs1_present.then_some((claim.rs1, claim.rs1_value)),
            rs2: claim.rs2_present.then_some((claim.rs2, claim.rs2_value)),
            memory: claim.memory.clone(),
        }
    }
}

pub fn cpu_output_claims(claims: &[TraceClaim]) -> Vec<CpuOutputClaim> {
    claims.iter().map(CpuOutputClaim::from_claim).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimProof {
    pub root: [u8; 32],
    pub complete: bool,
    pub openings: Vec<TraceClaimOpening>,
    /// Compact blob with rs1/rs2 columns omitted (reconstructed from the
    /// statement's initial registers).
    pub reg_blob: Option<Vec<u8>>,
    /// Committed claim columns and the claim relation (polylog verifier).
    /// `None` on the legacy row-based paths; the native path attaches it.
    pub table: Option<crate::claim_table::ClaimTableProof>,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum ClaimProofWire {
    Compact {
        root: [u8; 32],
        blob: Vec<u8>,
        #[serde(default)]
        table: Option<crate::claim_table::ClaimTableProof>,
    },
    CompactRegs {
        root: [u8; 32],
        blob: Vec<u8>,
        #[serde(default)]
        table: Option<crate::claim_table::ClaimTableProof>,
    },
    /// Compact blob plus the register indices of rows whose claim does not
    /// carry the indices implied by its instruction word (the blob derives
    /// `rd`/`rs1`/`rs2` from the word, and the executor may record others,
    /// e.g. on the syscall row).
    CompactIndexed {
        root: [u8; 32],
        blob: Vec<u8>,
        indices: Vec<(u32, u8, u8, u8)>,
        #[serde(default)]
        table: Option<crate::claim_table::ClaimTableProof>,
    },
    Full {
        root: [u8; 32],
        complete: bool,
        openings: Vec<TraceClaimOpening>,
        #[serde(default)]
        table: Option<crate::claim_table::ClaimTableProof>,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ClaimColumns {
    first_pc: u64,
    pc_deltas: Vec<(i64, u32)>,
    next_deltas: Vec<(i64, u32)>,
    words: Vec<u32>,
    flags: Vec<(u8, u32)>,
    first_rd_value: u64,
    first_rd_delta: i64,
    rd_delta_deltas: Vec<(i64, u32)>,
    rs1_values: Vec<(u64, u32)>,
    rs2_values: Vec<(u64, u32)>,
    memory_rows: Vec<u32>,
    memory: Vec<Vec<TraceMemClaim>>,
    syscall_rows: Vec<u32>,
    syscalls: Vec<magnetar_spec::SyscallTrace>,
}

fn run_length<T: PartialEq + Copy>(values: &[T]) -> Vec<(T, u32)> {
    let mut runs: Vec<(T, u32)> = Vec::new();
    for value in values {
        match runs.last_mut() {
            Some((last, count)) if *last == *value => *count += 1,
            _ => runs.push((*value, 1)),
        }
    }
    runs
}

fn expand_runs<T: Copy>(runs: &[(T, u32)], len: usize) -> Option<Vec<T>> {
    let mut values = Vec::with_capacity(len);
    for (value, count) in runs {
        let count = *count as usize;
        if values.len().saturating_add(count) > len {
            return None;
        }
        values.extend(std::iter::repeat_n(*value, count));
    }
    (values.len() == len).then_some(values)
}

fn encode_claim_columns(claims: &[TraceClaim]) -> Vec<u8> {
    let mut columns = ClaimColumns {
        first_pc: claims.first().map_or(0, |claim| claim.pc),
        pc_deltas: Vec::with_capacity(claims.len().saturating_sub(1)),
        next_deltas: Vec::with_capacity(claims.len()),
        words: Vec::with_capacity(claims.len()),
        flags: Vec::with_capacity(claims.len()),
        first_rd_value: 0,
        first_rd_delta: 0,
        rd_delta_deltas: Vec::new(),
        rs1_values: Vec::with_capacity(claims.len()),
        rs2_values: Vec::with_capacity(claims.len()),
        memory_rows: Vec::new(),
        memory: Vec::new(),
        syscall_rows: Vec::new(),
        syscalls: Vec::new(),
    };
    let mut previous_pc = columns.first_pc;
    let mut pc_deltas = Vec::with_capacity(claims.len().saturating_sub(1));
    let mut next_deltas = Vec::with_capacity(claims.len());
    let mut words = Vec::with_capacity(claims.len());
    let mut flags = Vec::with_capacity(claims.len());
    let mut raw_rd_values = Vec::with_capacity(claims.len());
    let mut raw_rs1_values = Vec::with_capacity(claims.len());
    let mut raw_rs2_values = Vec::with_capacity(claims.len());
    for (index, claim) in claims.iter().enumerate() {
        if index > 0 {
            pc_deltas.push(claim.pc as i64 - previous_pc as i64);
        }
        previous_pc = claim.pc;
        next_deltas.push(claim.next_pc as i64 - claim.pc as i64);
        words.push(claim.instruction_word);
        flags.push(
            u8::from(claim.rd_present)
                | (u8::from(claim.rs1_present) << 1)
                | (u8::from(claim.rs2_present) << 2),
        );
        raw_rd_values.push(claim.rd_value);
        raw_rs1_values.push(claim.rs1_value);
        raw_rs2_values.push(claim.rs2_value);
        if !claim.memory.is_empty() {
            columns.memory_rows.push(index as u32);
            columns.memory.push(claim.memory.clone());
        }
        if let Some(syscall) = claim.syscall {
            columns.syscall_rows.push(index as u32);
            columns.syscalls.push(syscall);
        }
    }
    columns.first_rd_value = raw_rd_values.first().copied().unwrap_or(0);
    let mut rd_deltas = Vec::with_capacity(raw_rd_values.len().saturating_sub(1));
    let mut previous_rd_value = columns.first_rd_value;
    for value in raw_rd_values.iter().skip(1) {
        rd_deltas.push(*value as i64 - previous_rd_value as i64);
        previous_rd_value = *value;
    }
    columns.first_rd_delta = rd_deltas.first().copied().unwrap_or(0);
    let mut previous_delta = columns.first_rd_delta;
    let mut delta_deltas = Vec::with_capacity(rd_deltas.len().saturating_sub(1));
    for delta in rd_deltas.iter().skip(1) {
        delta_deltas.push(*delta - previous_delta);
        previous_delta = *delta;
    }
    columns.rd_delta_deltas = run_length(&delta_deltas);
    columns.pc_deltas = run_length(&pc_deltas);
    columns.next_deltas = run_length(&next_deltas);
    let mut previous_word = 0u32;
    for (index, word) in words.iter().enumerate() {
        columns.words.push(if index == 0 { *word } else { previous_word ^ *word });
        previous_word = *word;
    }
    columns.flags = run_length(&flags);
    columns.rs1_values = run_length(&raw_rs1_values);
    columns.rs2_values = run_length(&raw_rs2_values);
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .serialize(&columns)
        .unwrap_or_default()
}

fn decode_claim_columns(blob: &[u8]) -> Result<Vec<TraceClaim>, Box<bincode::ErrorKind>> {
    decode_claim_columns_with_regs(blob, None)
}

fn decode_claim_columns_with_regs(
    blob: &[u8],
    initial_regs: Option<[magnetar_spec::Word; magnetar_spec::NUM_REGS]>,
) -> Result<Vec<TraceClaim>, Box<bincode::ErrorKind>> {
    let columns: ClaimColumns = bincode::DefaultOptions::new()
        .with_varint_encoding()
        .deserialize(blob)?;
    let count = columns.words.len();
    let pc_deltas = expand_runs(&columns.pc_deltas, count.saturating_sub(1))
        .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim pc runs".into())))?;
    let next_deltas = expand_runs(&columns.next_deltas, count)
        .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim next runs".into())))?;
    if columns.words.len() != count {
        return Err(Box::new(bincode::ErrorKind::Custom("claim word count".into())));
    }
    let flags = expand_runs(&columns.flags, count)
        .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim flag runs".into())))?;
    let mut regs = initial_regs;
    let rs1_values = if regs.is_some() {
        Vec::new()
    } else {
        expand_runs(&columns.rs1_values, count)
            .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim rs1 runs".into())))?
    };
    let rs2_values = if regs.is_some() {
        Vec::new()
    } else {
        expand_runs(&columns.rs2_values, count)
            .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim rs2 runs".into())))?
    };
    let delta_deltas = expand_runs(&columns.rd_delta_deltas, count.saturating_sub(2))
        .ok_or_else(|| Box::new(bincode::ErrorKind::Custom("claim rd delta runs".into())))?;
    let mut rd_values = Vec::with_capacity(count);
    let mut rd_value = columns.first_rd_value;
    let mut rd_delta = columns.first_rd_delta;
    for index in 0..count {
        if index > 0 {
            if index > 1 {
                rd_delta += delta_deltas[index - 2];
            }
            rd_value = (rd_value as i64 + rd_delta) as u64;
        }
        rd_values.push(rd_value);
    }
    let mut claims = Vec::with_capacity(count);
    let mut memory = vec![Vec::new(); count];
    for (row, entries) in columns.memory_rows.iter().zip(&columns.memory) {
        let index = *row as usize;
        if index >= memory.len() {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "claim memory row out of range".into(),
            )));
        }
        memory[index] = entries.clone();
    }
    let mut syscalls = vec![None; count];
    for (row, syscall) in columns.syscall_rows.iter().zip(&columns.syscalls) {
        let index = *row as usize;
        if index >= syscalls.len() {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "claim syscall row out of range".into(),
            )));
        }
        syscalls[index] = Some(*syscall);
    }
    let mut pc = columns.first_pc;
    let mut previous_word = 0u32;
    for index in 0..count {
        if index > 0 {
            pc = (pc as i64 + pc_deltas[index - 1]) as u64;
        }
        let row_flags = flags[index];
        let word = if index == 0 {
            columns.words[0]
        } else {
            previous_word ^ columns.words[index]
        };
        previous_word = word;
        let (instruction, instruction_len) = if word & 3 == 3 {
            (
                magnetar_spec::decode(word).map_err(|error| {
                    Box::new(bincode::ErrorKind::Custom(error.to_string()))
                })?,
                4,
            )
        } else {
            (
                magnetar_spec::decode_compressed((word & 0xffff) as u16).map_err(|error| {
                    Box::new(bincode::ErrorKind::Custom(error.to_string()))
                })?,
                2,
            )
        };
        claims.push(TraceClaim {
            pc,
            next_pc: (pc as i64 + next_deltas[index]) as u64,
            instruction_word: word,
            instruction_len,
            rd: instruction.rd,
            rs1: instruction.rs1,
            rs2: instruction.rs2,
            rd_present: row_flags & 1 != 0,
            rs1_present: row_flags & 2 != 0,
            rs2_present: row_flags & 4 != 0,
            rd_value: rd_values[index],
            rs1_value: match &regs {
                Some(regs) => {
                    if row_flags & 2 != 0 {
                        regs[usize::from(instruction.rs1)]
                    } else {
                        0
                    }
                }
                None => rs1_values[index],
            },
            rs2_value: match &regs {
                Some(regs) => {
                    if row_flags & 4 != 0 {
                        regs[usize::from(instruction.rs2)]
                    } else {
                        0
                    }
                }
                None => rs2_values[index],
            },
            memory: std::mem::take(&mut memory[index]),
            syscall: syscalls[index],
        });
        if let Some(regs) = &mut regs {
            if row_flags & 1 != 0 && instruction.rd != 0 {
                regs[usize::from(instruction.rd)] = rd_values[index];
            }
        }
    }
    Ok(claims)
}

/// Register indices the compact blob derives from the instruction word.
fn instruction_indices(word: u32, instruction_len: u8) -> Option<(u8, u8, u8)> {
    if instruction_len == 4 {
        magnetar_spec::decode(word)
            .ok()
            .map(|instruction| (instruction.rd, instruction.rs1, instruction.rs2))
    } else {
        magnetar_spec::decode_compressed((word & 0xffff) as u16)
            .ok()
            .map(|instruction| (instruction.rd, instruction.rs1, instruction.rs2))
    }
}

/// Rows whose claim indices are not the ones the compact blob re-derives.
fn claim_index_overrides(claims: &[TraceClaim]) -> Vec<(u32, u8, u8, u8)> {
    claims
        .iter()
        .enumerate()
        .filter_map(|(index, claim)| {
            let derived = instruction_indices(claim.instruction_word, claim.instruction_len)?;
            ((claim.rd, claim.rs1, claim.rs2) != derived)
                .then_some((index as u32, claim.rd, claim.rs1, claim.rs2))
        })
        .collect()
}

fn decode_compact_claim_blob(blob: &[u8]) -> Result<Vec<TraceClaim>, Box<bincode::ErrorKind>> {
    let blob = miniz_oxide::inflate::decompress_to_vec(blob)
        .map_err(|error| Box::new(bincode::ErrorKind::Custom(format!("claim blob: {error:?}"))))?;
    decode_claim_columns(&blob)
}

fn complete_claim_proof(root: [u8; 32], claims: Vec<TraceClaim>) -> ClaimProof {
    ClaimProof {
        root,
        complete: true,
        openings: claims
            .into_iter()
            .enumerate()
            .map(|(index, claim)| TraceClaimOpening { index, claim })
            .collect(),
        reg_blob: None,
        table: None,
    }
}

impl serde::Serialize for ClaimProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(blob) = &self.reg_blob {
            ClaimProofWire::CompactRegs {
                root: self.root,
                blob: blob.clone(),
                table: self.table.clone(),
            }
            .serialize(serializer)
        } else if self.complete {
            let claims = self
                .openings
                .iter()
                .map(|opening| opening.claim.clone())
                .collect::<Vec<_>>();
            let indices = claim_index_overrides(&claims);
            let blob = encode_claim_columns(&claims);
            let blob = miniz_oxide::deflate::compress_to_vec(&blob, 6);
            if indices.is_empty() {
                ClaimProofWire::Compact {
                    root: self.root,
                    blob,
                    table: self.table.clone(),
                }
            } else {
                ClaimProofWire::CompactIndexed {
                    root: self.root,
                    blob,
                    indices,
                    table: self.table.clone(),
                }
            }
            .serialize(serializer)
        } else {
            ClaimProofWire::Full {
                root: self.root,
                complete: self.complete,
                openings: self.openings.clone(),
                table: self.table.clone(),
            }
            .serialize(serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for ClaimProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match ClaimProofWire::deserialize(deserializer)? {
            ClaimProofWire::Compact { root, blob, table } => {
                let claims = decode_compact_claim_blob(&blob).map_err(serde::de::Error::custom)?;
                let mut proof = complete_claim_proof(root, claims);
                proof.table = table;
                Ok(proof)
            }
            ClaimProofWire::CompactIndexed {
                root,
                blob,
                indices,
                table,
            } => {
                let mut claims = decode_compact_claim_blob(&blob).map_err(serde::de::Error::custom)?;
                for (row, rd, rs1, rs2) in indices {
                    let claim = claims.get_mut(row as usize).ok_or_else(|| {
                        serde::de::Error::custom("claim index override out of range")
                    })?;
                    claim.rd = rd;
                    claim.rs1 = rs1;
                    claim.rs2 = rs2;
                }
                let mut proof = complete_claim_proof(root, claims);
                proof.table = table;
                Ok(proof)
            }
            ClaimProofWire::Full {
                root,
                complete,
                openings,
                table,
            } => Ok(Self {
                root,
                complete,
                openings,
                reg_blob: None,
                table,
            }),
            ClaimProofWire::CompactRegs { root, blob, table } => Ok(Self {
                root,
                complete: true,
                openings: Vec::new(),
                reg_blob: Some(blob),
                table,
            }),
        }
    }
}

impl ClaimProof {
    pub fn from_trace(trace: &Trace) -> Self {
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        let openings = claims
            .iter()
            .enumerate()
            .map(|(index, claim)| TraceClaimOpening {
                index,
                claim: claim.clone(),
            })
            .collect();
        Self {
            root: claim_root_of(&claims),
            complete: true,
            openings,
            reg_blob: None,
            table: None,
        }
    }

    /// Compact ROM/register-derived encoding: rows are rebuilt from the
    /// statement's initial registers; rs1/rs2 columns are omitted.
    pub fn from_trace_reg(trace: &Trace) -> Self {
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        let root = claim_root_of(&claims);
        let encoded = encode_claim_columns(&claims);
        let mut columns: ClaimColumns = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize(&encoded)
            .expect("claim columns round-trip");
        columns.rs1_values.clear();
        columns.rs2_values.clear();
        let blob = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize(&columns)
            .expect("claim columns serialize");
        let blob = miniz_oxide::deflate::compress_to_vec(&blob, 6);
        Self {
            root,
            complete: true,
            openings: Vec::new(),
            reg_blob: Some(blob),
            table: None,
        }
    }

    /// Verify a compact register-derived claim proof against the statement's
    /// initial registers.
    /// Decode the authenticated rows without recomputing the claim root; the
    /// caller checks the root separately with [`verify_complete_leaves`].
    pub fn decode_rows(
        &self,
        initial: &magnetar_spec::MachineState,
    ) -> Option<Vec<TraceClaim>> {
        if let Some(blob) = self.reg_blob.as_ref() {
            let blob = miniz_oxide::inflate::decompress_to_vec(blob).ok()?;
            return decode_claim_columns_with_regs(&blob, Some(initial.regs)).ok();
        }
        if self.complete && !self.openings.is_empty() {
            return Some(
                self.openings
                    .iter()
                    .map(|opening| opening.claim.clone())
                    .collect(),
            );
        }
        None
    }

    pub fn verify_reg(
        &self,
        initial: &magnetar_spec::MachineState,
    ) -> Option<Vec<TraceClaim>> {
        let Some(blob) = self.reg_blob.as_ref() else {
            return self.verify();
        };
        let profile = std::env::var_os("MAGNETAR_PROFILE_VERIFY").is_some();
        let started = std::time::Instant::now();
        let blob =
            miniz_oxide::inflate::decompress_to_vec(blob).ok()?;
        if profile {
            eprintln!("claim blob inflate: {:?}", started.elapsed());
        }
        let decode_started = std::time::Instant::now();
        let claims = decode_claim_columns_with_regs(&blob, Some(initial.regs)).ok()?;
        if profile {
            eprintln!("claim blob decode: {:?}", decode_started.elapsed());
        }
        if claims.first().map(|claim| claim.pc) != Some(initial.pc) {
            return None;
        }
        let tree_started = std::time::Instant::now();
        if !verify_complete_leaves(self.root, &claims) {
            return None;
        }
        if profile {
            eprintln!("claim leaves+tree: {:?}", tree_started.elapsed());
        }
        Some(claims)
    }

    pub fn verify(&self) -> Option<Vec<TraceClaim>> {
        if !self.complete {
            return None;
        }
        verify_complete_claims(self.root, &self.openings)
    }

}

impl ClaimProof {
    /// Diagnostic: compare compact encoding with ROM-derived words and
    /// register simulation omitted.
    pub fn compact_rom_probe(&self) -> Option<(usize, usize, usize, usize)> {
        if !self.complete || self.openings.is_empty() {
            return None;
        }
        let claims = self
            .openings
            .iter()
            .map(|opening| opening.claim.clone())
            .collect::<Vec<_>>();
        let encoded = encode_claim_columns(&claims);
        let current = encoded.len();
        let current_deflate = miniz_oxide::deflate::compress_to_vec(&encoded, 6).len();
        let mut no_rs1: ClaimColumns = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize(&encoded)
            .ok()?;
        no_rs1.rs1_values.clear();
        let no_rs1_bytes = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize(&no_rs1)
            .ok()?;
        let no_rs1_deflate = miniz_oxide::deflate::compress_to_vec(&no_rs1_bytes, 6).len();
        let mut no_words = no_rs1;
        no_words.words.clear();
        let no_words_bytes = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize(&no_words)
            .ok()?;
        let no_words_deflate = miniz_oxide::deflate::compress_to_vec(&no_words_bytes, 6).len();
        Some((current, current_deflate, no_rs1_deflate, no_words_deflate))
    }
}

impl ClaimProof {
    /// Diagnostic: serialized size of each compact claim column.
    pub fn compact_field_sizes(&self) -> Option<Vec<(&'static str, usize)>> {
        if !self.complete || self.openings.is_empty() {
            return None;
        }
        let claims = self
            .openings
            .iter()
            .map(|opening| opening.claim.clone())
            .collect::<Vec<_>>();
        let blob = encode_claim_columns(&claims);
        let columns: ClaimColumns = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize(&blob)
            .ok()?;
        let size = |bytes: usize| bytes;
        let mut sizes = Vec::new();
        macro_rules! push {
            ($name:literal, $value:expr) => {
                sizes.push(($name, size(bincode::serialize(&$value).ok()?.len())));
            };
        }
        push!("first_pc", columns.first_pc);
        push!("pc_deltas", columns.pc_deltas);
        push!("next_deltas", columns.next_deltas);
        push!("words", columns.words);
        push!("flags", columns.flags);
        push!("first_rd_value", columns.first_rd_value);
        push!("first_rd_delta", columns.first_rd_delta);
        push!("rd_delta_deltas", columns.rd_delta_deltas);
        push!("rs1_values", columns.rs1_values);
        push!("rs2_values", columns.rs2_values);
        push!("memory_rows", columns.memory_rows);
        push!("memory", columns.memory);
        push!("syscall_rows", columns.syscall_rows);
        push!("syscalls", columns.syscalls);
        Some(sizes)
    }
}

/// Verify a complete (all-row) claim proof without per-row Merkle paths.
pub fn verify_complete_claims(
    root: [u8; 32],
    openings: &[TraceClaimOpening],
) -> Option<Vec<TraceClaim>> {
    if openings.is_empty() {
        return None;
    }
    let mut claims = Vec::with_capacity(openings.len());
    for (index, opening) in openings.iter().enumerate() {
        if opening.index != index {
            return None;
        }
        claims.push(opening.claim.clone());
    }
    verify_complete_leaves(root, &claims).then_some(claims)
}

/// Root of the padded claim tree with `leaves` as the leaf layer.
fn reduce_claim_root(mut leaves: Vec<[u8; 32]>, workers: usize) -> [u8; 32] {
    let size = leaves.len().next_power_of_two();
    leaves.resize(size, [0u8; 32]);
    while leaves.len() > 1 {
        if workers > 1 && leaves.len() >= 8192 {
            let chunk = leaves.len().div_ceil(workers) & !1;
            let mut next = Vec::with_capacity(leaves.len() / 2);
            let mut partial: Vec<Vec<[u8; 32]>> = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(workers);
                for first in (0..leaves.len()).step_by(chunk) {
                    let last = (first + chunk).min(leaves.len());
                    let slice = &leaves[first..last];
                    handles.push(scope.spawn(move || {
                        slice
                            .chunks_exact(2)
                            .map(|pair| hash_node(&pair[0], &pair[1]))
                            .collect::<Vec<_>>()
                    }));
                }
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("claim tree worker"))
                    .collect()
            });
            for part in &mut partial {
                next.append(part);
            }
            leaves = next;
        } else {
            leaves = leaves
                .chunks_exact(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
        }
    }
    leaves[0]
}

/// Verify a complete payload list against the claim root, hashing each leaf
/// once. The tree is padded with zero leaves to a power of two.
pub fn verify_complete_leaves(root: [u8; 32], claims: &[TraceClaim]) -> bool {
    if claims.is_empty() {
        return false;
    }
    let groups = claims.len().div_ceil(CLAIM_LEAF_GROUP);
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
        .min(groups.max(1));
    let leaves = if workers > 1 && groups >= 512 {
        let chunk = groups.div_ceil(workers);
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for first in (0..groups).step_by(chunk) {
                let last = (first + chunk).min(groups);
                let start = first * CLAIM_LEAF_GROUP;
                let end = (last * CLAIM_LEAF_GROUP).min(claims.len());
                let slice = &claims[start..end];
                handles.push(scope.spawn(move || claim_group_leaves(slice)));
            }
            let mut leaves = Vec::with_capacity(groups);
            for handle in handles {
                leaves.extend(handle.join().expect("claim leaf worker"));
            }
            leaves
        })
    } else {
        claim_group_leaves(claims)
    };
    reduce_claim_root(leaves, workers) == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn leaf_buffer_matches_the_allocating_encoding() {
        let trace = trace();
        for row in &trace.rows {
            let claim = TraceClaim::from_row(row);
            assert_eq!(claim.leaf(), hash(&[LEAF_DOMAIN, &claim.encode()]));
        }
        let mut with_syscall = trace.rows[0].clone();
        let claim = TraceClaim::from_row(&with_syscall);
        assert_eq!(claim.leaf(), hash(&[LEAF_DOMAIN, &claim.encode()]));
        // Force the fallback path: a claim with many memory accesses.
        let mut claim = TraceClaim::from_row(&trace.rows[0]);
        claim.memory = (0..64)
            .map(|index| TraceMemClaim {
                cycle: index,
                addr: index * 8,
                value: index as u64,
                width: 8,
                is_write: index % 2 == 0,
            })
            .collect();
        assert_eq!(claim.leaf(), hash(&[LEAF_DOMAIN, &claim.encode()]));
        let _ = &mut with_syscall;
    }

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
    fn group_leaf_matches_the_allocating_encoding() {
        let trace = trace();
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        for group in claims.chunks(CLAIM_LEAF_GROUP) {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(LEAF_DOMAIN);
            bytes.extend_from_slice(&(group.len() as u16).to_le_bytes());
            for claim in group {
                let encoded = claim.encode();
                bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&encoded);
            }
            assert_eq!(claim_group_leaf(group), magnetar_transcript::sha256(&bytes));
        }
    }

    #[test]
    fn group_root_binds_every_row() {
        let trace = trace();
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        let root = TraceClaimTree::build(&trace).root();
        assert_eq!(root, claim_root_of(&claims));
        assert!(verify_complete_leaves(root, &claims));
        for mutate in [
            |claims: &mut Vec<TraceClaim>| claims[0].instruction_len ^= 4,
            |claims: &mut Vec<TraceClaim>| claims[1].rd_value ^= 1,
            |claims: &mut Vec<TraceClaim>| {
                claims.pop();
            },
        ] {
            let mut tampered = claims.clone();
            mutate(&mut tampered);
            assert!(!verify_complete_leaves(root, &tampered));
        }
    }

    #[test]
    fn verified_claims_recover_row_fields() {
        let trace = trace();
        let proof = ClaimProof::from_trace(&trace);
        let claims = proof.verify().unwrap();
        assert_eq!(claims.len(), trace.rows.len());
        assert_eq!(claims[0].pc, 0x1000);
        assert_eq!(claims[0].instruction_len, 4);
        let mut bad = proof;
        bad.openings[0].claim.instruction_len = 2;
        assert!(bad.verify().is_none());
    }

    #[test]
    fn recovered_claims_match_trace() {
        let trace = trace();
        let proof = ClaimProof::from_trace(&trace);
        let claims = proof.verify().unwrap();
        assert!(verify_claims_against_trace(&trace, &claims));
        let mut bad = claims;
        bad[0].rd_value ^= 1;
        assert!(!verify_claims_against_trace(&trace, &bad));
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
    fn complete_claim_proof_rejects_removed_or_reordered_rows() {
        let trace = trace();
        let proof = ClaimProof::from_trace(&trace);
        assert!(proof.complete);
        let mut removed = proof.clone();
        removed.openings.pop();
        assert!(removed.verify().is_none());
        let mut reordered = proof;
        reordered.openings.swap(0, 1);
        assert!(reordered.verify().is_none());
    }

    #[test]
    fn tampered_claim_fields_are_rejected() {
        let trace = trace();
        let root = TraceClaimTree::build(&trace).root();
        let claims = trace
            .rows
            .iter()
            .map(TraceClaim::from_row)
            .collect::<Vec<_>>();
        for mutate in [
            |claim: &mut TraceClaim| claim.instruction_len ^= 4,
            |claim: &mut TraceClaim| claim.rd_value ^= 1,
            |claim: &mut TraceClaim| {
                claim.memory.push(TraceMemClaim {
                    cycle: 0,
                    addr: 1,
                    value: 2,
                    width: 8,
                    is_write: true,
                })
            },
        ] {
            let mut tampered = claims.clone();
            mutate(&mut tampered[0]);
            assert!(!verify_complete_leaves(root, &tampered));
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
