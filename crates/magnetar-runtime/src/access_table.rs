//! M5b groundwork: committed memory/register event columns for the access layer.
//!
//! Design: `docs/POLYLOG_CLAIM_VERIFIER.md` §C.12. The access statement is
//! currently rebuilt from the claim rows (`AccessStatement::from_claims`) in
//! O(rows) and hashed with a serial digest (6.7 ms at 2^16). M5b commits the
//! event fields as packed bit columns inside the claim table so that
//!
//! 1. the access statement digest becomes `H("magnetar-access-v4" || table_root)`
//!    (O(1), derived from the statement-bound claim-table commitment), and
//! 2. the access verifier can bind the twist claims to the committed columns
//!    with one multi-group claim relation, deleting the witness rebuild.
//!
//! Layout (fixed order, `MEMORY_EVENTS_PER_CYCLE` = 2):
//! memory event e: present, is_write, width bit0, width bit1, addr bit 0..63,
//! width bit 0..3, addr bit 0..63, value bit 0..63  (= 134 columns per event, 268 total);
//! register op r (rd, rs1, rs2): present, index bit 0..4, value bit 0..63
//! (= 70 columns per op, 210 total); access columns = 478.
//!
//! These columns are appended after the M2/M3 claim schema slots in the v4
//! table: schema slots (512) + access columns (478) -> 1024 total slots.
//!
//! Everything here is opt-in (`MAGNETAR_ACCESS_COLUMNS=1` + `MAGNETAR_CLAIM_V4=1`
//! through the caller); the default path is untouched.

use magnetar_proof::PackedBits;

use crate::RuntimeError;

/// Maximum memory events committed per cycle (executor rows carry `mem` plus
/// `extra_mem`; two slots cover the current RV64 shapes). A trace exceeding it
/// is rejected at statement construction.
pub const MEMORY_EVENTS_PER_CYCLE: usize = 2;
/// Register operations committed per cycle (`rd`, `rs1`, `rs2`).
pub const REGISTER_OPS_PER_CYCLE: usize = 3;
/// Bits committed per memory event: present + write + width(4) + addr(64) + value(64).
/// `width` is the byte count (1/2/4/8), so it needs four bits.
pub const MEMORY_EVENT_BITS: usize = 1 + 1 + 4 + 64 + 64;
/// Bits committed per register op: present + index(5) + value(64).
pub const REGISTER_OP_BITS: usize = 1 + 5 + 64;
/// Total access columns.
pub const ACCESS_COLUMN_COUNT: usize =
    MEMORY_EVENTS_PER_CYCLE * MEMORY_EVENT_BITS + REGISTER_OPS_PER_CYCLE * REGISTER_OP_BITS;

/// Is the M5b access-column path enabled? Default off.
pub fn access_columns_enabled() -> bool {
    crate::trace_free::trace_free_enabled()
        || matches!(
            std::env::var("MAGNETAR_ACCESS_COLUMNS").ok().as_deref(),
            Some("1" | "on" | "true" | "yes")
        )
}

/// Domain of the O(1) access statement digest (M5b).
pub const ACCESS_V4_DOMAIN: &[u8] = b"magnetar-access-v4";

/// O(1) access statement digest derived from the v4 claim-table root.
///
/// Replaces `AccessStatement::from_claims(...).digest()` once the memory and
/// register columns are committed in `T` (§C.12.4).
pub fn access_statement_digest(claim_table_v4_root: &[u8; 32]) -> [u8; 32] {
    let mut bytes = ACCESS_V4_DOMAIN.to_vec();
    bytes.extend_from_slice(claim_table_v4_root);
    magnetar_transcript::sha256(&bytes)
}

/// Committed per-cycle access columns (cycle-major bit vectors; padding cycles 0).
#[derive(Clone, Debug)]
pub struct AccessColumns {
    pub cycles: usize,
    /// `ACCESS_COLUMN_COUNT` columns of `cycles` bits each, fixed layout above.
    pub columns: Vec<Vec<bool>>,
}

impl AccessColumns {
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }
}

fn push_word(columns: &mut [Vec<bool>], offset: usize, cycle: usize, value: u64) {
    for bit in 0..64 {
        columns[offset + bit][cycle] = (value >> bit) & 1 == 1;
    }
}

/// Build the committed access columns from the trace at statement construction.
///
/// Same trust model as the M2/M3 claim table: the statement is built from the
/// trace, and the v4 root binds this commitment.
pub fn access_columns_from_trace(
    trace: &magnetar_spec::Trace,
) -> Result<AccessColumns, RuntimeError> {
    let cycles = trace.rows.len().next_power_of_two().max(2);
    let mut columns = vec![vec![false; cycles]; ACCESS_COLUMN_COUNT];
    for (cycle, row) in trace.rows.iter().enumerate() {
        let claim = crate::trace_claims::TraceClaim::from_row(row);
        // Memory events: `claim.memory` already merges `mem` and `extra_mem`.
        if claim.memory.len() > MEMORY_EVENTS_PER_CYCLE {
            return Err(RuntimeError::Proof(
                "M5b: more memory events per cycle than the committed slots".into(),
            ));
        }
        for (event_index, event) in claim.memory.iter().enumerate() {
            let base = event_index * MEMORY_EVENT_BITS;
            columns[base][cycle] = true;
            columns[base + 1][cycle] = event.is_write;
            for bit in 0..4 {
                columns[base + 2 + bit][cycle] = (event.width >> bit) & 1 == 1;
            }
            push_word(&mut columns, base + 6, cycle, event.addr);
            push_word(&mut columns, base + 70, cycle, event.value);
        }
        // Register ops: rd, rs1, rs2 in that fixed order.
        let register_obits = MEMORY_EVENTS_PER_CYCLE * MEMORY_EVENT_BITS;
        let ops = [
            (claim.rd_present, claim.rd, claim.rd_value),
            (claim.rs1_present, claim.rs1, claim.rs1_value),
            (claim.rs2_present, claim.rs2, claim.rs2_value),
        ];
        for (op_index, (present, index, value)) in ops.iter().enumerate() {
            let base = register_obits + op_index * REGISTER_OP_BITS;
            columns[base][cycle] = *present;
            for bit in 0..5 {
                columns[base + 1 + bit][cycle] = (u64::from(*index) >> bit) & 1 == 1;
            }
            push_word(&mut columns, base + 6, cycle, *value);
        }
    }
    Ok(AccessColumns { cycles, columns })
}

/// Pack the access columns stage of a v4 table: the columns occupy
/// `ACCESS_COLUMN_COUNT` slots (padded to a power of two by the caller with the
/// claim schema slots) and each slot holds `cycles` bits.
///
/// Returns the packed bit table for the access region alone; the v4 table
/// builder concatenates it after the schema region in slot order.
pub fn access_bits(access: &AccessColumns) -> (PackedBits, usize) {
    let slots = ACCESS_COLUMN_COUNT.next_power_of_two();
    let mut bits = PackedBits::zeroed(slots * access.cycles);
    for (column, values) in access.columns.iter().enumerate() {
        for (cycle, bit) in values.iter().enumerate() {
            if *bit {
                bits.set(column * access.cycles + cycle, true);
            }
        }
    }
    (bits, slots)
}

/// Slot-bits packing: the v4 table's slot dimension (schema slots + access
/// slots) must hold the combined column count.
pub fn combined_slot_bits(schema_slots: usize) -> usize {
    let columns = schema_slots + ACCESS_COLUMN_COUNT;
    let mut slot_bits = 1usize;
    while (1usize << slot_bits) < columns.max(2) {
        slot_bits += 1;
    }
    // Same PCS folding minimum as `claim_table::slot_bits_for`: at least 1024
    // packed bits at the current cycle count is enforced by the caller.
    slot_bits
}

/// Pack the combined v4 table: schema slots first (unchanged order), then the
/// access columns, then zero padding to `2^combined_slot_bits`.
pub fn combined_bits(
    schema_bits: &PackedBits,
    schema_slots: usize,
    schema_cycles: usize,
    access_bits: &PackedBits,
    access_slots: usize,
) -> Result<(PackedBits, usize), RuntimeError> {
    if schema_bits.len() != schema_slots * schema_cycles
        || access_bits.len() != access_slots * schema_cycles
    {
        return Err(RuntimeError::Proof(
            "M5b: combined table shape mismatch".into(),
        ));
    }
    let slot_bits = combined_slot_bits(schema_slots);
    let total_slots = 1usize << slot_bits;
    if schema_slots + access_slots > total_slots {
        return Err(RuntimeError::Proof(
            "M5b: combined table slots overflow".into(),
        ));
    }
    let mut bits = PackedBits::zeroed(total_slots * schema_cycles);
    for cycle in 0..schema_cycles {
        for slot in 0..schema_slots {
            if schema_bits.get(slot * schema_cycles + cycle) {
                bits.set(slot * schema_cycles + cycle, true);
            }
        }
        for slot in 0..access_slots {
            if access_bits.get(slot * schema_cycles + cycle) {
                bits.set((schema_slots + slot) * schema_cycles + cycle, true);
            }
        }
    }
    Ok((bits, total_slots))
}

/// Host-side digest of the v4 combined table (used for the statement root and
/// the O(1) access digest). F2 mirrors the claim-table commitment encoding.
pub fn combined_table_commitment(
    schema: &crate::claim_table::ClaimTableColumns,
    access: &AccessColumns,
) -> Result<(magnetar_pcs::P3Commitment, usize), RuntimeError> {
    let (schema_bits, _schema_slots) = {
        let bits = crate::claim_table::claim_table_bits(schema);
        (bits, schema.slot_count())
    };
    let schema_slots = schema.slot_count();
    let (access_bits, access_slots) = access_bits(access);
    let (bits, total_slots) =
        combined_bits(&schema_bits, schema_slots, schema.cycles, &access_bits, access_slots)?;
    let commitment = crate::claim_table::commit_claim_table(&bits)?;
    Ok((commitment, total_slots))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    fn trace() -> magnetar_spec::Trace {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 7,
                    shamt: 0,
                }
                .encode(),
                Instruction::new(Op::Ecall).encode(),
            ],
        );
        magnetar_executor::execute(
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
        .unwrap()
    }

    #[test]
    fn access_layout_and_digest_are_stable() {
        assert_eq!(ACCESS_COLUMN_COUNT, 478);
        assert_eq!(MEMORY_EVENTS_PER_CYCLE * MEMORY_EVENT_BITS, 268);
        assert_eq!(REGISTER_OPS_PER_CYCLE * REGISTER_OP_BITS, 210);
        assert_eq!(combined_slot_bits(512), 10);
        let digest = access_statement_digest(&[7u8; 32]);
        assert_ne!(digest, [0u8; 32]);
        assert_ne!(digest, access_statement_digest(&[8u8; 32]));
        assert_eq!(digest, access_statement_digest(&[7u8; 32]));
    }

    #[test]
    fn access_columns_from_trace_have_the_fixed_shape() {
        let trace = trace();
        let cycles = trace.rows.len().next_power_of_two().max(2);
        let access = access_columns_from_trace(&trace).unwrap();
        assert_eq!(access.cycles, cycles);
        assert_eq!(access.column_count(), ACCESS_COLUMN_COUNT);
        // The first row has rd = 1 present and no memory events.
        assert!(access.columns[268][0], "rd present bit not set");
        assert!(!access.columns[0][0], "memory present bit must be clear");
        // Padding cycles carry no events and no register ops.
        for cycle in trace.rows.len()..cycles {
            assert!(!access.columns[268][cycle]);
        }
    }

    #[test]
    fn combined_table_packs_schema_then_access() {
        let trace = trace();
        let schema = crate::claim_table::claim_table_columns(&trace).unwrap();
        let access = access_columns_from_trace(&trace).unwrap();
        let (commitment, total_slots) = combined_table_commitment(&schema, &access).unwrap();
        assert_eq!(total_slots, 1024);
        // The PCS packs 128 bits per field element and may pad up to its
        // folding minimum, so the commitment arity is at least
        // log2(total_slots * cycles / 128) and never more than the total bit
        // count.
        let fields = total_slots * access.cycles / 128;
        assert!((1usize << commitment.num_variables) >= fields);
        assert!(
            commitment.num_variables
                <= total_slots.trailing_zeros() as usize + access.cycles.trailing_zeros() as usize
        );
    }
}
