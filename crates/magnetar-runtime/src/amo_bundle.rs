//! Standalone AMO bundle proof collected from an executed trace.

use magnetar_spec::{Op, Trace};
use serde::{Deserialize, Serialize};

use crate::amo_add_row::{prove_amo_add_batch, verify_amo_add_batch};
use crate::amo_logic_row::{prove_amo_logic_batch, verify_amo_logic_batch, AmoLogicKind};
use crate::amo_minmax_row::{prove_amo_minmax_batch, verify_amo_minmax_batch, AmoMinMaxKind};
use crate::lr_row::{prove_lr_batch, verify_lr_batch};
use crate::reservation_row::{prove_reservation_batch, verify_reservation_batch};
use crate::sc_row::{prove_sc_batch, verify_sc_batch};
use crate::RuntimeError;

type AmoProof = magnetar_proof::SpartanProof<magnetar_pcs::P3Commitment, magnetar_pcs::P3Opening>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AmoBundleProof {
    pub add: Option<AmoProof>,
    pub xor: Option<AmoProof>,
    pub and: Option<AmoProof>,
    pub or: Option<AmoProof>,
    pub swap: Option<AmoProof>,
    pub min: Option<AmoProof>,
    pub max: Option<AmoProof>,
    pub minu: Option<AmoProof>,
    pub maxu: Option<AmoProof>,
    pub lr: Option<AmoProof>,
    pub sc: Option<AmoProof>,
    pub reservation: Option<AmoProof>,
}

#[derive(Default)]
struct Rows {
    add: Vec<(u64, u64, u64)>,
    xor: Vec<(u64, u64, u64)>,
    and: Vec<(u64, u64, u64)>,
    or: Vec<(u64, u64, u64)>,
    swap: Vec<(u64, u64, u64)>,
    min: Vec<(u64, u64, u64)>,
    max: Vec<(u64, u64, u64)>,
    minu: Vec<(u64, u64, u64)>,
    maxu: Vec<(u64, u64, u64)>,
    lr: Vec<(u64, u64)>,
    sc: Vec<(u64, u64, u64, bool)>,
    reservation: Vec<(u64, u64, bool, bool, bool, bool)>,
}

fn collect(trace: &Trace) -> Rows {
    let mut rows = Rows::default();
    for row in &trace.rows {
        let Some(mem) = row.mem else {
            continue;
        };
        let event = (row.rd_val, row.rs2_val, mem.addr);
        match row.instruction.op {
            Op::AmoaddW | Op::AmoaddD => rows.add.push(event),
            Op::AmoxorW | Op::AmoxorD => rows.xor.push(event),
            Op::AmoandW | Op::AmoandD => rows.and.push(event),
            Op::AmoorW | Op::AmoorD => rows.or.push(event),
            Op::AmoswapW | Op::AmoswapD => rows.swap.push(event),
            Op::AmominW | Op::AmominD => rows.min.push(event),
            Op::AmomaxW | Op::AmomaxD => rows.max.push(event),
            Op::AmominuW | Op::AmominuD => rows.minu.push(event),
            Op::AmomaxuW | Op::AmomaxuD => rows.maxu.push(event),
            Op::LrW | Op::LrD => {
                let mask = if mem.width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (u32::from(mem.width) * 8)) - 1
                };
                rows.lr.push((row.rd_val & mask, mem.addr));
            }
            Op::ScW | Op::ScD => {
                let mask = if mem.width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (u32::from(mem.width) * 8)) - 1
                };
                let old = memory_before(trace, mem.addr, mem.width, row.cycle, mask).unwrap_or(0);
                rows.sc
                    .push((old, row.rs2_val & mask, mem.addr, row.rd_val == 0));
            }
            _ => {}
        }
        let addr = row.mem.map(|mem| mem.addr).unwrap_or(0);
        let res_addr = row.reservation_before.unwrap_or(0);
        rows.reservation.push((
            addr,
            res_addr,
            row.reservation_before.is_some(),
            matches!(row.instruction.op, Op::LrW | Op::LrD),
            matches!(row.instruction.op, Op::ScW | Op::ScD),
            is_amo_op(row.instruction.op) || is_store_op(row.instruction.op),
        ));
    }
    rows
}

fn pad(mut rows: Vec<(u64, u64, u64)>) -> Option<Vec<(u64, u64, u64)>> {
    if rows.is_empty() {
        return None;
    }
    while !rows.len().is_power_of_two() {
        rows.push((0, 0, 0));
    }
    Some(rows)
}

impl AmoBundleProof {
    pub fn is_empty(&self) -> bool {
        self.add.is_none()
            && self.xor.is_none()
            && self.and.is_none()
            && self.or.is_none()
            && self.swap.is_none()
            && self.min.is_none()
            && self.max.is_none()
            && self.minu.is_none()
            && self.maxu.is_none()
            && self.lr.is_none()
            && self.sc.is_none()
            && self.reservation.is_none()
    }
}

pub fn has_amo_events(trace: &Trace) -> bool {
    let rows = collect(trace);
    !rows.add.is_empty()
        || !rows.xor.is_empty()
        || !rows.and.is_empty()
        || !rows.or.is_empty()
        || !rows.swap.is_empty()
        || !rows.min.is_empty()
        || !rows.max.is_empty()
        || !rows.minu.is_empty()
        || !rows.maxu.is_empty()
        || !rows.lr.is_empty()
        || !rows.sc.is_empty()
        || !rows.reservation.is_empty()
}

fn pad_lr(mut rows: Vec<(u64, u64)>) -> Option<Vec<(u64, u64)>> {
    if rows.is_empty() {
        return None;
    }
    while !rows.len().is_power_of_two() {
        rows.push((0, 0));
    }
    Some(rows)
}

#[allow(clippy::type_complexity)]
fn pad_reservation(
    mut rows: Vec<(u64, u64, bool, bool, bool, bool)>,
) -> Option<Vec<(u64, u64, bool, bool, bool, bool)>> {
    if rows.is_empty() {
        return None;
    }
    while !rows.len().is_power_of_two() {
        rows.push((0, 0, false, false, false, false));
    }
    Some(rows)
}

fn pad_sc(mut rows: Vec<(u64, u64, u64, bool)>) -> Option<Vec<(u64, u64, u64, bool)>> {
    if rows.is_empty() {
        return None;
    }
    while !rows.len().is_power_of_two() {
        rows.push((0, 0, 0, false));
    }
    Some(rows)
}

pub fn prove_amo_bundle(trace: &Trace, width: usize) -> Result<AmoBundleProof, RuntimeError> {
    let rows = collect(trace);
    let add = pad(rows.add)
        .map(|rows| prove_amo_add_batch(width, &rows))
        .transpose()?;
    let xor = pad(rows.xor)
        .map(|rows| prove_amo_logic_batch(width, AmoLogicKind::Xor, &rows))
        .transpose()?;
    let and = pad(rows.and)
        .map(|rows| prove_amo_logic_batch(width, AmoLogicKind::And, &rows))
        .transpose()?;
    let or = pad(rows.or)
        .map(|rows| prove_amo_logic_batch(width, AmoLogicKind::Or, &rows))
        .transpose()?;
    let swap = pad(rows.swap)
        .map(|rows| prove_amo_logic_batch(width, AmoLogicKind::Swap, &rows))
        .transpose()?;
    let min = pad(rows.min)
        .map(|rows| prove_amo_minmax_batch(width, AmoMinMaxKind::Min, &rows))
        .transpose()?;
    let max = pad(rows.max)
        .map(|rows| prove_amo_minmax_batch(width, AmoMinMaxKind::Max, &rows))
        .transpose()?;
    let minu = pad(rows.minu)
        .map(|rows| prove_amo_minmax_batch(width, AmoMinMaxKind::Minu, &rows))
        .transpose()?;
    let maxu = pad(rows.maxu)
        .map(|rows| prove_amo_minmax_batch(width, AmoMinMaxKind::Maxu, &rows))
        .transpose()?;
    let reservation = pad_reservation(rows.reservation)
        .map(|rows| prove_reservation_batch(width, &rows))
        .transpose()?;
    let lr = pad_lr(rows.lr)
        .map(|rows| prove_lr_batch(width, &rows))
        .transpose()?;
    let sc = pad_sc(rows.sc)
        .map(|rows| prove_sc_batch(width, &rows))
        .transpose()?;
    Ok(AmoBundleProof {
        add,
        xor,
        and,
        or,
        swap,
        min,
        max,
        minu,
        maxu,
        lr,
        sc,
        reservation,
    })
}

#[allow(clippy::type_complexity)]
fn memory_before(trace: &Trace, addr: u64, width: u8, cycle: u64, mask: u64) -> Option<u64> {
    let mut value = None;
    for event in &trace.memory_events {
        if event.cycle >= cycle {
            break;
        }
        if event.access.addr == addr && event.access.is_write {
            value = Some(event.access.value & mask);
        }
    }
    if value.is_some() {
        return value;
    }
    let index = trace.config.ram_index(addr, width as usize)?;
    let bytes = trace.initial_ram.get(index..index + width as usize)?;
    let mut value = 0u64;
    for (byte, shift) in bytes.iter().zip(0..) {
        value |= u64::from(*byte) << (8 * shift);
    }
    Some(value & mask)
}

fn check_memory_events(trace: &Trace) -> Result<(), RuntimeError> {
    for row in &trace.rows {
        let Some(mem) = row.mem else {
            continue;
        };
        if !matches!(
            row.instruction.op,
            Op::AmoaddW
                | Op::AmoaddD
                | Op::AmoxorW
                | Op::AmoxorD
                | Op::AmoandW
                | Op::AmoandD
                | Op::AmoorW
                | Op::AmoorD
                | Op::AmoswapW
                | Op::AmoswapD
                | Op::AmominW
                | Op::AmominD
                | Op::AmomaxW
                | Op::AmomaxD
                | Op::AmominuW
                | Op::AmominuD
                | Op::AmomaxuW
                | Op::AmomaxuD
        ) {
            continue;
        }
        let bits = u32::from(mem.width) * 8;
        let mask = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let old = row.rd_val & mask;
        let operand = row.rs2_val & mask;
        let new = match row.instruction.op {
            Op::AmoaddW | Op::AmoaddD => old.wrapping_add(operand),
            Op::AmoxorW | Op::AmoxorD => old ^ operand,
            Op::AmoandW | Op::AmoandD => old & operand,
            Op::AmoorW | Op::AmoorD => old | operand,
            Op::AmoswapW | Op::AmoswapD => operand,
            Op::AmominW | Op::AmominD => {
                let (a, b) = (
                    if bits == 32 {
                        (old as u32 as i32) as i64
                    } else {
                        old as i64
                    },
                    if bits == 32 {
                        (operand as u32 as i32) as i64
                    } else {
                        operand as i64
                    },
                );
                if a < b {
                    old
                } else {
                    operand
                }
            }
            Op::AmomaxW | Op::AmomaxD => {
                let (a, b) = (
                    if bits == 32 {
                        (old as u32 as i32) as i64
                    } else {
                        old as i64
                    },
                    if bits == 32 {
                        (operand as u32 as i32) as i64
                    } else {
                        operand as i64
                    },
                );
                if a < b {
                    operand
                } else {
                    old
                }
            }
            Op::AmominuW | Op::AmominuD => old.min(operand),
            Op::AmomaxuW | Op::AmomaxuD => old.max(operand),
            _ => continue,
        } & mask;
        if let Some(prior) = memory_before(trace, mem.addr, mem.width, row.cycle, mask) {
            if prior != old {
                return Err(RuntimeError::Proof(
                    "AMO old value is not the latest memory value".into(),
                ));
            }
        }
        let write_ok = trace.memory_events.iter().any(|event| {
            event.access.addr == mem.addr
                && event.access.is_write
                && (event.access.value & mask) == new
        });
        if !write_ok {
            return Err(RuntimeError::Proof(
                "AMO event is not consistent with memory_events".into(),
            ));
        }
    }
    Ok(())
}

fn is_amo_op(op: Op) -> bool {
    matches!(
        op,
        Op::AmoaddW
            | Op::AmoaddD
            | Op::AmoxorW
            | Op::AmoxorD
            | Op::AmoandW
            | Op::AmoandD
            | Op::AmoorW
            | Op::AmoorD
            | Op::AmoswapW
            | Op::AmoswapD
            | Op::AmominW
            | Op::AmominD
            | Op::AmomaxW
            | Op::AmomaxD
            | Op::AmominuW
            | Op::AmominuD
            | Op::AmomaxuW
            | Op::AmomaxuD
    )
}

fn is_store_op(op: Op) -> bool {
    matches!(op, Op::Sb | Op::Sh | Op::Sw | Op::Sd)
}

fn check_reservations(trace: &Trace) -> Result<(), RuntimeError> {
    let mut current = None;
    for row in &trace.rows {
        if row.reservation_before != current {
            return Err(RuntimeError::Proof(
                "reservation_before does not chain".into(),
            ));
        }
        let after = match row.instruction.op {
            Op::LrW | Op::LrD => {
                let Some(mem) = row.mem else {
                    return Err(RuntimeError::Proof("LR without memory access".into()));
                };
                Some(mem.addr)
            }
            Op::ScW | Op::ScD => {
                if row.rd_val == 0 {
                    let Some(mem) = row.mem else {
                        return Err(RuntimeError::Proof("SC without memory access".into()));
                    };
                    if row.reservation_before != Some(mem.addr) {
                        return Err(RuntimeError::Proof(
                            "successful SC without matching reservation".into(),
                        ));
                    }
                }
                None
            }
            op if is_amo_op(op) || is_store_op(op) => None,
            _ => row.reservation_after,
        };
        if after != row.reservation_after {
            return Err(RuntimeError::Proof(
                "reservation_after does not match the operation".into(),
            ));
        }
        current = after;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn verify_amo_bundle(
    trace: &Trace,
    width: usize,
    proof: &AmoBundleProof,
) -> Result<(), RuntimeError> {
    check_memory_events(trace)?;
    check_reservations(trace)?;
    let rows = collect(trace);
    let expected =
        |rows: &Vec<(u64, u64, u64)>, present: bool, label: &str| -> Result<usize, RuntimeError> {
            let count = pad(rows.clone()).map(|r| r.len()).unwrap_or(0);
            if (count > 0) != present {
                return Err(RuntimeError::Proof(format!("AMO bundle {label} presence")));
            }
            Ok(count)
        };
    if let Some(proof) = &proof.add {
        verify_amo_add_batch(width, expected(&rows.add, true, "add")?, proof)?;
    } else {
        let _ = expected(&rows.add, false, "add")?;
    }
    let logic: [(&Option<AmoProof>, AmoLogicKind, &Vec<(u64, u64, u64)>, &str); 4] = [
        (&proof.xor, AmoLogicKind::Xor, &rows.xor, "xor"),
        (&proof.and, AmoLogicKind::And, &rows.and, "and"),
        (&proof.or, AmoLogicKind::Or, &rows.or, "or"),
        (&proof.swap, AmoLogicKind::Swap, &rows.swap, "swap"),
    ];
    for (proof, kind, rows, label) in logic {
        if let Some(proof) = proof {
            verify_amo_logic_batch(width, kind, expected(rows, true, label)?, proof)?;
        } else {
            let _ = expected(rows, false, label)?;
        }
    }
    let minmax: [(
        &Option<AmoProof>,
        AmoMinMaxKind,
        &Vec<(u64, u64, u64)>,
        &str,
    ); 4] = [
        (&proof.min, AmoMinMaxKind::Min, &rows.min, "min"),
        (&proof.max, AmoMinMaxKind::Max, &rows.max, "max"),
        (&proof.minu, AmoMinMaxKind::Minu, &rows.minu, "minu"),
        (&proof.maxu, AmoMinMaxKind::Maxu, &rows.maxu, "maxu"),
    ];
    for (proof, kind, rows, label) in minmax {
        if let Some(proof) = proof {
            verify_amo_minmax_batch(width, kind, expected(rows, true, label)?, proof)?;
        } else {
            let _ = expected(rows, false, label)?;
        }
    }
    if let Some(proof) = &proof.lr {
        let rows = pad_lr(rows.lr.clone())
            .ok_or_else(|| RuntimeError::Proof("LR bundle missing".into()))?;
        verify_lr_batch(width, rows.len(), proof)?;
    } else if !rows.lr.is_empty() {
        return Err(RuntimeError::Proof("LR bundle presence".into()));
    }
    if let Some(proof) = &proof.sc {
        let rows = pad_sc(rows.sc.clone())
            .ok_or_else(|| RuntimeError::Proof("SC bundle missing".into()))?;
        verify_sc_batch(width, rows.len(), proof)?;
    } else if !rows.sc.is_empty() {
        return Err(RuntimeError::Proof("SC bundle presence".into()));
    }
    if let Some(proof) = &proof.reservation {
        let rows = pad_reservation(rows.reservation.clone())
            .ok_or_else(|| RuntimeError::Proof("reservation bundle missing".into()))?;
        verify_reservation_batch(width, rows.len(), proof)?;
    } else if !rows.reservation.is_empty() {
        return Err(RuntimeError::Proof("reservation bundle presence".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetar_executor::execute;
    use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

    #[test]
    fn amo_bundle_proves() {
        let program = ProgramImage::new(
            0x1000,
            vec![
                Instruction {
                    op: Op::Lui,
                    rd: 4,
                    rs1: 0,
                    rs2: 0,
                    imm: 0x1000_0000,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: 10,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Sd,
                    rd: 0,
                    rs1: 4,
                    rs2: 1,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: 5,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmoaddD,
                    rd: 3,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmoswapW,
                    rd: 5,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmoxorD,
                    rd: 6,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::AmomaxD,
                    rd: 7,
                    rs1: 4,
                    rs2: 2,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::LrD,
                    rd: 9,
                    rs1: 4,
                    rs2: 0,
                    imm: 0,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::Addi,
                    rd: 10,
                    rs1: 0,
                    rs2: 0,
                    imm: 9,
                    shamt: 0,
                }
                .encode(),
                Instruction {
                    op: Op::ScD,
                    rd: 11,
                    rs1: 4,
                    rs2: 10,
                    imm: 0,
                    shamt: 0,
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
                ram_size: 0x100,
                stack_top: 0x1000_0080,
                max_cycles: 100,
            },
        )
        .unwrap();
        let proof = prove_amo_bundle(&trace, 8).unwrap();
        verify_amo_bundle(&trace, 8, &proof).unwrap();
        let mut bad = trace.clone();
        if let Some(row) = bad
            .rows
            .iter_mut()
            .find(|row| matches!(row.instruction.op, Op::LrD))
        {
            row.reservation_after = None;
        }
        assert!(check_reservations(&bad).is_err());
    }
}
