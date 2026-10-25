use magnetar_executor::execute;
use magnetar_runtime::unified_gated::{prove_unified_gated, verify_unified_gated};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
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
    let proof = prove_unified_gated(&trace, 8).unwrap();
    verify_unified_gated(&trace, &proof, 8).unwrap();
    let revealed = magnetar_runtime::prove_unified_revealed(&trace, 8).unwrap();
    magnetar_runtime::verify_unified_trace(&trace, &revealed, 8).unwrap();
    println!(
        "revealed total {} opening {}",
        bincode::serialize(&revealed).unwrap().len(),
        revealed.opening.is_some()
    );
    println!(
        "e5 batch {} ring {} field {} field_commitment {} e5_field_tables {}",
        proof
            .unified
            .e5_opening
            .as_ref()
            .map(|opening| bincode::serialize(&opening.batch).unwrap().len())
            .unwrap_or(0),
        proof
            .unified
            .e5_opening
            .as_ref()
            .map(|opening| bincode::serialize(&opening.ring).unwrap().len())
            .unwrap_or(0),
        proof
            .unified
            .field_opening
            .as_ref()
            .map(|opening| bincode::serialize(opening).unwrap().len())
            .unwrap_or(0),
        proof
            .unified
            .field_pcs_commitment
            .as_ref()
            .map(|commitment| bincode::serialize(commitment).unwrap().len())
            .unwrap_or(0),
        proof.unified.field_tables.len(),
    );
    let p = &proof.unified;
    for (index, table) in p.commitment.tables.iter().enumerate() {
        println!(
            "table {index} columns {} vars {}",
            table.num_columns, table.num_variables
        );
    }
    println!("total {}", bincode::serialize(p).unwrap().len());
    println!("access {}", bincode::serialize(&p.access).unwrap().len());
    println!("cpu {}", bincode::serialize(&p.cpu).unwrap().len());
    println!("gated {}", bincode::serialize(&p.gated).unwrap().len());
    println!(
        "packed_shout {}",
        bincode::serialize(&p.packed_shout).unwrap().len()
    );
    println!("opening {}", bincode::serialize(&p.opening).unwrap().len());
    println!("shout {}", bincode::serialize(&p.shout).unwrap().len());
    println!(
        "shift {}",
        bincode::serialize(&p.shift_router).unwrap().len()
    );
    println!(
        "store {}",
        bincode::serialize(&p.store_router).unwrap().len()
    );
}
