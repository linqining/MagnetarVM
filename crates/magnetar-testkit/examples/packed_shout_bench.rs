use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::binary_shout::{prove_binary_shout, BinaryShoutWitness};
use magnetar_runtime::packed_shout::{prove_packed_shout, verify_packed_shout};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
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
    let witness = BinaryShoutWitness::from_trace(&trace).unwrap();

    let started = Instant::now();
    let reference = prove_binary_shout(&witness).unwrap();
    let reference_time = started.elapsed();
    let reference_bytes = bincode::serialize(&reference).unwrap().len();

    let started = Instant::now();
    let packed = prove_packed_shout(&witness).unwrap();
    let packed_time = started.elapsed();
    let packed_bytes = bincode::serialize(&packed).unwrap().len();
    verify_packed_shout(&witness, &packed).unwrap();

    println!("reference: {reference_bytes} B prove={reference_time:?}");
    println!("packed:    {packed_bytes} B prove={packed_time:?}");
}
