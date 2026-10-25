use std::time::Instant;

use magnetar_executor::execute;
use magnetar_memory::BinaryTwistWitness;
use magnetar_runtime::binary_twist_address::{
    prove_address_multiplicity, verify_address_multiplicity,
};
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
            Instruction {
                op: Op::Lui,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 0x1000_0000,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sd,
                rd: 0,
                rs1: 2,
                rs2: 1,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Ld,
                rd: 3,
                rs1: 2,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
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
            max_cycles: 100,
        },
    )
    .unwrap()
}

fn main() {
    let trace = trace();
    let witness = BinaryTwistWitness::from_trace(&trace).unwrap();
    for (name, write) in [("read", false), ("write", true)] {
        let started = Instant::now();
        let proof = prove_address_multiplicity(&witness, write).unwrap();
        let prove_time = started.elapsed();
        let bytes = bincode::serialize(&proof).unwrap().len();
        let started = Instant::now();
        verify_address_multiplicity(&proof, write, &witness).unwrap();
        let verify_time = started.elapsed();
        println!(
            "{name}: proof={bytes} collision_rounds={} prove={prove_time:?} verify={verify_time:?}",
            proof.collision_rounds.len()
        );
    }
}
