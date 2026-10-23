use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::binary_router::{prove_binary_router, BinaryRouterWitness, RouterMode};
use magnetar_runtime::packed_router::{prove_packed_router, verify_packed_router};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let program = ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Slli,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
                shamt: 2,
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
    let witness = BinaryRouterWitness::from_trace_mode(&trace, RouterMode::Shifts).unwrap();

    let started = Instant::now();
    let reference = prove_binary_router(&witness).unwrap();
    let reference_time = started.elapsed();
    let reference_bytes = bincode::serialize(&reference).unwrap().len();

    let started = Instant::now();
    let packed = prove_packed_router(&witness).unwrap();
    let packed_time = started.elapsed();
    let packed_bytes = bincode::serialize(&packed).unwrap().len();
    verify_packed_router(&witness, &packed).unwrap();

    println!("reference: {reference_bytes} B prove={reference_time:?}");
    let claims_bytes = bincode::serialize(&packed.claims).unwrap().len();
    let bit_bytes = bincode::serialize(&packed.bit_groups).unwrap().len();
    let field_bytes = bincode::serialize(&packed.field_groups).unwrap().len();
    println!("packed:    {packed_bytes} B prove={packed_time:?} claims={claims_bytes} bits={bit_bytes} fields={field_bytes}");
}
