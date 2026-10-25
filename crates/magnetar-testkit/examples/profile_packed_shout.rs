use magnetar_executor::execute;
use magnetar_runtime::binary_shout::BinaryShoutWitness;
use magnetar_runtime::packed_shout::prove_packed_shout_profile;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512usize);
    let mut rom = Vec::new();
    for index in 0..rows.saturating_sub(1) {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: index as i64 + 1,
                shamt: 0,
            }
            .encode(),
        );
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    let trace = execute(
        &ProgramImage::new(0x1000, rom),
        MachineConfig {
            entry: 0x1000,
            rom_base: 0x1000,
            ram_base: 0x1000_0000,
            ram_size: 0x100,
            stack_top: 0x1000_0100,
            max_cycles: 1_000_000,
        },
    )
    .unwrap();
    let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
    let (proof, timings) = prove_packed_shout_profile(&witness).unwrap();
    println!("proof={}B", bincode::serialize(&proof).unwrap().len());
    for timing in timings {
        println!("{:>14}: {:?}", timing.stage, timing.duration);
    }
}
