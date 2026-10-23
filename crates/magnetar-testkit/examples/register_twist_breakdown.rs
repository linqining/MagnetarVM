use magnetar_executor::execute;
use magnetar_runtime::binary_twist::prove_binary_twist_ram;
use magnetar_runtime::gated_register::{
    gated_register_events_from_trace, gated_register_twist_witness,
};
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
    let (events, initial) = gated_register_events_from_trace(&trace).unwrap();
    let witness = gated_register_twist_witness(&events, &initial).unwrap();
    let proof = prove_binary_twist_ram(&witness).unwrap();
    println!("total {}", bincode::serialize(&proof).unwrap().len());
    println!(
        "boolean {}",
        bincode::serialize(&proof.boolean).unwrap().len()
    );
    println!("read {}", bincode::serialize(&proof.read).unwrap().len());
    println!("write {}", bincode::serialize(&proof.write).unwrap().len());
    println!(
        "update {}",
        bincode::serialize(&proof.update).unwrap().len()
    );
    println!(
        "opening {}",
        bincode::serialize(&proof.opening).unwrap().len()
    );
}
