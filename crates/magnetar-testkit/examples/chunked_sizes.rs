use magnetar_executor::execute;
use magnetar_runtime::{
    chunked_proof_sizes, prove_chunked_trace, prove_unified_trace, unified_proof_sizes,
    verify_chunked_trace,
};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn main() {
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 1000,
    };
    let mut rom = Vec::new();
    for index in 0..16 {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1 + (index % 8) as u8,
                rs1: 1 + (index % 8) as u8,
                rs2: 0,
                imm: 1,
                shamt: 0,
            }
            .encode(),
        );
    }
    rom.push(Instruction::new(Op::Ecall).encode());
    let program = ProgramImage::new(0x1000, rom);
    let trace = execute(&program, config).unwrap();
    let unified = prove_unified_trace(&trace, 8).unwrap();
    let unified_sizes = unified_proof_sizes(&unified).unwrap();
    println!(
        "unified: total {} access {} cpu {} gated {:?} opening {:?}",
        unified_sizes.total(),
        unified_sizes.access,
        unified_sizes.cpu,
        unified_sizes.gated,
        unified_sizes.opening
    );
    for chunk in [2usize, 4, 8, 16] {
        let proof = prove_chunked_trace(&trace, 8, chunk).unwrap();
        let sizes = chunked_proof_sizes(&proof).unwrap();
        verify_chunked_trace(&trace, &proof, 8).unwrap();
        let shape_bytes = proof
            .chunks
            .iter()
            .map(|chunk| bincode::serialize(&chunk.shape).unwrap().len())
            .sum::<usize>();
        println!(
            "chunk {chunk}: total {} access {} cpu {} (shape {}) aux {} chain {}",
            sizes.total(),
            sizes.access,
            sizes.cpu,
            shape_bytes,
            sizes.aux,
            sizes.chain
        );
    }
}
