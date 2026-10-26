use magnetar_executor::execute;
use magnetar_runtime::binary_shout::BinaryShoutWitness;
use magnetar_runtime::logup_shout::{logup_shout_proof_size, prove_logup_shout, verify_logup_shout};
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

#[test]
fn runtime_logup_shout_round_trips() {
    let rows = std::env::var("ROWS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(128);
    let mut rom = Vec::new();
    for index in 0..rows.saturating_sub(1) {
        rom.push(
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 1,
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
            max_cycles: 10_000_000,
        },
    )
    .unwrap();
    let witness = BinaryShoutWitness::from_trace(&trace).unwrap();
    let started = std::time::Instant::now();
    let proof = prove_logup_shout(&witness).unwrap();
    let prove = started.elapsed();
    let started = std::time::Instant::now();
    verify_logup_shout(&proof, &witness.rom).unwrap();
    eprintln!(
        "runtime logup Shout rows={rows} prove={prove:?} verify={:?} bytes={}",
        started.elapsed(),
        logup_shout_proof_size(&proof).unwrap()
    );
    eprintln!(
        "  logup={}B opening={}B reader_claims={}B links={}B rom_claims={}B",
        bincode::serialize(&proof.logup).unwrap().len(),
        bincode::serialize(&proof.opening).unwrap().len(),
        bincode::serialize(&proof.reader_claims).unwrap().len(),
        bincode::serialize(&proof.link_claims).unwrap().len(),
        bincode::serialize(&proof.rom_claims).unwrap().len()
    );
    let mut bad = proof;
    bad.reader_claims[0] = bad.reader_claims[0] + magnetar_constraint::F2_128::from(1u64);
    assert!(verify_logup_shout(&bad, &witness.rom).is_err());
}
