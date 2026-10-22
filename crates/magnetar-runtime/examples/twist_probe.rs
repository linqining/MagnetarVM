use std::time::Instant;

use magnetar_executor::ExecutionIo;
use magnetar_memory::BinaryTwistWitness;
use magnetar_runtime::binary_twist::{prove_binary_twist_ram, verify_binary_twist_ram};
use magnetar_runtime::run_guest_elf;
use magnetar_spec::MachineConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/guest/hello.elf".to_string());
    let bytes = std::fs::read(&path)?;
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x10000,
        stack_top: 0x1000_8000,
        max_cycles: 10_000,
    };
    let mut io = ExecutionIo::default();
    let outcome = run_guest_elf(&bytes, config, 8, &mut io)?;
    let witness = BinaryTwistWitness::from_trace(&outcome.trace)?;
    println!(
        "rows={} cells={} cycles={} padded_cycles={}",
        outcome.trace.rows.len(),
        witness.initial.len(),
        witness.cycles,
        witness.cycles.next_power_of_two(),
    );

    let started = Instant::now();
    let proof = prove_binary_twist_ram(&witness)?;
    println!("prove: {:?}", started.elapsed());
    let bytes = bincode::serialize(&proof)?;
    println!("proof bytes: {}", bytes.len());
    let started = Instant::now();
    let ok = verify_binary_twist_ram(&witness, &proof)?;
    println!("verify: {:?} ok={ok}", started.elapsed());
    Ok(())
}
