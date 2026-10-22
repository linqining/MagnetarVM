use std::error::Error;

use magnetar_executor::ExecutionIo;
use magnetar_runtime::{
    encode_unified_proof, prove_unified_trace, run_guest_elf, verify_unified_statement,
};
use magnetar_spec::MachineConfig;

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/guest/hello.elf".to_string());
    let width = match std::env::args().nth(2) {
        Some(value) => value.parse::<usize>()?,
        None => 64,
    };

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

    println!("program: {path}");
    println!("rows: {}", outcome.trace.rows.len());
    println!("exit: {:?}", outcome.trace.exit_code);
    println!(
        "output: {}",
        String::from_utf8_lossy(&outcome.trace.io_output)
    );

    let proof = prove_unified_trace(&outcome.trace, width)?;
    let encoded = encode_unified_proof(&proof)?;
    verify_unified_statement(&outcome.statement, &proof, width)?;
    println!("proof: {} bytes, verified", encoded.len());
    Ok(())
}
