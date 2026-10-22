use std::error::Error;
use std::time::Instant;

use magnetar_executor::ExecutionIo;
use magnetar_runtime::{
    encode_unified_proof, prove_unified_trace, run_guest_elf, trace_cpu_stats, unified_proof_sizes,
    verify_unified_statement,
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

    let stats = trace_cpu_stats(&outcome.trace, width)?;
    println!(
        "cpu system: width={} vars={} constraints={}",
        stats.width, stats.variables, stats.constraints
    );
    for row in &stats.rows {
        println!(
            "  cycle={:<3} pc={:#06x} op={:<6} vars={:<6} constraints={}",
            row.cycle, row.pc, row.op, row.variables, row.constraints
        );
    }

    let started = Instant::now();
    let proof = prove_unified_trace(&outcome.trace, width)?;
    let prove_time = started.elapsed();

    let started = Instant::now();
    verify_unified_statement(&outcome.statement, &proof, width)?;
    let verify_time = started.elapsed();

    let encoded = encode_unified_proof(&proof)?;
    let sizes = unified_proof_sizes(&proof)?;
    println!(
        "proof: {} bytes (access={}, cpu={}, shout={}, router={}, rows={}), verified in {:?}",
        encoded.len(),
        sizes.access,
        sizes.cpu,
        sizes.shout,
        sizes.router,
        sizes.rows,
        verify_time
    );
    println!("prove: {prove_time:?}");
    Ok(())
}
