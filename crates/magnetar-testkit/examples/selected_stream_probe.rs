//! Selected-CPU prover probe: measures the dynamic selected prover in
//! isolation (no Shout/Router/claim stages) so the staircase in
//! `docs/STREAMING_SELECTED_PROVER_HANDOFF.md` can be reproduced quickly.
//!
//! `WIDTH` (default 64) and `ADDS` (default 1023) select the RV64 width and
//! the number of `addi` instructions, as in `paper_unified_bench`.

use std::time::Instant;

use magnetar_executor::execute;
use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

fn width() -> usize {
    std::env::var("WIDTH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64)
}

fn resident_bytes() -> u64 {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .map(|kib| kib * 1024)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

fn main() {
    let adds = std::env::var("ADDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1023);
    let mut rom = Vec::new();
    for index in 0..adds {
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
    let program = ProgramImage::new(0x1000, rom);
    let config = MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x100,
        stack_top: 0x1000_0100,
        max_cycles: 10_000_000,
    };
    let trace = execute(&program, config).unwrap();
    let width = width();
    let backend = magnetar_runtime::protocol::selected_backend();

    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = {
        let peak = peak.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let rss = resident_bytes();
                peak.fetch_max(rss, std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
    };
    let started = Instant::now();
    let claims =
        magnetar_runtime::simd_dual::prove_dynamic_cpu_claims(&trace, width, &backend).unwrap();
    let prove = started.elapsed();
    let rss = peak.load(std::sync::atomic::Ordering::Relaxed);
    let proof_bytes = bincode::serialize(&claims.proof).map(|bytes| bytes.len()).unwrap_or(0);
    let segment_bytes = bincode::serialize(&claims.segments).map(|bytes| bytes.len()).unwrap_or(0);

    let public_started = Instant::now();
    magnetar_runtime::simd_dual::verify_dynamic_segments_public(&claims, &backend).unwrap();
    let public = public_started.elapsed();
    let bind_started = Instant::now();
    magnetar_runtime::simd_dual::verify_dynamic_segments_against_trace(&claims, &trace, &backend)
        .unwrap();
    let bind = bind_started.elapsed();
    let verify = public + bind;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    sampler.join().unwrap();
    println!(
        "width={width} adds={adds} cycles={} prove={prove:?} verify={verify:?} (public {public:?} + witness binding {bind:?}) peak_rss={:.2}GiB proof={proof_bytes}B segments={segment_bytes}B",
        trace.rows.len(),
        gib(rss),
    );
}
