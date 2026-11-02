use std::time::Instant;

use magnetar_executor::execute;
use magnetar_runtime::{
    access_statement::AccessStatement, program_hash, prove_unified_trace_paper, trace_digest,
    unified_proof_sizes, verify_native_unified, Statement,
};
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
    output
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
        * 1024
}

/// Process CPU time (user + system) in seconds, parsed from `ps`.
fn process_cpu_seconds() -> Option<f64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    let mut seconds = 0.0f64;
    for part in text.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(seconds)
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

fn main() {
    let _memory_watchdog = magnetar_testkit::install_memory_watchdog(4.0);
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
    let statement = Statement {
        program_hash: program_hash(&program),
        rom: trace.rom.clone(),
        trace_commitment: trace_digest(&trace),
        trace_claim_root: magnetar_runtime::claim_table::statement_claim_root(&trace),
        access_statement_digest: AccessStatement::from_trace(&trace).digest(),
        config: trace.config.clone(),
        initial_state: trace.initial_state.clone(),
        initial_ram: trace.initial_ram.clone(),
        final_state: trace.final_state.clone(),
        trace_len: trace.len() as u64,
        output: trace.io_output.clone(),
        input: trace.io_input.clone(),
        halted: trace.halted,
        exit_code: trace.exit_code,
    };
    let use_trace_shout = std::env::var_os("TRACE_SHOUT").is_some();
    let no_claim = std::env::var_os("NO_CLAIM").is_some();
    let profile = std::env::var_os("MAGNETAR_PROFILE_UNIFIED").is_some();
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampler = profile.then(|| {
        let peak = peak.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                peak.fetch_max(resident_bytes(), std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
    });
    let prove_peak = peak.clone();
    let cpu_before = process_cpu_seconds();
    let started = Instant::now();
    let proof = if use_trace_shout {
        let mut proof =
            magnetar_runtime::prove_unified_trace_dynamic_native(&trace, width()).unwrap();
        // Keep the committed claim table when swapping in the compact
        // register-derived blob; the composed trace_claim_root binds it.
        let claim_table = proof
            .claim_proof
            .as_ref()
            .and_then(|claims| claims.table.clone());
        proof.claim_proof = if no_claim {
            None
        } else {
            let mut claims = magnetar_runtime::trace_claims::ClaimProof::from_trace_reg(&trace);
            claims.table = claim_table;
            Some(claims)
        };
        if no_claim {
            // Trace-mode verification binds the legacy row root only.
            proof.trace_claim_root =
                magnetar_runtime::trace_claims::TraceClaimTree::build(&trace).root();
        }
        proof
    } else {
        prove_unified_trace_paper(&trace, width()).unwrap()
    };
    let prove = started.elapsed();
    if let (Some(before), Some(after)) = (cpu_before, process_cpu_seconds()) {
        eprintln!("prove cpu: {:.1} s", after - before);
    }
    if profile {
        eprintln!("bench prove peak rss={:.2} GiB", gib(prove_peak.swap(0, std::sync::atomic::Ordering::Relaxed)));
    }
    let sizes = unified_proof_sizes(&proof).unwrap();
    let serialized = bincode::serialize(&proof).unwrap();
    let bytes = serialized.len();
    let varint_bytes = magnetar_runtime::serialize_unified_proof(&proof).unwrap();
    let varint_decoded = magnetar_runtime::deserialize_unified_proof(&varint_bytes).unwrap();
    assert_eq!(varint_decoded.trace_commitment, proof.trace_commitment);
    let varint = varint_bytes.len();
    let compressed_bytes =
        magnetar_runtime::serialize_unified_proof_compressed(&proof).unwrap();
    let compressed = compressed_bytes.len();
    let decoded =
        magnetar_runtime::deserialize_unified_proof_compressed(&compressed_bytes).unwrap();
    assert_eq!(decoded.trace_commitment, proof.trace_commitment);
    if std::env::var_os("FAST_SELECTED").is_some() {
        if let Some(selected) = &proof.selected_cpu {
            let backend = magnetar_runtime::protocol::selected_backend();
            let selected_started = Instant::now();
            magnetar_runtime::simd_dual::verify_dynamic_segments_public(selected, &backend)
                .unwrap();
            eprintln!(
                "fast selected public verify: {:?}",
                selected_started.elapsed()
            );
        }
    }
    let started = Instant::now();
    if no_claim {
        magnetar_runtime::verify_unified_trace(&trace, &proof, width()).unwrap();
    } else {
        verify_native_unified(&statement, &proof, width()).unwrap();
    }
    let verify = started.elapsed();
    // Load-independent CPU cost: repeat the verification and diff the
    // process CPU time reported by `ps`.
    if let Ok(repeat) = std::env::var("MAGNETAR_VERIFY_CPU") {
        let repeat = repeat.parse::<usize>().unwrap_or(25).max(1);
        let cpu = process_cpu_seconds();
        let wall = Instant::now();
        for _ in 0..repeat {
            let _ = verify_native_unified(&statement, &proof, width());
        }
        let wall = wall.elapsed();
        let cpu_ms = match (cpu, process_cpu_seconds()) {
            (Some(before), Some(after)) => {
                Some((after - before) * 1000.0 / repeat as f64)
            }
            _ => None,
        };
        // `ps` may be unavailable in sandboxed runs, so the wall figure is
        // always printed; CPU is printed when the process CPU counter works.
        match cpu_ms {
            Some(cpu_ms) => eprintln!(
                "verify cpu: {cpu_ms:.1} ms/iter over {repeat} runs (wall {:.1} ms/iter)",
                wall.as_secs_f64() * 1000.0 / repeat as f64
            ),
            None => eprintln!(
                "verify wall: {:.1} ms/iter over {repeat} runs (ps unavailable)",
                wall.as_secs_f64() * 1000.0 / repeat as f64
            ),
        }
    }
    if profile {
        eprintln!("bench verify peak rss={:.2} GiB", gib(peak.load(std::sync::atomic::Ordering::Relaxed)));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(sampler) = sampler {
            sampler.join().unwrap();
        }
    }
    eprintln!("{sizes:?}");
    if let Some(claim) = &proof.claim_proof {
        eprintln!("claim_fields={:?}", claim.compact_field_sizes());
        eprintln!("claim_rom_probe={:?}", claim.compact_rom_probe());
    }
    println!(
        "adds={adds} rows={} proof={bytes}B varint={varint}B compressed={compressed}B access={}B logup={}B selected={}B claim={}B shape={}B prove={prove:?} verify={verify:?}",
        trace.rows.len(),
        sizes.access,
        // compressed,
        sizes.logup_shout,
        sizes.selected_cpu,
        sizes.claim_proof,
        sizes.shape,
    );
}
