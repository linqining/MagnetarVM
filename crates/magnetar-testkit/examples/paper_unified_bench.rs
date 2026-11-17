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
    magnetar_testkit::peak_rss_bytes().unwrap_or(0)
}

/// Process CPU time (user + system) in seconds.
///
/// `ps` is unavailable in sandboxed runs, so use the in-process `getrusage`
/// counter the proof crate exposes; it is also the load-robust metric.
fn process_cpu_seconds() -> Option<f64> {
    Some(magnetar_proof::process_cpu_seconds())
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
    let use_trace_shout = std::env::var_os("TRACE_SHOUT").is_some();
    // M4b: paper proofs default to the committed linear Shout and bind the
    // host-derived Shout tables in the v3 statement root; the native trace path
    // keeps the legacy/native root. `MAGNETAR_CLASSIC_LOGUP=1` delegates to the
    // classic paper root, exactly like the prover.
    let trace_claim_root = if use_trace_shout {
        magnetar_runtime::claim_table::statement_claim_root(&trace)
    } else {
        magnetar_runtime::paper_statement_claim_root(&trace, width())
    };
    let statement = Statement {
        program_hash: program_hash(&program),
        rom: trace.rom.clone(),
        trace_commitment: trace_digest(&trace),
        trace_claim_root,
        access_statement_digest: magnetar_runtime::statement_access_digest(&trace),
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
        // M5 v4: the proof must keep its table-only claim encoding (the verifier
        // rejects row payloads in v4 mode); only the legacy formats get the
        // compact register-derived blob.
        let v4 = magnetar_runtime::claim_table::claims_v4_enabled();
        proof.claim_proof = if no_claim {
            None
        } else if v4 {
            proof.claim_proof
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
    // BENCH_AUDIT: binding-audit tamper matrix (docs/M4A_BINDING_AUDIT.md E1).
    // One proof, several in-memory mutations, one verify each.
    if std::env::var_os("BENCH_AUDIT").is_some() {
        let verify = |candidate: &magnetar_runtime::UnifiedTraceProof| {
            verify_native_unified(&statement, candidate, width()).map_err(|error| error.to_string())
        };
        let plus = magnetar_constraint::F2_128::from(1u64);
        let line = |label: &str, result: &Result<(), String>| match result {
            Ok(()) => println!("audit {label:<46} ACCEPTED"),
            Err(error) => println!(
                "audit {label:<46} rejected: {}",
                error.chars().take(90).collect::<String>()
            ),
        };
        if std::env::var_os("BENCH_ROOT_DEBUG").is_some() {
            println!(
                "root debug: stmt={:?} proof={:?} bits_trace={:?} bits_proof={:?}",
                statement.trace_claim_root,
                proof.trace_claim_root,
                magnetar_runtime::m4a_binding::bits_root_from_trace(&trace),
                magnetar_runtime::m4a_binding::bits_root_from_proof(&proof),
            );
        }
        line("baseline", &verify(&proof));
        if let Some(linear) = proof.access.registers.linear.as_ref() {
            let mut tampered = proof.clone();
            let value = linear.local.values[3][0];
            tampered.access.registers.linear.as_mut().unwrap().local.values[3][0] = value + plus;
            line("register linear values[3][0] (address) += 1", &verify(&tampered));

            let mut tampered = proof.clone();
            let value = linear.local.endpoints[0];
            tampered.access.registers.linear.as_mut().unwrap().local.endpoints[0] = value + plus;
            line("register linear endpoints[0] (initial) += 1", &verify(&tampered));

            let mut tampered = proof.clone();
            let value = linear.local.values[2][0];
            tampered.access.registers.linear.as_mut().unwrap().local.values[2][0] = value + plus;
            line("register linear values[2][0] (increment) += 1", &verify(&tampered));
        }
        if let Some(linear_m4a) = proof.access.registers.linear_m4a.as_ref() {
            let mut tampered = proof.clone();
            let value = linear_m4a.m4a.bits_claims[0];
            tampered.access.registers.linear_m4a.as_mut().unwrap().m4a.bits_claims[0] = value + plus;
            line("register m4a bits_claims[0] += 1", &verify(&tampered));

            let mut tampered = proof.clone();
            let value = linear_m4a.m4a.bits_opening.packed_values[0];
            tampered.access.registers.linear_m4a.as_mut().unwrap().m4a.bits_opening.packed_values[0] =
                value + plus;
            line("register m4a bits opening packed_value[0] += 1", &verify(&tampered));

            if proof.access.registers.addr_table_dropped {
                let mut tampered = proof.clone();
                tampered.access.registers.addr_table_dropped = false;
                line("register addr_table_dropped flag cleared", &verify(&tampered));
            }
        }
        if let Some(value) = proof.access.ram.boolean_evals.first().copied() {
            let mut tampered = proof.clone();
            tampered.access.ram.boolean_evals[0] = value + plus;
            line("ram boolean_evals[0] += 1", &verify(&tampered));
        }
        return;
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
    if magnetar_runtime::trace_free::trace_free_enabled() {
        eprintln!("trace-free mode: statement-only verify (no trace, no witness)");
        verify_native_unified(&statement, &proof, width()).unwrap();
    } else if no_claim {
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
    // macOS counts freed-but-reusable pages in `ps`/RSS but not in the OS
    // footprint, so peak memory is only comparable when both are quoted.
    if let Some(footprint) = magnetar_testkit::peak_footprint_bytes() {
        eprintln!("bench peak footprint={:.2} GiB", gib(footprint));
    }
    if let Some(claim) = &proof.claim_proof {
        eprintln!("claim_fields={:?}", claim.compact_field_sizes());
        eprintln!("claim_rom_probe={:?}", claim.compact_rom_probe());
    }
    println!(
        "adds={adds} rows={} proof={bytes}B varint={varint}B compressed={compressed}B access={}B logup={}B committed_shout={}B selected={}B claim={}B shape={}B prove={prove:?} verify={verify:?}",
        trace.rows.len(),
        sizes.access,
        // `logup_shout` is the classic paper wire (MAGNETAR_CLASSIC_LOGUP=1);
        // `committed_logup_shout` is the M4b default.
        sizes.logup_shout,
        sizes.committed_logup_shout,
        sizes.selected_cpu,
        sizes.claim_proof,
        sizes.shape,
    );
}
