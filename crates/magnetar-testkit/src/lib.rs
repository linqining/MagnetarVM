//! Shared programs and fixtures for integration tests.

use magnetar_spec::{Instruction, MachineConfig, Op, ProgramImage};

pub fn sample_config() -> MachineConfig {
    MachineConfig {
        entry: 0x1000,
        rom_base: 0x1000,
        ram_base: 0x1000_0000,
        ram_size: 0x1000,
        stack_top: 0x1000_1000,
        max_cycles: 100,
    }
}

/// `x3 = 5 + 7; ram[0x10000000] = x3; x5 = ram[0x10000000]; exit(0)`.
pub fn arith_memory_program() -> ProgramImage {
    ProgramImage::new(
        0x1000,
        vec![
            Instruction {
                op: Op::Addi,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 5,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Addi,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 7,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Lui,
                rd: 4,
                rs1: 0,
                rs2: 0,
                imm: 0x1000_0000,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Sd,
                rd: 0,
                rs1: 4,
                rs2: 3,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction {
                op: Op::Ld,
                rd: 5,
                rs1: 4,
                rs2: 0,
                imm: 0,
                shamt: 0,
            }
            .encode(),
            Instruction::new(Op::Ecall).encode(),
        ],
    )
}

/// Peak-RSS watchdog for benchmark examples.
///
/// The prover's peak is a sum of transients, so a single wrong constant can
/// push the host into swap and take the machine down. Every example that runs
/// a proof should install this: it aborts the process as soon as the peak RSS
/// passes `limit_gib` (taken from `MAGNETAR_MAX_RSS_GIB`, default 4.0 GiB,
/// which is above the RV64 `2^16` peak of ~2.3 GiB). Raise the variable
/// deliberately for a larger run; never run a large proof without it.
#[cfg(not(test))]
pub fn install_memory_watchdog(default_gib: f64) -> std::thread::JoinHandle<()> {
    let limit_gib = std::env::var("MAGNETAR_MAX_RSS_GIB")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default_gib);
    let limit_bytes = (limit_gib * 1024.0 * 1024.0 * 1024.0) as u64;
    eprintln!("memory watchdog: limit {limit_gib:.2} GiB");
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        record_footprint();
        if let Some(peak) = peak_rss_bytes() {
            if peak > limit_bytes {
                let footprint = peak_footprint_bytes()
                    .map(|bytes| format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)))
                    .unwrap_or_else(|| "unavailable".to_owned());
                eprintln!(
                    "memory watchdog: peak RSS {:.2} GiB (peak footprint {footprint}) exceeded the {limit_gib:.2} GiB limit; aborting",
                    peak as f64 / (1024.0 * 1024.0 * 1024.0)
                );
                std::process::abort();
            }
        }
    })
}

/// Peak resident set size of this process, in bytes.
pub fn peak_rss_bytes() -> Option<u64> {
    // `getrusage(RUSAGE_SELF).ru_maxrss` is the peak, so one check per tick is
    // enough: once it passes the limit the watchdog fires.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if status != 0 {
        return None;
    }
    let maxrss = usage.ru_maxrss as u64;
    // macOS reports bytes; Linux reports KiB.
    #[cfg(target_os = "macos")]
    {
        Some(maxrss)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(maxrss.saturating_mul(1024))
    }
}

/// Current physical footprint of this process, in bytes (macOS `phys_footprint`).
///
/// [`peak_rss_bytes`] reads `getrusage().ru_maxrss`, which counts libmalloc's
/// `MADV_FREE_REUSABLE` pages; the footprint excludes them, so it is the number
/// the OS charges against the memory-pressure limit. `None` where the platform
/// has no equivalent. See `docs/MEMORY_PATH.md` §3.1.
pub fn footprint_bytes() -> Option<u64> {
    magnetar_proof::alloc_release::phys_footprint_bytes()
}

/// Best footprint sample seen by the watchdog (or by an earlier call).
static PEAK_FOOTPRINT_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record one footprint sample in the peak tracker.
fn record_footprint() {
    if let Some(current) = footprint_bytes() {
        PEAK_FOOTPRINT_BYTES.fetch_max(current, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Peak physical footprint of this process, in bytes.
///
/// The watchdog samples it every 100 ms; `peak_footprint_bytes()` also samples
/// on every call, so read it after the prove. Pair it with [`peak_rss_bytes`]
/// when reporting a memory number: RSS counts pages the allocator has freed but
/// not returned, the footprint does not. `None` off macOS.
pub fn peak_footprint_bytes() -> Option<u64> {
    let current = footprint_bytes()?;
    let peak = PEAK_FOOTPRINT_BYTES.fetch_max(current, std::sync::atomic::Ordering::Relaxed);
    Some(peak.max(current))
}
