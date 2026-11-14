//! Isolated timing probe for the P3 binary PCS at the three profiles the RV64
//! `2^16` prover actually uses.
//!
//! The full benchmark runs the mosaic / selected / local PCS inside a
//! concurrent prover, which makes their stage times depend on the host load and
//! on whatever else is running. This probe calls the same entry points on
//! synthetic data of the same shape, so a vendor or wrapper change can be A/B
//! measured in seconds instead of minutes.
//!
//! Set `MAGNETAR_TRACE_SPANS=1` to print one line per internal `tracing` span
//! (`close span=... time.busy=... time.idle=...`). The vendored p3 crates
//! already instrument their encode / Merkle / fold / query / grind phases, so
//! this needs no source changes there.
//!
//! Run:
//! ```sh
//! cargo build --release -p magnetar-pcs --example p3_stage_probe
//! REPEAT=3 MAGNETAR_TRACE_SPANS=1 target/release/examples/p3_stage_probe
//! ```
//!
//! Each case line reports the commit-phase high-water RSS (`getrusage`
//! `ru_maxrss`), the post-commit live RSS (`proc_pidinfo`) and the process
//! peak. Set `COMMIT_ONLY=1` to skip the opening phase, so the process peak is
//! the commit peak; per-case overrides are `CASES=selected:commit,mosaic:full`.

use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::{P3BatchPoint, P3BinaryPcs, P3MosaicPoint, P3MosaicTable};
use magnetar_proof::Pcs;

fn values(count: usize, seed: u64) -> Vec<F2_128> {
    (0..count)
        .map(|index| {
            F2_128::from(
                (index as u128)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(seed as u128),
            )
        })
        .collect()
}

fn point(len: usize, seed: u64) -> Vec<F2_128> {
    (0..len)
        .map(|bit| F2_128::from(((seed >> bit) & 1) as u64))
        .collect()
}

fn repeat() -> usize {
    std::env::var("REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
}

fn truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// One measured run of a case.
///
/// `ru_maxrss` is a monotonic high-water mark, so `peak_after_commit` is the
/// commit-phase peak as long as this is the only run in the process (or the
/// first one); the live readings bracket what the phase actually holds.
struct CaseRun {
    commit: std::time::Duration,
    open: Option<std::time::Duration>,
    live_before: u64,
    peak_after_commit: u64,
    live_after_commit: u64,
    peak_at_end: u64,
    live_at_end: u64,
}

/// Peak RSS of this process in bytes. `ru_maxrss` is bytes on macOS and KiB on
/// Linux, matching the watchdog below.
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let peak = usage.ru_maxrss as u64;
    #[cfg(not(target_os = "macos"))]
    let peak = peak.saturating_mul(1024);
    peak
}

/// Current resident set size in bytes (macOS `proc_pidinfo`; 0 elsewhere).
fn live_rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut libc::proc_taskinfo as *mut libc::c_void,
                size,
            )
        };
        if written == size {
            info.pti_resident_size
        } else {
            0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn report(name: &str, runs: &[CaseRun], commit_only: bool) {
    let commit = runs.iter().map(|run| run.commit).min().unwrap();
    let open = runs
        .iter()
        .filter_map(|run| run.open)
        .min()
        .map(|open| format!("{open:?}"))
        .unwrap_or_else(|| "n/a".to_string());
    // Peaks are high-water marks, so report the last (largest) one; live
    // readings are the last run's.
    let last = runs.last().unwrap();
    println!(
        "{name}:{mode} commit={commit:?} open={open} runs={runs} \
         commit_peak_rss={commit_peak}B({commit_peak_mib:.1}MiB) \
         post_commit_live_rss={post_commit_live}B({post_commit_mib:.1}MiB) \
         process_peak_rss={process_peak}B({process_peak_mib:.1}MiB) \
         final_live_rss={final_live}B({final_mib:.1}MiB) \
         rss_before_commit={rss_before}B({rss_before_mib:.1}MiB)",
        mode = if commit_only { " commit-only" } else { "" },
        runs = runs.len(),
        commit_peak = last.peak_after_commit,
        commit_peak_mib = mib(last.peak_after_commit),
        post_commit_live = last.live_after_commit,
        post_commit_mib = mib(last.live_after_commit),
        process_peak = last.peak_at_end,
        process_peak_mib = mib(last.peak_at_end),
        final_live = last.live_at_end,
        final_mib = mib(last.live_at_end),
        rss_before = last.live_before,
        rss_before_mib = mib(last.live_before),
    );
}

/// A tiny `tracing` subscriber that sums the wall time of same-named spans.
///
/// The vendored p3 crates already put `tracing` spans around their encode,
/// Merkle, fold, query and grind phases, so this needs no source change there.
/// Aggregating by name keeps the report short even when a phase runs many times
/// (one span per fold batch, per Merkle tree, ...).
static ACTIVE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u64, (&'static str, Instant, f64)>>,
> = std::sync::OnceLock::new();
static TOTALS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<&'static str, (u64, std::time::Duration, f64)>>,
> = std::sync::OnceLock::new();
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

struct SpanTimer;

fn active(
) -> &'static std::sync::Mutex<std::collections::HashMap<u64, (&'static str, Instant, f64)>> {
    ACTIVE.get_or_init(Default::default)
}

/// Process CPU seconds, for the load-independent half of each span's cost.
fn process_cpu_seconds() -> f64 {
    magnetar_proof::process_cpu_seconds()
}

fn totals() -> &'static std::sync::Mutex<
    std::collections::HashMap<&'static str, (u64, std::time::Duration, f64)>,
> {
    TOTALS.get_or_init(Default::default)
}

impl tracing::Subscriber for SpanTimer {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::INFO)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name: &'static str = Box::leak(span.metadata().name().to_string().into_boxed_str());
        active()
            .lock()
            .unwrap()
            .insert(id, (name, Instant::now(), process_cpu_seconds()));
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, span: &tracing::span::Id) {
        let id = span.into_u64();
        if let Some(slot) = active().lock().unwrap().get_mut(&id) {
            slot.1 = Instant::now();
            slot.2 = process_cpu_seconds();
        }
    }

    fn exit(&self, span: &tracing::span::Id) {
        let entry = active().lock().unwrap().remove(&span.into_u64());
        if let Some((name, started, cpu_started)) = entry {
            let elapsed = started.elapsed();
            let cpu = process_cpu_seconds() - cpu_started;
            let mut totals = totals().lock().unwrap();
            let slot = totals
                .entry(name)
                .or_insert((0, std::time::Duration::ZERO, 0.0));
            slot.0 += 1;
            slot.1 += elapsed;
            slot.2 += cpu;
        }
    }

    fn try_close(&self, span: tracing::span::Id) -> bool {
        // A span that was never entered (or was entered and has exited) is done.
        let _ = active().lock().unwrap().remove(&span.into_u64());
        true
    }
}

fn init_spans() {
    if std::env::var_os("MAGNETAR_TRACE_SPANS").is_none() {
        return;
    }
    tracing::subscriber::set_global_default(SpanTimer).expect("install span timer");
}

fn dump_spans() {
    if std::env::var_os("MAGNETAR_TRACE_SPANS").is_none() {
        return;
    }
    let totals = totals().lock().unwrap();
    let mut rows = totals
        .iter()
        .map(|(name, (count, wall, cpu))| (*name, *count, *wall, *cpu))
        .collect::<Vec<_>>();
    rows.sort_by_key(|(_, _, wall, _)| std::cmp::Reverse(*wall));
    for (name, count, wall, cpu) in rows {
        eprintln!("span {name}: count={count} wall={wall:?} cpu={cpu:.3}s");
    }
}

fn selected_witness(commit_only: bool) {
    let pcs = P3BinaryPcs::with_params(100, 1, 20, 3);
    let table = values(1 << 22, 1);
    let at = point(22, 2);
    let mut runs = Vec::new();
    for _ in 0..repeat() {
        let live_before = live_rss_bytes();
        let commit_started = Instant::now();
        let commitment = pcs.commit(&table).unwrap();
        let commit = commit_started.elapsed();
        let peak_after_commit = peak_rss_bytes();
        let live_after_commit = live_rss_bytes();
        let mut open = None;
        if !commit_only {
            let open_started = Instant::now();
            let opening = pcs.open(&table, &at).unwrap();
            open = Some(open_started.elapsed());
            let value = magnetar_proof::Mle::new(table.clone())
                .unwrap()
                .eval(&at)
                .unwrap();
            assert!(pcs.verify(&commitment, &at, value, &opening).unwrap());
        }
        std::hint::black_box(&commitment);
        runs.push(CaseRun {
            commit,
            open,
            live_before,
            peak_after_commit,
            live_after_commit,
            peak_at_end: peak_rss_bytes(),
            live_at_end: live_rss_bytes(),
        });
    }
    report("selected", &runs, commit_only);
}

/// The mosaic commitment: the RV64 `2^16` table shapes, rate 1/4, 21 grinding
/// bits, 4-way folding. `commit_mosaic` is the Commit stage; `open_mosaic`
/// re-encodes the same tables in the Opening stage.
fn mosaic() -> Vec<P3MosaicTable> {
    let shapes = [
        (1usize, 12usize),
        (1, 1),
        (5, 2),
        (1, 1),
        (1, 1),
        (16, 12),
        (16, 12),
        (16, 1),
        (5, 2),
        (16, 1),
        (16, 1),
        (19, 1),
    ];
    let mut tables = Vec::new();
    for (index, (bits, columns)) in shapes.into_iter().enumerate() {
        let rows = 1usize << bits;
        tables.push(P3MosaicTable {
            columns: (0..columns)
                .map(|column| values(rows, (index * 31 + column) as u64))
                .collect(),
        });
    }
    tables
}

fn mosaic_points() -> Vec<P3MosaicPoint> {
    let mut points = Vec::new();
    // Grouped by table index, as the real claim schedule is.
    for table in [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        let bits = match table {
            5 | 6 | 7 | 9 | 10 => 16,
            2 | 8 => 5,
            11 => 19,
            _ => 1,
        };
        let columns = match table {
            5 | 6 => vec![0, 3],
            0 => vec![0, 1],
            2 | 8 => vec![0, 1],
            _ => vec![0],
        };
        points.push(P3MosaicPoint {
            table,
            point: point(bits, table as u64 + 3),
            columns,
            next_columns: Vec::new(),
        });
    }
    points
}

fn mosaic_case(commit_only: bool) {
    let pcs = P3BinaryPcs::with_params(100, 2, 21, 2);
    let tables = mosaic();
    let points = mosaic_points();
    let mut runs = Vec::new();
    for _ in 0..repeat() {
        let live_before = live_rss_bytes();
        let commit_started = Instant::now();
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        let commit = commit_started.elapsed();
        let peak_after_commit = peak_rss_bytes();
        let live_after_commit = live_rss_bytes();
        let mut open = None;
        if !commit_only {
            let open_started = Instant::now();
            let opening = pcs.open_mosaic(&tables, &points).unwrap();
            open = Some(open_started.elapsed());
            assert_eq!(opening.commitment, commitment);
        }
        std::hint::black_box(&commitment);
        runs.push(CaseRun {
            commit,
            open,
            live_before,
            peak_after_commit,
            live_after_commit,
            peak_at_end: peak_rss_bytes(),
            live_at_end: live_rss_bytes(),
        });
    }
    report("mosaic", &runs, commit_only);
}

/// The local Twist PCS: 15 columns x `2^16` rows (stacked arity 20 at RV64
/// `2^16`), rate 1/8, 20 grinding bits, 8-way folding, one prepared commit and
/// one batched open (the Access register-twist path).
fn local_twist(commit_only: bool) {
    let pcs = P3BinaryPcs::with_params(100, 3, 20, 3);
    let columns = (0..15usize)
        .map(|column| values(1 << 16, column as u64 + 7))
        .collect::<Vec<_>>();
    let points = vec![
        P3BatchPoint {
            point: point(16, 11),
            columns: vec![1, 2],
        },
        P3BatchPoint {
            point: point(16, 12),
            columns: vec![0],
        },
        P3BatchPoint {
            point: point(16, 13),
            columns: vec![0],
        },
        P3BatchPoint {
            point: point(16, 14),
            columns: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        },
    ];
    let mut runs = Vec::new();
    for _ in 0..repeat() {
        let live_before = live_rss_bytes();
        let commit_started = Instant::now();
        let prepared = pcs.commit_batch_prepared(&columns).unwrap();
        let commit = commit_started.elapsed();
        let peak_after_commit = peak_rss_bytes();
        let live_after_commit = live_rss_bytes();
        let mut open = None;
        if !commit_only {
            let open_started = Instant::now();
            let opening = pcs.open_batch_prepared(prepared, &points).unwrap();
            open = Some(open_started.elapsed());
            assert_eq!(opening.commitment.num_columns, 15);
        } else {
            std::hint::black_box(&prepared);
        }
        runs.push(CaseRun {
            commit,
            open,
            live_before,
            peak_after_commit,
            live_after_commit,
            peak_at_end: peak_rss_bytes(),
            live_at_end: live_rss_bytes(),
        });
    }
    report("local", &runs, commit_only);
}

/// Abort if the process peak RSS passes a limit (default 2 GiB, override with
/// `MAGNETAR_MAX_RSS_GIB`). The probe's shapes are bounded, but the harness
/// convention on this host is a watchdog rather than a human watching `top`.
fn install_memory_watchdog(default_gib: f64) -> std::thread::JoinHandle<()> {
    let limit_gib = std::env::var("MAGNETAR_MAX_RSS_GIB")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default_gib);
    let limit_bytes = (limit_gib * 1024.0 * 1024.0 * 1024.0) as u64;
    eprintln!("memory watchdog: limit {limit_gib:.2} GiB");
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if status != 0 {
            continue;
        }
        let peak = usage.ru_maxrss as u64;
        #[cfg(not(target_os = "macos"))]
        let peak = peak.saturating_mul(1024);
        if peak > limit_bytes {
            eprintln!(
                "memory watchdog: peak RSS {:.2} GiB exceeded the {limit_gib:.2} GiB limit; aborting",
                peak as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            std::process::abort();
        }
    })
}

/// Direct measurement of the PoW grind: how many CPU seconds one `grind(bits)`
/// costs on a challenger with a fixed prefix. This is the phase the AVX/NEON
/// batched Keccak path cannot serve, so it is measured on its own.
fn grind_case() {
    use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
    use p3_challenger::{CanObserve, GrindingChallenger, HashChallenger};
    use p3_keccak::Keccak256Hash;
    type Ch = BinaryChallenger<BinaryField128, HashChallenger<u8, Keccak256Hash, 32>>;
    for (bits, prefix_values) in [(20usize, 4usize), (21, 4), (21, 32), (21, 0)] {
        let mut challenger = Ch::from_hasher(Vec::new(), Keccak256Hash);
        for index in 0..prefix_values {
            challenger.observe(BinaryField128::from_repr((index as u128) * 7 + 1));
        }
        let cpu_started = process_cpu_seconds();
        let started = Instant::now();
        let witness = challenger.grind(bits);
        let cpu = process_cpu_seconds() - cpu_started;
        let wall = started.elapsed();
        println!("grind bits={bits} prefix={prefix_values} values: wall={wall:?} cpu={cpu:.3}s");
    }
}

/// The `(case, commit_only)` pairs to run.
///
/// `COMMIT_ONLY=1` makes every case commit-only, so the process peak measured
/// by `/usr/bin/time -l` is the commit peak. A `CASES` token can override the
/// mode per case: `selected:commit`, `mosaic:full`.
fn selected_cases() -> Vec<(&'static str, bool)> {
    let raw = std::env::var("CASES").unwrap_or_else(|_| "selected,mosaic,local".into());
    let default_commit_only = truthy("COMMIT_ONLY");
    let mut cases: Vec<(&'static str, bool)> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (name, mode) = match token.split_once(':') {
            Some((name, mode)) => (name.trim(), Some(mode.trim().to_ascii_lowercase())),
            None => (token, None),
        };
        let commit_only = match mode.as_deref() {
            Some("commit" | "commit-only" | "commit_only") => true,
            Some("full" | "open") => false,
            _ => default_commit_only,
        };
        let name = match name {
            "selected" => "selected",
            "mosaic" => "mosaic",
            "local" => "local",
            "grind" => "grind",
            other => {
                eprintln!("unknown case {other:?}; expected selected, mosaic, local or grind");
                continue;
            }
        };
        cases.push((name, commit_only));
    }
    cases
}

fn main() {
    let _watchdog = install_memory_watchdog(2.0);
    init_spans();
    for (name, commit_only) in selected_cases() {
        match name {
            "selected" => selected_witness(commit_only),
            "mosaic" => mosaic_case(commit_only),
            "local" => local_twist(commit_only),
            "grind" => grind_case(),
            _ => {}
        }
    }
    dump_spans();
}
