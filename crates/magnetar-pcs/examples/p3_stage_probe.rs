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

use std::time::Instant;

use magnetar_constraint::F2_128;
use magnetar_pcs::{
    P3BatchPoint, P3BinaryPcs, P3MosaicPoint, P3MosaicTable,
};
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

fn report(name: &str, runs: &[(std::time::Duration, std::time::Duration)]) {
    let commit = runs.iter().map(|(commit, _)| *commit).min().unwrap();
    let open = runs.iter().map(|(_, open)| *open).min().unwrap();
    println!("{name}: commit={commit:?} open={open:?} runs={}", runs.len());
}

/// A tiny `tracing` subscriber that sums the wall time of same-named spans.
///
/// The vendored p3 crates already put `tracing` spans around their encode,
/// Merkle, fold, query and grind phases, so this needs no source change there.
/// Aggregating by name keeps the report short even when a phase runs many times
/// (one span per fold batch, per Merkle tree, ...).
static ACTIVE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u64, (&'static str, Instant)>>,
> = std::sync::OnceLock::new();
static TOTALS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<&'static str, (u64, std::time::Duration)>>,
> = std::sync::OnceLock::new();
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

struct SpanTimer;

fn active() -> &'static std::sync::Mutex<std::collections::HashMap<u64, (&'static str, Instant)>>
{
    ACTIVE.get_or_init(Default::default)
}

fn totals(
) -> &'static std::sync::Mutex<std::collections::HashMap<&'static str, (u64, std::time::Duration)>>
{
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
        active().lock().unwrap().insert(id, (name, Instant::now()));
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, span: &tracing::span::Id) {
        let id = span.into_u64();
        if let Some(slot) = active().lock().unwrap().get_mut(&id) {
            slot.1 = Instant::now();
        }
    }

    fn exit(&self, span: &tracing::span::Id) {
        let entry = active().lock().unwrap().remove(&span.into_u64());
        if let Some((name, started)) = entry {
            let elapsed = started.elapsed();
            let mut totals = totals().lock().unwrap();
            let slot = totals.entry(name).or_insert((0, std::time::Duration::ZERO));
            slot.0 += 1;
            slot.1 += elapsed;
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
        .map(|(name, (count, total))| (*name, *count, *total))
        .collect::<Vec<_>>();
    rows.sort_by_key(|(_, _, total)| std::cmp::Reverse(*total));
    for (name, count, total) in rows {
        eprintln!("span {name}: count={count} total={total:?}");
    }
}

fn selected_witness() {
    let pcs = P3BinaryPcs::with_params(100, 1, 20, 3);
    let table = values(1 << 22, 1);
    let at = point(22, 2);
    let mut runs = Vec::new();
    for _ in 0..repeat() {
        let commit_started = Instant::now();
        let commitment = pcs.commit(&table).unwrap();
        let commit = commit_started.elapsed();
        let open_started = Instant::now();
        let opening = pcs.open(&table, &at).unwrap();
        let open = open_started.elapsed();
        let value = magnetar_proof::Mle::new(table.clone())
            .unwrap()
            .eval(&at)
            .unwrap();
        assert!(pcs.verify(&commitment, &at, value, &opening).unwrap());
        runs.push((commit, open));
    }
    report("selected", &runs);
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

fn mosaic_case() {
    let pcs = P3BinaryPcs::with_params(100, 2, 21, 2);
    let tables = mosaic();
    let points = mosaic_points();
    let mut runs = Vec::new();
    for _ in 0..repeat() {
        let commit_started = Instant::now();
        let commitment = pcs.commit_mosaic(&tables).unwrap();
        let commit = commit_started.elapsed();
        let open_started = Instant::now();
        let opening = pcs.open_mosaic(&tables, &points).unwrap();
        let open = open_started.elapsed();
        assert_eq!(opening.commitment, commitment);
        runs.push((commit, open));
    }
    report("mosaic", &runs);
}

/// The local Twist PCS: 15 columns x `2^16` rows (stacked arity 20 at RV64
/// `2^16`), rate 1/8, 20 grinding bits, 8-way folding, one prepared commit and
/// one batched open (the Access register-twist path).
fn local_twist() {
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
        let commit_started = Instant::now();
        let prepared = pcs.commit_batch_prepared(&columns).unwrap();
        let commit = commit_started.elapsed();
        let open_started = Instant::now();
        let opening = pcs.open_batch_prepared(prepared, &points).unwrap();
        let open = open_started.elapsed();
        assert_eq!(opening.commitment.num_columns, 15);
        runs.push((commit, open));
    }
    report("local", &runs);
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

fn main() {
    let _watchdog = install_memory_watchdog(2.0);
    init_spans();
    let cases = std::env::var("CASES").unwrap_or_else(|_| "selected,mosaic,local".into());
    if cases.contains("selected") {
        selected_witness();
    }
    if cases.contains("mosaic") {
        mosaic_case();
    }
    if cases.contains("local") {
        local_twist();
    }
    dump_spans();
}
