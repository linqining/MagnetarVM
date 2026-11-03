//! Optional, env-gated return of freed allocator pages to the OS.
//!
//! `MAGNETAR_RELEASE_TRANSIENTS=1` asks the allocator to reclaim pages it is
//! still holding after a big transient has been dropped. It changes *when*
//! pages are returned, never any value, so proof bytes are untouched.
//!
//! The hook exists because large prover buffers are `Vec`s in the
//! hundreds-of-MiB range and libmalloc's large zone keeps their pages in
//! `resident_size` (what `ps rss` and `/usr/bin/time -l` report) after a free,
//! while the OS memory-pressure number (`phys_footprint`) already excludes
//! them. See `docs/MEMORY_PATH.md` §3.1. `MAGNETAR_PROFILE_RELEASE=1` (or the
//! existing `MAGNETAR_PROFILE_UNIFIED`/`MAGNETAR_PROFILE_SELECTED`) prints the
//! effect of every release point.

use std::sync::atomic::{AtomicU8, Ordering};

static ENABLED: AtomicU8 = AtomicU8::new(2);

/// Whether the release hook is enabled (`MAGNETAR_RELEASE_TRANSIENTS=1`).
pub fn enabled() -> bool {
    match ENABLED.load(Ordering::Relaxed) {
        2 => {
            let value = u8::from(std::env::var_os("MAGNETAR_RELEASE_TRANSIENTS").is_some());
            ENABLED.store(value, Ordering::Relaxed);
            value == 1
        }
        value => value == 1,
    }
}

fn profiling() -> bool {
    std::env::var_os("MAGNETAR_PROFILE_RELEASE").is_some()
        || std::env::var_os("MAGNETAR_PROFILE_UNIFIED").is_some()
        || std::env::var_os("MAGNETAR_PROFILE_SELECTED").is_some()
}

/// Bytes the OS currently charges to this process (macOS `phys_footprint`).
///
/// `ps` RSS and `/usr/bin/time -l` also count libmalloc's `MADV_FREE_REUSABLE`
/// pages; `phys_footprint` excludes them, so it is the number that matters for
/// memory pressure. `None` where the platform has no equivalent.
pub fn phys_footprint_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
        // SAFETY: `rusage_info_v4` is the layout libc declares for
        // RUSAGE_INFO_V4; the call fills it and signals failure with -1.
        let result = unsafe {
            libc::proc_pid_rusage(
                std::process::id() as libc::c_int,
                libc::RUSAGE_INFO_V4,
                info.as_mut_ptr().cast::<libc::rusage_info_t>(),
            )
        };
        if result == 0 {
            // SAFETY: the call succeeded and wrote the whole struct.
            Some(unsafe { info.assume_init() }.ri_phys_footprint)
        } else {
            None
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Ask the allocator to return freed pages to the OS and report the result.
///
/// Call after a big transient has been dropped and before the next allocation
/// wave; `label` only feeds the profile line. A no-op unless
/// `MAGNETAR_RELEASE_TRANSIENTS=1`.
pub fn release(label: &str) {
    if !enabled() {
        return;
    }
    let before = phys_footprint_bytes();
    let released = release_pages();
    if profiling() {
        let after = phys_footprint_bytes();
        match (before, after) {
            (Some(before), Some(after)) => eprintln!(
                "release {label}: footprint {:.2} GiB -> {:.2} GiB (allocator returned {:.1} MiB)",
                gib(before),
                gib(after),
                released as f64 / (1024.0 * 1024.0),
            ),
            _ => eprintln!(
                "release {label}: allocator returned {:.1} MiB",
                released as f64 / (1024.0 * 1024.0),
            ),
        }
    }
}

fn release_pages() -> usize {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut core::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: a null zone means "all zones" and goal 0 means "maximal
        // relief"; the call only returns already-free pages to the OS.
        unsafe { malloc_zone_pressure_relief(core::ptr::null_mut(), 0) }
    }
    // glibc only; other Linux libcs and non-Unix targets have no equivalent.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        let _ = libc::malloc_trim(0);
        0
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
    {
        0
    }
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}
