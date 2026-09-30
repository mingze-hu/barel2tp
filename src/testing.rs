//! Small helpers shared by unit tests. They live in the crate so each module does not need its own
//! temporary-path generator.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

/// Tests run in parallel and timestamp resolution cannot guarantee uniqueness, so a counter backs
/// it up.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Builds a temporary file path under `target` that is unique to this run.
pub(crate) fn temp_path(suffix: &str) -> PathBuf {
    let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "barel2tp-test-{}-{nonce}.{suffix}",
            std::process::id()
        ))
}
