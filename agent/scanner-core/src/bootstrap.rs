//! Engine bootstrap: build the detection engine from the **embedded baseline**
//! merged with the **updatable on-disk store** (where feed updates land) plus
//! optional explicit overrides. Shared by the CLI and the GUI so both load
//! signatures identically.

use std::path::Path;

use walkdir::WalkDir;

use crate::error::Result;
use crate::{Engine, HashSignatureDb, YaraEngine};

fn is_yara(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
        .unwrap_or(false)
}

fn collect_yara_dir(dir: &Path, out: &mut Vec<(String, String)>) {
    if !dir.is_dir() {
        return;
    }
    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && is_yara(entry.path()) {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                out.push((entry.path().display().to_string(), text));
            }
        }
    }
}

fn count_yara_dir(dir: &Path) -> usize {
    if !dir.is_dir() {
        return 0;
    }
    WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_yara(e.path()))
        .count()
}

/// Build the engine: embedded baseline + the on-disk `store` (a `hashes/` dir of
/// `*.hashdb` and a `yara/` dir of `*.yar`) + optional explicit overrides.
///
/// Returns `(engine, hash_count, yara_file_count, skipped_yara_sources)`.
/// External YARA that our engine can't compile is skipped, not fatal.
pub fn load_engine(
    embedded_hashdb: &str,
    embedded_yara: &[(&str, &str)],
    store: &Path,
    extra_hash_file: Option<&Path>,
    extra_yara_dir: Option<&Path>,
    no_yara: bool,
) -> Result<(Engine, usize, usize, Vec<String>)> {
    let mut hashes = HashSignatureDb::from_str_db(embedded_hashdb)?;
    hashes.merge(HashSignatureDb::from_dir(store.join("hashes"))?);
    if let Some(f) = extra_hash_file {
        if f.is_file() {
            hashes.merge(HashSignatureDb::from_file(f)?);
        }
    }
    let hash_count = hashes.len();

    if no_yara {
        return Ok((Engine::new(hashes, None), hash_count, 0, Vec::new()));
    }

    let mut sources: Vec<(String, String)> = embedded_yara
        .iter()
        .map(|(n, s)| (n.to_string(), s.to_string()))
        .collect();
    collect_yara_dir(&store.join("yara"), &mut sources);
    if let Some(d) = extra_yara_dir {
        collect_yara_dir(d, &mut sources);
    }
    let (engine, skipped) = YaraEngine::from_sources_lenient(sources);
    let yara_files = engine.source_files();
    Ok((
        Engine::new(hashes, Some(engine)),
        hash_count,
        yara_files,
        skipped,
    ))
}

/// Cheap dashboard counts: `(hash_signatures, yara_files)` from embedded + store.
pub fn inventory(
    embedded_hashdb: &str,
    embedded_yara_count: usize,
    store: &Path,
) -> (usize, usize) {
    let mut db = HashSignatureDb::from_str_db(embedded_hashdb).unwrap_or_default();
    if let Ok(s) = HashSignatureDb::from_dir(store.join("hashes")) {
        db.merge(s);
    }
    let yara_files = embedded_yara_count + count_yara_dir(&store.join("yara"));
    (db.len(), yara_files)
}
