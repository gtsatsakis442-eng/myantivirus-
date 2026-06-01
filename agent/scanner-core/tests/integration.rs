//! End-to-end pipeline tests, including a guard that the *shipped* detection
//! content compiles and behaves (catches broken rules in CI).

use std::fs;
use std::path::PathBuf;

use scanner_core::{DetectionKind, Engine, HashSignatureDb, ScanSummary, Scanner, YaraEngine};

// EICAR standard anti-malware test string (harmless).
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn repo_signatures() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/agent/scanner-core
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../signatures")
}

#[test]
fn pipeline_detects_eicar_via_both_layers() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("eicar.com"), EICAR).unwrap();
    fs::write(dir.path().join("readme.txt"), b"a perfectly benign file").unwrap();

    let hashes = HashSignatureDb::from_str_db(&format!("{EICAR_SHA256}  Eicar.Test.File")).unwrap();
    let yara = YaraEngine::from_sources([(
        "eicar",
        r#"rule Eicar { strings: $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" condition: $s }"#,
    )])
    .unwrap();
    let engine = Engine::new(hashes, Some(yara));
    let scanner = Scanner::new(&engine);

    let mut summary = ScanSummary::default();
    let mut eicar_report = None;
    for report in scanner.scan_tree(dir.path()) {
        summary.record(&report);
        if report.path.ends_with("eicar.com") {
            eicar_report = Some(report);
        }
    }

    assert_eq!(summary.files_scanned, 2);
    assert_eq!(summary.malicious, 1);

    let rep = eicar_report.expect("eicar report present");
    assert!(rep.is_malicious());
    let kinds: Vec<_> = rep.detections.iter().map(|d| d.kind).collect();
    assert!(
        kinds.contains(&DetectionKind::HashSignature),
        "hash layer should fire"
    );
    assert!(
        kinds.contains(&DetectionKind::YaraRule),
        "yara layer should fire"
    );
}

#[test]
fn large_file_takes_hash_only_path() {
    use scanner_core::ScanOptions;

    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.bin");
    fs::write(&big, vec![0u8; 4096]).unwrap();

    let engine = Engine::new(HashSignatureDb::new(), None);
    // Force the hash-only path by capping content size below the file size.
    let opts = ScanOptions {
        max_content_bytes: 1024,
        ..Default::default()
    };
    let scanner = Scanner::with_options(&engine, opts);
    let rep = scanner.scan_file(&big);

    assert!(
        !rep.content_inspected,
        "file above cap must skip content inspection"
    );
    assert!(
        rep.hashes.is_some(),
        "hashes are still computed by streaming"
    );
    assert!(!rep.is_malicious());
}

#[test]
fn shipped_signature_content_compiles_and_detects() {
    let sigs = repo_signatures();
    let yara = YaraEngine::from_dir(sigs.join("yara")).expect("shipped YARA rules must compile");
    assert!(
        yara.source_files() >= 2,
        "expected at least eicar + webshells"
    );

    let hashes = HashSignatureDb::from_file(sigs.join("hashes/baseline.hashdb"))
        .expect("shipped hash db must parse");

    let engine = Engine::new(hashes, Some(yara));
    let scanner = Scanner::new(&engine);

    let dir = tempfile::tempdir().unwrap();
    let eicar = dir.path().join("eicar.com");
    fs::write(&eicar, EICAR).unwrap();
    let clean = dir.path().join("clean.txt");
    fs::write(&clean, b"nothing to see here, just a normal text file").unwrap();

    assert!(
        scanner.scan_file(&eicar).is_malicious(),
        "EICAR must be detected by shipped content"
    );
    assert!(
        !scanner.scan_file(&clean).is_malicious(),
        "benign file must not be flagged (false-positive discipline)"
    );
}
