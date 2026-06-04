//! Static heuristic analysis layer (L2): lightweight PE structural checks.
//!
//! Heuristics produce *suspicion* signals — never a definitive malicious
//! verdict on their own (see [`crate::verdict::Disposition::Suspicious`]). They
//! only run on PE files; any other input yields no findings, so ordinary
//! documents and scripts are never flagged by this layer.
//!
//! **False-positive discipline.** Benign software — especially signed Microsoft
//! DLLs — routinely has high-entropy *resource* sections (compressed assets,
//! icons, the embedded Authenticode blob) and imports powerful APIs for
//! legitimate reasons. To avoid flagging them, this layer:
//!   1. **trusts Authenticode-signed binaries** (emits nothing for them);
//!   2. only treats high entropy in **executable code** sections as a packing
//!      signal — resource/data-section entropy is ignored; and
//!   3. requires **at least two independent signals** before reporting, so a
//!      lone quirk never produces a "suspicious" verdict.
//!
//! Known-bad files (even signed ones) are still caught by the hash/YARA layers.

use goblin::pe::PE;

use crate::verdict::{Detection, DetectionKind, Severity};

/// Entropy (bits/byte) above which an **executable** section looks
/// packed/encrypted. Normal x86 code sits around 6.0–6.5 bits/byte.
const PACKED_ENTROPY: f64 = 7.2;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// The independent structural signals we derive from a PE. Kept separate from
/// the reporting decision so the (FP-sensitive) policy is unit-testable without
/// constructing real PE files.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Signals {
    /// An executable/code section has packed-or-encrypted-level entropy.
    packed_code: bool,
    /// A section is simultaneously writable and executable (W^X violation).
    writable_executable: bool,
    /// The classic process-injection import trio is present.
    injection_imports: bool,
    /// The file carries an embedded Authenticode signature (benign hint).
    signed: bool,
}

/// Analyze a buffer, returning heuristic findings (empty for non-PE input).
pub fn analyze(data: &[u8]) -> Vec<Detection> {
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };
    findings_for(&signals(&pe, data))
}

/// Derive the structural [`Signals`] from a parsed PE.
fn signals(pe: &PE, data: &[u8]) -> Signals {
    let mut sig = Signals {
        signed: is_authenticode_signed(pe),
        ..Signals::default()
    };

    for section in &pe.sections {
        let executable =
            section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
        if executable {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let end = start.saturating_add(size);
            if size != 0
                && start < data.len()
                && end <= data.len()
                && shannon_entropy(&data[start..end]) > PACKED_ENTROPY
            {
                sig.packed_code = true;
            }
        }
        if is_writable_executable(section.characteristics) {
            sig.writable_executable = true;
        }
    }

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    sig.injection_imports = has_injection_combo(&imports);

    sig
}

/// Map structural signals to reported detections, applying FP discipline.
fn findings_for(sig: &Signals) -> Vec<Detection> {
    // Trust Authenticode-signed binaries at this layer: their structural quirks
    // (compressed resources, mixed sections) are normal for shipping software,
    // and they are the dominant source of false positives. This is a benign
    // *hint*, not cryptographic verification — known-bad signed files are still
    // caught by the hash and YARA layers.
    if sig.signed {
        return Vec::new();
    }

    let mut findings = Vec::new();
    if sig.packed_code {
        findings.push(detection("Heuristic.PackedCodeSection", Severity::Medium));
    }
    if sig.writable_executable {
        findings.push(detection(
            "Heuristic.WritableExecutableSection",
            Severity::Medium,
        ));
    }
    if sig.injection_imports {
        findings.push(detection(
            "Heuristic.ProcessInjectionImports",
            Severity::Medium,
        ));
    }

    // Corroboration gate: any one of these signals occurs in plenty of benign
    // executables (legit packers/installers, JIT stubs, debuggers, profilers).
    // Only surface suspicion when at least two independent signals agree.
    if findings.len() >= 2 {
        findings
    } else {
        Vec::new()
    }
}

/// True if the PE has an embedded Authenticode certificate. We check both the
/// parsed certificate table and the raw certificate **data directory** size, so
/// a present-but-truncated signature blob still counts as "signed".
pub(crate) fn is_authenticode_signed(pe: &PE) -> bool {
    if !pe.certificates.is_empty() {
        return true;
    }
    pe.header
        .optional_header
        .as_ref()
        .and_then(|oh| oh.data_directories.get_certificate_table())
        .is_some_and(|dd| dd.size > 0)
}

fn detection(name: &str, severity: Severity) -> Detection {
    Detection {
        name: name.to_string(),
        kind: DetectionKind::Heuristic,
        severity,
    }
}

/// Shannon entropy (bits per byte) of a buffer, in the range `[0.0, 8.0]`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn is_writable_executable(characteristics: u32) -> bool {
    characteristics & IMAGE_SCN_MEM_WRITE != 0 && characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

/// True if the imports contain a classic process-injection trio:
/// memory allocation + remote write + remote thread creation.
fn has_injection_combo(imports: &[String]) -> bool {
    let has = |name: &str| imports.iter().any(|i| i == name);
    let alloc = has("virtualallocex") || has("virtualalloc") || has("ntallocatevirtualmemory");
    let write = has("writeprocessmemory") || has("ntwritevirtualmemory");
    let thread = has("createremotethread")
        || has("createremotethreadex")
        || has("ntcreatethreadex")
        || has("rtlcreateuserthread");
    alloc && write && thread
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        // All identical bytes -> 0 entropy.
        assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
        // Every byte value equally likely -> 8 bits/byte.
        let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 8).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn injection_combo_detected() {
        let imports = vec![
            "virtualallocex".to_string(),
            "writeprocessmemory".to_string(),
            "createremotethread".to_string(),
        ];
        assert!(has_injection_combo(&imports));
        // Missing the thread-creation leg -> not flagged.
        assert!(!has_injection_combo(&imports[..2]));
    }

    #[test]
    fn wx_section_flag() {
        assert!(is_writable_executable(
            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        ));
        assert!(!is_writable_executable(IMAGE_SCN_MEM_EXECUTE));
        assert!(!is_writable_executable(IMAGE_SCN_MEM_WRITE));
    }

    #[test]
    fn non_pe_yields_nothing() {
        assert!(analyze(b"this is just text, not a PE").is_empty());
        assert!(analyze(&[0u8; 64]).is_empty());
    }

    // --- False-positive discipline (the reporting policy) ---

    #[test]
    fn single_signal_is_not_reported() {
        // A lone quirk is far too common in benign software to flag.
        for sig in [
            Signals {
                packed_code: true,
                ..Default::default()
            },
            Signals {
                writable_executable: true,
                ..Default::default()
            },
            Signals {
                injection_imports: true,
                ..Default::default()
            },
        ] {
            assert!(
                findings_for(&sig).is_empty(),
                "one signal must not be suspicious: {sig:?}"
            );
        }
    }

    #[test]
    fn two_signals_are_reported() {
        let sig = Signals {
            packed_code: true,
            injection_imports: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|d| d.kind == DetectionKind::Heuristic));
    }

    #[test]
    fn signed_binaries_are_trusted_even_with_signals() {
        // Even with every signal set, a signed binary emits nothing here.
        let sig = Signals {
            packed_code: true,
            writable_executable: true,
            injection_imports: true,
            signed: true,
        };
        assert!(
            findings_for(&sig).is_empty(),
            "Authenticode-signed files are trusted at the heuristic layer"
        );
    }
}
