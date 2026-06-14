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
//!      signal — resource/data-section entropy is ignored;
//!   3. uses a **weighted score** rather than a raw count — each signal
//!      carries a weight reflecting how often it appears in benign software;
//!      only combinations that reach the threshold (`≥ 3`) are reported.
//!
//! Known-bad files (even signed ones) are still caught by the hash/YARA layers.

use goblin::pe::PE;

use crate::verdict::{Detection, DetectionKind, Severity};

/// Entropy (bits/byte) above which an **executable** section looks
/// packed/encrypted. Normal x86 code sits around 6.0–6.5 bits/byte.
const PACKED_ENTROPY: f64 = 7.2;

/// Minimum aggregate signal weight before any heuristic finding is reported.
const HEURISTIC_THRESHOLD: u32 = 3;

/// Year-2038 boundary as a Unix timestamp. A PE compile timestamp beyond this
/// is implausible for legitimately compiled software on today's toolchains and
/// is a common sign of timestamp spoofing or packer artefacts.
const FUTURE_TIMESTAMP_CUTOFF: u32 = 0x8000_0000; // ~2038-01-19

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_FILE_DLL: u16 = 0x2000;

/// All structural signals derived from a single PE file, each with its weight.
/// Kept separate from the reporting decision so the (FP-sensitive) policy is
/// unit-testable without constructing real PE files.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Signals {
    // weight 1 — relatively common in benign software
    /// An executable section has packed-or-encrypted-level entropy.
    packed_code: bool,
    /// Significant data exists beyond the last PE section (overlay). Common in
    /// packers and self-extracting archives, but also in some benign installers.
    anomalous_overlay: bool,
    /// Compile timestamp is zero (stripped) or past the year-2038 boundary —
    /// both are implausible for legitimately compiled software today.
    timestamp_anomaly: bool,

    // weight 2 — rare in benign, strong packer/injection indicator
    /// A section is simultaneously writable and executable (W^X violation).
    writable_executable: bool,
    /// The classic process-injection import trio is present.
    injection_imports: bool,
    /// The section table contains a known packer/protector section name.
    suspicious_section_name: bool,
    /// Import table is entirely absent — almost always a packed or shellcode
    /// payload (legitimate EXEs/DLLs have at least a handful of imports).
    zero_imports: bool,
    /// The DLL has exports but every one is ordinal-only (no symbol names).
    /// In-memory-only shellcode DLLs commonly use ordinal-only exports to
    /// make the IAT less obvious to static analysis.
    dll_ordinal_only_exports: bool,
    /// The DLL imports functions but none come from kernel32/ntdll/kernelbase
    /// or common runtime libraries (.NET, COM, UCRT, Winsock). Absence usually
    /// means the payload resolves Win32 API via direct syscalls to evade hooks.
    missing_base_imports: bool,

    // weight 1 — combined with other signals reaches threshold
    /// The PE is a DLL (IMAGE_FILE_DLL) but exports nothing.
    /// Weight 1 (not 2): resource-only DLLs, stub DLLs, and many plugin/COM
    /// DLLs legitimately have no exports, so this alone is not a strong signal.
    dll_no_exports: bool,

    // weight 4 — standalone verdict
    /// An export is named "ReflectiveLoader" or "ReflectiveDllInjection".
    /// This is the canonical reflective DLL injection bootstrap export —
    /// present in legitimate offensive-security tools but never in vendor DLLs.
    reflective_loader_export: bool,

    /// The file carries an embedded Authenticode signature (benign fast-path).
    signed: bool,
}

/// Analyse a buffer, returning heuristic findings (empty for non-PE input).
pub fn analyze(data: &[u8]) -> Vec<Detection> {
    match PE::parse(data) {
        Ok(pe) => analyze_pe(&pe, data),
        Err(_) => Vec::new(),
    }
}

/// Like [`analyze`] but reuses an already-parsed PE. The engine parses a
/// file's PE structure once and shares it across the heuristic and behavioral
/// layers, avoiding a redundant `goblin` parse of the same bytes on every scan.
pub(crate) fn analyze_pe(pe: &PE, data: &[u8]) -> Vec<Detection> {
    findings_for(&signals(pe, data))
}

/// Derive the structural [`Signals`] from a parsed PE.
fn signals(pe: &PE, data: &[u8]) -> Signals {
    let mut sig = Signals {
        signed: is_authenticode_signed(pe),
        ..Signals::default()
    };

    let is_dll = pe.header.coff_header.characteristics & IMAGE_FILE_DLL != 0;

    // --- Section analysis ---
    let mut last_section_end: usize = 0;
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

        // Known packer / protector section names. The raw name is 8 bytes
        // zero-padded; we convert to lowercase for comparison.
        let raw_name = std::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_ascii_lowercase();
        if is_packer_section(&raw_name) {
            sig.suspicious_section_name = true;
        }

        let section_end = (section.pointer_to_raw_data as usize)
            .saturating_add(section.size_of_raw_data as usize);
        if section_end > last_section_end {
            last_section_end = section_end;
        }
    }

    // Overlay: data beyond the last section. Signed files are already trusted;
    // for unsigned PEs, a large overlay (> 512 bytes) is suspicious.
    if !sig.signed && last_section_end > 0 && data.len() > last_section_end + 512 {
        sig.anomalous_overlay = true;
    }

    // --- Import table ---
    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    sig.injection_imports = has_injection_combo(&imports);
    sig.zero_imports = imports.is_empty();

    // --- Export table ---
    // ReflectiveLoader check applies to any PE (EXE or DLL): some offensive
    // loaders compile as EXE but still export the bootstrap symbol.
    sig.reflective_loader_export = pe.exports.iter().any(|e| {
        e.name
            .map(|n| {
                let n = n.to_ascii_lowercase();
                n.contains("reflectiveloader") || n.contains("reflectivedllinjection")
            })
            .unwrap_or(false)
    });

    // DLL-specific export checks.
    if is_dll {
        sig.dll_no_exports = pe.exports.is_empty();
        // Ordinal-only exports (has entries but none have symbol names) are
        // common in in-memory shellcode DLLs that want to hide their API surface.
        if !pe.exports.is_empty() {
            sig.dll_ordinal_only_exports = pe.exports.iter().all(|e| e.name.is_none());
        }
        // A DLL that imports functions but avoids kernel32/ntdll/kernelbase AND
        // common runtime libraries (mscoree for .NET, ole32/oleaut32 for COM,
        // ucrtbase/vcruntime/msvcp for UCRT-only DLLs, ws2_32 for Winsock-only)
        // is likely resolving Win32 via direct syscalls to evade hooks.
        if !imports.is_empty() {
            let has_base = pe.imports.iter().any(|i| {
                let dll = i.dll.to_ascii_lowercase();
                dll.contains("kernel32")
                    || dll.contains("ntdll")
                    || dll.contains("kernelbase")
                    || dll.contains("mscoree")
                    || dll.contains("ole32")
                    || dll.contains("oleaut32")
                    || dll.contains("ucrtbase")
                    || dll.contains("vcruntime")
                    || dll.contains("msvcp")
                    || dll.contains("ws2_32")
            });
            sig.missing_base_imports = !has_base;
        }
    }

    // --- PE timestamp anomaly (separate signal from overlay) ---
    let ts = pe.header.coff_header.time_date_stamp;
    if !sig.signed && (ts == 0 || ts > FUTURE_TIMESTAMP_CUTOFF) {
        sig.timestamp_anomaly = true;
    }

    sig
}

/// Map structural signals to reported detections, applying FP discipline.
fn findings_for(sig: &Signals) -> Vec<Detection> {
    if sig.signed {
        return Vec::new();
    }

    // Reflective loader export is a standalone high-confidence signal.
    if sig.reflective_loader_export {
        return vec![Detection {
            name: "Heuristic.ReflectiveLoaderExport".to_string(),
            kind: DetectionKind::Heuristic,
            severity: Severity::High,
        }];
    }

    // Build the weighted signal list.
    let items: &[(&str, bool, u32)] = &[
        ("Heuristic.PackedCodeSection", sig.packed_code, 1),
        ("Heuristic.AnomalousOverlay", sig.anomalous_overlay, 1),
        ("Heuristic.SuspiciousTimestamp", sig.timestamp_anomaly, 1),
        (
            "Heuristic.WritableExecutableSection",
            sig.writable_executable,
            2,
        ),
        (
            "Heuristic.ProcessInjectionImports",
            sig.injection_imports,
            2,
        ),
        (
            "Heuristic.SuspiciousSectionName",
            sig.suspicious_section_name,
            2,
        ),
        ("Heuristic.ZeroImports", sig.zero_imports, 2),
        (
            "Heuristic.DllOrdinalOnlyExports",
            sig.dll_ordinal_only_exports,
            2,
        ),
        ("Heuristic.MissingBaseImports", sig.missing_base_imports, 2),
        ("Heuristic.DllNoExports", sig.dll_no_exports, 1),
    ];

    let triggered: Vec<(&str, Severity)> = items
        .iter()
        .filter(|(_, fired, _)| *fired)
        .map(|(name, _, _)| (*name, Severity::Medium))
        .collect();

    let total_weight: u32 = items
        .iter()
        .filter(|(_, fired, _)| *fired)
        .map(|(_, _, w)| w)
        .sum();

    if total_weight >= HEURISTIC_THRESHOLD {
        triggered
            .into_iter()
            .map(|(name, severity)| Detection {
                name: name.to_string(),
                kind: DetectionKind::Heuristic,
                severity,
            })
            .collect()
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

/// True if the section name matches a known packer or software-protector.
fn is_packer_section(name: &str) -> bool {
    matches!(
        name,
        "upx0"
            | "upx1"
            | "upx2"
            | "upx!"
            | ".aspack"
            | ".adata"
            | ".vmp0"
            | ".vmp1"
            | ".vmp2"
            | ".themida"
            | ".winlicen"
            | ".enigma1"
            | ".enigma2"
            | ".nsp0"
            | ".nsp1"
            | ".nsp2"
            | ".petite"
            | ".mpress1"
            | ".mpress2"
            | "pec2"
            | ".perplex"
            | ".svkp"
            | ".ace"
            | "!packer"
    )
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

    #[test]
    fn packer_section_names_recognised() {
        assert!(is_packer_section("upx0"));
        assert!(is_packer_section(".vmp0"));
        assert!(is_packer_section(".themida"));
        assert!(!is_packer_section(".text"));
        assert!(!is_packer_section(".data"));
    }

    // --- False-positive discipline (the reporting policy) ---

    #[test]
    fn single_weak_signal_is_not_reported() {
        // A lone weight-1 signal (packed_code) is well below the threshold.
        let sig = Signals {
            packed_code: true,
            ..Default::default()
        };
        assert!(
            findings_for(&sig).is_empty(),
            "packed_code alone must not be suspicious: {sig:?}"
        );
    }

    #[test]
    fn single_medium_signal_is_not_reported() {
        // A lone weight-2 signal is still below the threshold of 3.
        for sig in [
            Signals {
                writable_executable: true,
                ..Default::default()
            },
            Signals {
                injection_imports: true,
                ..Default::default()
            },
            Signals {
                zero_imports: true,
                ..Default::default()
            },
            Signals {
                dll_no_exports: true,
                ..Default::default()
            },
        ] {
            assert!(
                findings_for(&sig).is_empty(),
                "single weight-2 signal must not be suspicious: {sig:?}"
            );
        }
    }

    #[test]
    fn weight_1_plus_weight_2_reaches_threshold() {
        // packed_code (1) + injection_imports (2) = 3 >= threshold.
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
    fn two_weight_2_signals_reach_threshold() {
        let sig = Signals {
            writable_executable: true,
            injection_imports: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dll_no_exports_plus_packed_below_threshold() {
        let sig = Signals {
            dll_no_exports: true,
            packed_code: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        // dll_no_exports (1) + packed_code (1) = 2 < threshold (3)
        // Resource-only / plugin DLLs with optimised code must not be flagged.
        assert!(
            findings.is_empty(),
            "DLL with no exports + packed code alone must NOT be flagged (too common in legit DLLs)"
        );
    }

    #[test]
    fn dll_no_exports_plus_two_weight1_reaches_threshold() {
        let sig = Signals {
            dll_no_exports: true,
            packed_code: true,
            timestamp_anomaly: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        // dll_no_exports (1) + packed_code (1) + timestamp_anomaly (1) = 3
        assert!(
            !findings.is_empty(),
            "DLL with no exports + packed code + timestamp anomaly must be flagged"
        );
    }

    #[test]
    fn dll_no_exports_plus_weight2_reaches_threshold() {
        let sig = Signals {
            dll_no_exports: true,
            writable_executable: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        // dll_no_exports (1) + writable_executable (2) = 3
        assert!(
            !findings.is_empty(),
            "DLL with no exports + W^X section must be flagged"
        );
    }

    #[test]
    fn reflective_loader_export_fires_standalone() {
        let sig = Signals {
            reflective_loader_export: true,
            ..Default::default()
        };
        let findings = findings_for(&sig);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].name.contains("ReflectiveLoader"));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn signed_binaries_are_trusted_even_with_signals() {
        // Even with every signal set, a signed binary emits nothing here.
        let sig = Signals {
            packed_code: true,
            writable_executable: true,
            injection_imports: true,
            suspicious_section_name: true,
            zero_imports: true,
            dll_no_exports: true,
            signed: true,
            ..Default::default()
        };
        assert!(
            findings_for(&sig).is_empty(),
            "Authenticode-signed files are trusted at the heuristic layer"
        );
    }

    #[test]
    fn overlay_and_packed_code_reach_threshold() {
        let sig = Signals {
            anomalous_overlay: true,
            packed_code: true,
            zero_imports: true,
            ..Default::default()
        };
        // 1 + 1 + 2 = 4 >= 3
        assert!(!findings_for(&sig).is_empty());
    }

    #[test]
    fn timestamp_anomaly_is_separate_from_overlay() {
        // Timestamp alone (weight 1) must not fire.
        let sig = Signals {
            timestamp_anomaly: true,
            ..Default::default()
        };
        assert!(
            findings_for(&sig).is_empty(),
            "timestamp alone is not enough"
        );
        // Timestamp (1) + injection_imports (2) = 3 — should fire.
        let sig2 = Signals {
            timestamp_anomaly: true,
            injection_imports: true,
            ..Default::default()
        };
        let findings = findings_for(&sig2);
        assert!(
            !findings.is_empty(),
            "timestamp + injection imports must reach threshold"
        );
        // The finding name must mention Timestamp, not Overlay.
        assert!(
            findings.iter().any(|d| d.name.contains("Timestamp")),
            "should report SuspiciousTimestamp"
        );
    }

    #[test]
    fn dll_ordinal_only_exports_reaches_threshold() {
        // ordinal-only (2) + packed_code (1) = 3 >= threshold.
        let sig = Signals {
            dll_ordinal_only_exports: true,
            packed_code: true,
            ..Default::default()
        };
        assert!(
            !findings_for(&sig).is_empty(),
            "DLL with ordinal-only exports + packed code must be flagged"
        );
    }

    #[test]
    fn missing_base_imports_reaches_threshold() {
        // missing_base_imports (2) + anomalous_overlay (1) = 3 >= threshold.
        let sig = Signals {
            missing_base_imports: true,
            anomalous_overlay: true,
            ..Default::default()
        };
        assert!(
            !findings_for(&sig).is_empty(),
            "DLL bypassing kernel32/ntdll + overlay must be flagged"
        );
    }
}
