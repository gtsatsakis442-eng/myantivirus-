//! Static heuristic analysis layer (L2): lightweight PE structural checks.
//!
//! Heuristics produce *suspicion* signals — never a definitive malicious
//! verdict on their own (see [`crate::verdict::Disposition::Suspicious`]). They
//! only run on PE files; any other input yields no findings, so ordinary
//! documents and scripts are never flagged by this layer.

use goblin::pe::PE;

use crate::verdict::{Detection, DetectionKind, Severity};

/// Entropy (bits/byte) above which a section looks packed/encrypted.
const PACKED_ENTROPY: f64 = 7.2;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Analyze a buffer, returning heuristic findings (empty for non-PE input).
pub fn analyze(data: &[u8]) -> Vec<Detection> {
    let pe = match PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    let mut packed = false;

    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = start.saturating_add(size);
        if size != 0
            && start < data.len()
            && end <= data.len()
            && shannon_entropy(&data[start..end]) > PACKED_ENTROPY
        {
            packed = true;
        }
        if is_writable_executable(section.characteristics) {
            findings.push(detection(
                "Heuristic.WritableExecutableSection",
                Severity::Medium,
            ));
        }
    }

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_ascii_lowercase())
        .collect();
    if has_injection_combo(&imports) {
        findings.push(detection(
            "Heuristic.ProcessInjectionImports",
            Severity::Medium,
        ));
    }

    if packed {
        findings.push(detection("Heuristic.HighEntropySection", Severity::Low));
    }

    findings
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
}
