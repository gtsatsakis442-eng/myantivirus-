//! Built-in default detection content, embedded into the binary at compile time
//! so the **standalone `talos.exe` works with no external files**.
//!
//! External content takes precedence when present: an MSI install lays a
//! `signatures/` folder next to the exe, and `--hashes` / `--rules` override
//! explicitly. Only when none is found do we fall back to these built-ins.

/// Baseline hash-signature database (the same file shipped under `signatures/`).
pub const HASHDB: &str = include_str!("../../../signatures/hashes/baseline.hashdb");

/// Built-in YARA rules as `(name, source)` pairs.
pub const YARA_RULES: &[(&str, &str)] = &[
    (
        "eicar.yar",
        include_str!("../../../signatures/yara/eicar.yar"),
    ),
    (
        "webshells.yar",
        include_str!("../../../signatures/yara/webshells.yar"),
    ),
    (
        "powershell.yar",
        include_str!("../../../signatures/yara/powershell.yar"),
    ),
];
