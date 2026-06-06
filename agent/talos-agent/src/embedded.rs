//! Built-in detection content embedded into `talos-agent.exe`, so the service
//! protects with no external files. The on-disk store (feed updates) is merged
//! on top at load time — identical to the CLI and GUI.

/// Built-in hash-signature database: the EICAR baseline plus Talos's own
/// curated first-party database.
pub const HASHDB: &str = concat!(
    include_str!("../../../signatures/hashes/baseline.hashdb"),
    "\n",
    include_str!("../../../signatures/hashes/talos.hashdb"),
);

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
