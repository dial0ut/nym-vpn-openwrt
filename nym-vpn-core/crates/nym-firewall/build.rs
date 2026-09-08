// SPDX-License-Identifier: GPL-3.0-only

//! Fails the build while `scripts/fw-rules.sh` differs from what
//! `src/openwrt/boot_rules.rs` renders (compiled in via `#[path]`, hence
//! `std`-only). `NYM_FW_RULES_REGEN=1` rewrites the file instead.

use std::env;
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "src/openwrt/boot_rules.rs"]
mod boot_rules;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/openwrt/boot_rules.rs");
    println!("cargo:rerun-if-changed=scripts/fw-rules.sh");
    println!("cargo:rerun-if-env-changed=NYM_FW_RULES_REGEN");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("scripts").join("fw-rules.sh");
    let rendered = boot_rules::shell_fragment();
    let committed = fs::read_to_string(&path).unwrap_or_default();

    if committed == rendered {
        return;
    }
    if env::var_os("NYM_FW_RULES_REGEN").is_some() {
        fs::write(&path, rendered).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        println!("cargo:warning=regenerated {}; commit it", path.display());
        return;
    }
    panic!(
        "{} is out of date with src/openwrt/boot_rules.rs. \
         Regenerate with `NYM_FW_RULES_REGEN=1 cargo build -p nym-firewall` and commit the result.",
        path.display()
    );
}
