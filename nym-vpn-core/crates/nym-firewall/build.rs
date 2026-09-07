// SPDX-License-Identifier: GPL-3.0-only

//! Keeps `scripts/fw-rules.sh` — the shell fragment both firewall includes
//! source for the emergency and boot-time rule sets — identical to what
//! `src/openwrt/boot_rules.rs` renders. The module is compiled into this
//! build script directly (it is `std`-only for that reason), the fragment is
//! rendered, and the build fails while the committed file differs, the way
//! checked-in generated code is usually guarded. Set `NYM_FW_RULES_REGEN=1`
//! to rewrite the file instead; commit the result.

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
