//! Stamps the build with the commit it was made from (`version` prints it as
//! the pin) and with its target.
//!
//! The commit is `GHOSTLANE_ENGINE_PIN` when the builder sets it (40 hex
//! digits, anything else fails the build), else what `git rev-parse HEAD`
//! says in this checkout, else `unknown`: a source tree with no git, or one
//! copied into another repository, whose commit says nothing of this code.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GHOSTLANE_ENGINE_PIN");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let pin = match env::var("GHOSTLANE_ENGINE_PIN") {
        Ok(pin) if is_commit(&pin) => pin,
        Ok(pin) => panic!("GHOSTLANE_ENGINE_PIN must be 40 lowercase hex digits, got `{pin}`"),
        Err(_) => git_head(&manifest).unwrap_or_else(|| "unknown".to_owned()),
    };
    println!("cargo:rustc-env=GHOSTLANE_ENGINE_PIN_BUILT={pin}");
    println!(
        "cargo:rustc-env=GHOSTLANE_ENGINE_TARGET={}",
        env::var("TARGET").expect("cargo sets it")
    );
}

fn is_commit(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The checkout's commit, and the files that move when it does as inputs of
/// this script (only those that exist: a path that is missing would run the
/// script at every build).
fn git_head(dir: &Path) -> Option<String> {
    // The crate at its own place in its own repository, not a copy of it
    // somewhere inside another one.
    if git(dir, &["rev-parse", "--show-prefix"])? != "crates/ghostlane-engine/" {
        return None;
    }
    let head = git(dir, &["rev-parse", "HEAD"]).filter(|head| is_commit(head))?;
    let mut inputs = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(branch) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        inputs.push(branch);
    }
    for input in inputs {
        let Some(path) = git(dir, &["rev-parse", "--git-path", &input]) else {
            continue;
        };
        let path = dir.join(path);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    Some(head)
}
