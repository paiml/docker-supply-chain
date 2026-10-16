//! `pinscan`: three supply-chain checks for container builds. `pins` finds base images that are
//! not pinned by digest, `diff` compares two CycloneDX SBOMs, and `gate` fails a build whose
//! SBOM contains a denied component.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;

/// One `FROM` line of a Dockerfile.
#[derive(Debug, PartialEq, Eq)]
pub struct FromLine {
    pub image: String,
    pub pinned: bool,
}

fn is_digest_pin(image: &str) -> bool {
    match image.split_once("@sha256:") {
        Some((_, hex)) => hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// Parses the `FROM` lines; `scratch` and stage names from earlier stages count as pinned.
pub fn parse_from(dockerfile: &str) -> Vec<FromLine> {
    let mut stages: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for line in dockerfile.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if !words
            .first()
            .is_some_and(|w| w.eq_ignore_ascii_case("FROM"))
        {
            continue;
        }
        let Some(image) = words[1..].iter().find(|w| !w.starts_with("--")) else {
            continue;
        };
        let pinned =
            *image == "scratch" || stages.iter().any(|s| s == image) || is_digest_pin(image);
        if let Some(pos) = words.iter().position(|w| w.eq_ignore_ascii_case("AS")) {
            if let Some(name) = words.get(pos + 1) {
                stages.push((*name).to_string());
            }
        }
        out.push(FromLine {
            image: (*image).to_string(),
            pinned,
        });
    }
    out
}

/// The `name@version` set of a CycloneDX JSON document.
pub fn components(sbom: &str) -> Result<BTreeSet<String>, String> {
    let v: Value = serde_json::from_str(sbom).map_err(|e| format!("not JSON: {e}"))?;
    let list = v
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| "no components array".to_string())?;
    Ok(list
        .iter()
        .map(|c| {
            let name = c.get("name").and_then(Value::as_str).unwrap_or("?");
            let version = c.get("version").and_then(Value::as_str).unwrap_or("?");
            format!("{name}@{version}")
        })
        .collect())
}

/// Components added and removed going from `a` to `b`.
pub fn sbom_diff(a: &BTreeSet<String>, b: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        b.difference(a).cloned().collect(),
        a.difference(b).cloned().collect(),
    )
}

/// Components whose name is on the deny list.
pub fn gate(found: &BTreeSet<String>, deny: &[&str]) -> Vec<String> {
    found
        .iter()
        .filter(|c| {
            let name = c.split('@').next().unwrap_or("");
            deny.contains(&name)
        })
        .cloned()
        .collect()
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn load(path: &str) -> Result<BTreeSet<String>, String> {
    components(&read(path)?)
}

fn dispatch(args: &[String], out: &mut dyn Write) -> Result<i32, String> {
    let io = |e: std::io::Error| e.to_string();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["pins", file] => {
            let froms = parse_from(&read(file)?);
            for f in &froms {
                writeln!(out, "{} {}", if f.pinned { "pinned  " } else { "UNPINNED" }, f.image).map_err(io)?;
            }
            let bad = froms.iter().filter(|f| !f.pinned).count();
            if bad == 0 {
                writeln!(out, "contract: all-bases-pinned OK").map_err(io)?;
            }
            Ok(i32::from(bad > 0))
        }
        ["diff", a, b] => {
            let (added, removed) = sbom_diff(&load(a)?, &load(b)?);
            for c in &added {
                writeln!(out, "+ {c}").map_err(io)?;
            }
            for c in &removed {
                writeln!(out, "- {c}").map_err(io)?;
            }
            writeln!(out, "{} added, {} removed", added.len(), removed.len()).map_err(io)?;
            Ok(0)
        }
        ["gate", sbom, deny] => {
            let deny: Vec<&str> = deny.split(',').collect();
            let hits = gate(&load(sbom)?, &deny);
            for h in &hits {
                writeln!(out, "DENIED {h}").map_err(io)?;
            }
            if hits.is_empty() {
                writeln!(out, "contract: no-denied-components OK").map_err(io)?;
            }
            Ok(i32::from(!hits.is_empty()))
        }
        _ => Err("usage: pinscan pins <Dockerfile> | diff <a.json> <b.json> | gate <sbom.json> <name,name>".to_string()),
    }
}

/// Runs the command line; returns the exit code (0 ok, 1 finding, 2 usage or input error).
pub fn run(args: &[String], out: &mut dyn Write) -> i32 {
    match dispatch(args, out) {
        Ok(code) => code,
        Err(msg) => {
            let _ = writeln!(out, "pinscan: {msg}");
            2
        }
    }
}
