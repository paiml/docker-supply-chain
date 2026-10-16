use pinscan::{components, gate, parse_from, run, sbom_diff, FromLine};

const PINNED: &str = include_str!("../fixtures/pinned.Dockerfile");
const LOOSE: &str = include_str!("../fixtures/loose.Dockerfile");
const A: &str = include_str!("../fixtures/a.cdx.json");
const B: &str = include_str!("../fixtures/b.cdx.json");

fn cmd(args: &[&str]) -> (i32, String) {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let code = run(&a, &mut out);
    (code, String::from_utf8(out).unwrap())
}

fn fixture(name: &str) -> String {
    format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn digest_pinned_stage_names_and_scratch_count_as_pinned() {
    let f = parse_from(PINNED);
    assert_eq!(f.len(), 3);
    assert!(f.iter().all(|l| l.pinned), "{f:?}");
}

#[test]
fn tags_are_not_pins() {
    let f = parse_from(LOOSE);
    assert_eq!(
        f[0],
        FromLine {
            image: "rust:1-alpine".into(),
            pinned: false
        }
    );
    assert!(!f[1].pinned);
}

#[test]
fn a_short_or_non_hex_digest_is_not_a_pin() {
    assert!(!parse_from("FROM x@sha256:abc")[0].pinned);
    let bad = format!("FROM x@sha256:{}", "z".repeat(64));
    assert!(!parse_from(&bad)[0].pinned);
}

#[test]
fn platform_flags_and_bare_from_are_handled() {
    let f = parse_from("from --platform=linux/amd64 alpine:3 as base\nFROM\nRUN x\nFROM base");
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].image, "alpine:3");
    assert!(f[1].pinned);
}

#[test]
fn as_without_a_name_is_ignored() {
    assert_eq!(parse_from("FROM alpine AS").len(), 1);
}

#[test]
fn components_reads_names_and_versions() {
    let c = components(A).unwrap();
    assert!(c.contains("musl@1.2.5"));
    assert!(components(B).unwrap().contains("zlib@?"));
}

#[test]
fn components_rejects_bad_input() {
    assert!(components("nope").unwrap_err().starts_with("not JSON"));
    assert_eq!(components("{}").unwrap_err(), "no components array");
    assert!(components(r#"{"components":[{}]}"#)
        .unwrap()
        .contains("?@?"));
}

#[test]
fn diff_lists_added_and_removed() {
    let (add, rem) = sbom_diff(&components(A).unwrap(), &components(B).unwrap());
    assert_eq!(add, ["musl@1.2.6", "zlib@?"]);
    assert_eq!(rem, ["musl@1.2.5", "openssl@3.3.0"]);
}

#[test]
fn gate_matches_names_not_versions() {
    let c = components(A).unwrap();
    assert_eq!(gate(&c, &["openssl"]), ["openssl@3.3.0"]);
    assert!(gate(&c, &["3.3.0"]).is_empty());
}

#[test]
fn pins_command_passes_and_fails() {
    let (code, out) = cmd(&["pins", &fixture("pinned.Dockerfile")]);
    assert_eq!(code, 0);
    assert!(out.contains("contract: all-bases-pinned OK"));
    let (code, out) = cmd(&["pins", &fixture("loose.Dockerfile")]);
    assert_eq!(code, 1);
    assert!(out.contains("UNPINNED rust:1-alpine"));
    assert!(!out.contains("contract"));
}

#[test]
fn diff_command_prints_changes() {
    let (code, out) = cmd(&["diff", &fixture("a.cdx.json"), &fixture("b.cdx.json")]);
    assert_eq!(code, 0);
    assert!(out.contains("+ zlib@?") && out.contains("- openssl@3.3.0"));
    assert!(out.contains("2 added, 2 removed"));
}

#[test]
fn gate_command_denies_and_allows() {
    let (code, out) = cmd(&["gate", &fixture("a.cdx.json"), "openssl,curl"]);
    assert_eq!(code, 1);
    assert!(out.contains("DENIED openssl@3.3.0"));
    let (code, out) = cmd(&["gate", &fixture("b.cdx.json"), "openssl"]);
    assert_eq!(code, 0);
    assert!(out.contains("contract: no-denied-components OK"));
}

#[test]
fn usage_and_input_errors_exit_two() {
    assert_eq!(cmd(&[]).0, 2);
    let (code, out) = cmd(&["pins", "/no/such/file"]);
    assert_eq!(code, 2);
    assert!(out.starts_with("pinscan: /no/such/file"));
    assert_eq!(cmd(&["diff", &fixture("a.cdx.json"), "/no/such"]).0, 2);
}

struct Broken;
impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_errors_are_reported_as_exit_two() {
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        run(&args(&["pins", &fixture("loose.Dockerfile")]), &mut Broken),
        2
    );
    assert_eq!(
        run(
            &args(&["diff", &fixture("a.cdx.json"), &fixture("b.cdx.json")]),
            &mut Broken
        ),
        2
    );
    assert_eq!(
        run(
            &args(&["gate", &fixture("a.cdx.json"), "openssl"]),
            &mut Broken
        ),
        2
    );
}

#[test]
#[ignore]
fn calls_nothing() {}
