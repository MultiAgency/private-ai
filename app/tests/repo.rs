//! The repo tools, as test/repo.test.mjs checks them, plus the hostile entries
//! a tarball can carry: a symlink out of the tree and a path that climbs with `..`.
use private_investigator::repo::Repo;
use serde_json::json;

fn header(path: &[u8], kind: tar::EntryType, size: u64) -> tar::Header {
    let mut h = tar::Header::new_old();
    h.as_old_mut().name[..path.len()].copy_from_slice(path);
    h.set_entry_type(kind);
    h.set_size(size);
    h.set_mode(0o644);
    h.set_cksum();
    h
}

/// A tarball shaped like GitHub's: one top-level directory holding the tree.
fn tarball() -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let mut file = |path: &str, data: &[u8]| {
        b.append(&header(path.as_bytes(), tar::EntryType::Regular, data.len() as u64), data).unwrap();
    };
    file("owner-repo-abc123/src/add.js", b"export const add = (a, b) => a - b;\nexport const one = 1;\n");
    file("owner-repo-abc123/README.md", b"# Example\n");
    file("owner-repo-abc123/node_modules/dep/index.js", b"a - b\n");
    file("owner-repo-abc123/../outside.txt", b"runner secret\n");
    file("owner-repo-abc123/logo.png", b"\x89PNG\0\0binary");
    let mut link = header(b"owner-repo-abc123/escape.txt", tar::EntryType::Symlink, 0);
    link.set_link_name("../../outside.txt").unwrap();
    link.set_cksum();
    b.append(&link, &b""[..]).unwrap();
    b.into_inner().unwrap().finish().unwrap()
}

#[test]
fn the_head_commit_unpacks_and_the_tools_read_it_with_line_numbers() {
    let repo = Repo::from_tarball(&tarball(), usize::MAX).unwrap();
    assert_eq!(repo.call("list_files", &json!({})), "README.md\nlogo.png\nsrc/");
    assert_eq!(repo.call("read_file", &json!({ "path": "src/add.js", "start_line": 2, "end_line": 2 })), "2\texport const one = 1;\n… 1 more lines");
    assert_eq!(repo.call("grep", &json!({ "pattern": "a - b" })), "src/add.js:1: export const add = (a, b) => a - b;");
    assert_eq!(repo.call("grep", &json!({ "pattern": "nothing" })), "no matches");
    assert_eq!(repo.call("read_file", &json!({ "path": "logo.png" })), "logo.png is binary or larger than 1000000 bytes");
}

#[test]
fn no_path_leaves_the_head_commit_through_dotdot_or_a_symlink() {
    let repo = Repo::from_tarball(&tarball(), usize::MAX).unwrap();
    assert_eq!(repo.file_count(), 4, "the symlink and the climbing entry are dropped");
    assert!(repo.call("read_file", &json!({ "path": "../../../../etc/hosts" })).starts_with("error: "));
    assert!(repo.call("read_file", &json!({ "path": "escape.txt" })).starts_with("error: "));
    assert!(!repo.call("grep", &json!({ "pattern": "runner secret" })).contains("runner secret"));
    assert!(!repo.call("list_files", &json!({})).contains("escape"));
    assert!(!repo.call("grep", &json!({ "pattern": "a - b" })).contains("node_modules"));
}

#[test]
fn bad_input_comes_back_as_an_error_the_model_can_read() {
    let repo = Repo::from_tarball(&tarball(), usize::MAX).unwrap();
    assert!(repo.call("grep", &json!({ "pattern": "(" })).starts_with("error: "));
    assert_eq!(repo.call("read_file", &json!({ "path": "missing.js" })), "error: missing.js does not exist");
    assert_eq!(repo.call("run_shell", &json!({ "command": "id" })), "unknown tool run_shell");
    assert_eq!(repo.call("read_file", &json!({ "path": "src" })), "error: src is a directory");
}

#[test]
fn common_patterns_and_lookaround_work() {
    let repo = Repo::from_tarball(&tarball(), usize::MAX).unwrap();
    for pattern in [r"\bone\b", r"export\s+const", r"add(?= =)", r"(a), \(?b\)?", r"a \- b", r"\/"] {
        assert!(!repo.call("grep", &json!({ "pattern": pattern })).starts_with("error"), "{pattern}");
    }
}

#[test]
fn the_tool_descriptions_state_the_limits_the_tools_enforce() {
    let spec = private_investigator::review::spec();
    let limits = &spec["repo_limits"];
    let description = |name: &str| Repo::definitions().into_iter().find(|t| t["function"]["name"] == name).unwrap()["function"]["description"].as_str().unwrap().to_string();
    assert!(description("read_file").contains(&format!("At most {} lines", limits["max_lines"])));
    assert!(description("grep").contains(&format!("up to {} matching lines", limits["max_matches"])));
}

/// A tarball of the given files, compressed the way a hostile one would be: zeros squeeze well.
fn tarball_of(files: &[(&str, usize)]) -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best()));
    for (path, size) in files {
        b.append(&header(format!("owner-repo-abc123/{path}").as_bytes(), tar::EntryType::Regular, *size as u64), &vec![b'a'; *size][..]).unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

#[test]
fn a_file_over_the_limit_is_listed_but_never_held() {
    let gzipped = tarball_of(&[("big.txt", 50_000_000), ("small.txt", 10)]);
    assert!(gzipped.len() < 1_000_000, "50 MB of one byte compresses to a small download");
    let repo = Repo::from_tarball(&gzipped, 1_000).expect("the big file costs nothing against the budget");
    assert_eq!(repo.call("list_files", &json!({})), "big.txt\nsmall.txt");
    assert_eq!(repo.call("read_file", &json!({ "path": "big.txt" })), "big.txt is binary or larger than 1000000 bytes");
    assert_eq!(repo.call("grep", &json!({ "pattern": "a" })), "small.txt:1: aaaaaaaaaa");
}

#[test]
fn a_tree_past_the_budget_is_refused() {
    let gzipped = tarball_of(&[("a.txt", 600_000), ("b.txt", 600_000)]);
    assert!(Repo::from_tarball(&gzipped, 1_000_000).is_err_and(|e| e.to_string() == private_investigator::repo::TOO_LARGE));
    assert!(Repo::from_tarball(&gzipped, 1_200_000).is_ok());
}
