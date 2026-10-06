//! The pull request's head commit, held in memory, and the read-only tools the
//! model uses on it. Port of `review/repo.mjs`, with the definitions and limits
//! from `review/review.json`. Nothing is written to disk or executed, and the
//! tree holds only regular files at normalized paths: symlinks, hardlinks and
//! any path with `..` are dropped when the tarball is read, so no path the
//! model names can leave the commit.
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use crate::review::spec;

fn limit(key: &str) -> usize {
    spec()["repo_limits"][key].as_u64().unwrap_or_else(|| panic!("review.json lacks repo_limits.{key}")) as usize
}

fn skipped(name: &str) -> bool {
    spec()["repo_limits"]["skip_dirs"].as_array().into_iter().flatten().any(|d| d.as_str() == Some(name))
}

/// JavaScript's string order (UTF-16 code units), as the Action sorts.
fn js_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The first `n` UTF-16 code units of `s`, never splitting a character.
fn js_prefix(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > n {
            return &s[..i];
        }
    }
    s
}

pub struct Repo {
    /// Each file's bytes, or `None` for one larger than `max_file_bytes`: the
    /// tools refuse those anyway, so they are listed but never held.
    files: BTreeMap<String, Option<Vec<u8>>>,
    dirs: BTreeSet<String>,
}

/// The message when the files held would pass the budget `from_tarball` is given.
pub const TOO_LARGE: &str = "the head commit is larger than a run can hold";

/// A path inside the commit, normalized; `None` when it would leave it.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

enum Node<'a> {
    Dir(String),
    File(Option<&'a [u8]>),
}

impl Repo {
    /// Reads a GitHub tarball (one top-level directory holding the tree),
    /// holding at most `budget` bytes of files.
    pub fn from_tarball(gzipped: &[u8], budget: usize) -> Result<Self> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(gzipped));
        let (mut files, mut dirs) = (BTreeMap::new(), BTreeSet::from([String::new()]));
        let (max, mut held) = (limit("max_file_bytes"), 0usize);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let kind = entry.header().entry_type();
            if !(kind.is_file() || kind.is_dir()) {
                continue;
            }
            let raw = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            // Strip GitHub's top-level directory; drop anything that climbs out.
            let Some(path) = raw.split_once('/').map(|(_, rest)| rest).filter(|r| !r.split('/').any(|p| p == "..")).and_then(normalize) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            let mut parent = path.as_str();
            while let Some((up, _)) = parent.rsplit_once('/') {
                dirs.insert(up.to_string());
                parent = up;
            }
            if kind.is_dir() {
                dirs.insert(path);
            } else if entry.size() > max as u64 {
                files.insert(path, None);
            } else {
                // Read no more than the limit, whatever size the header claims.
                let mut bytes = Vec::new();
                entry.by_ref().take(max as u64 + 1).read_to_end(&mut bytes)?;
                held += bytes.len();
                if held > budget {
                    anyhow::bail!(TOO_LARGE);
                }
                files.insert(path, (bytes.len() <= max).then_some(bytes));
            }
        }
        Ok(Self { files, dirs })
    }

    fn node(&self, path: &str) -> std::result::Result<(String, Node<'_>), String> {
        let rel = normalize(path).ok_or_else(|| format!("{path} is outside the repository"))?;
        if let Some(bytes) = self.files.get(&rel) {
            Ok((rel, Node::File(bytes.as_deref())))
        } else if self.dirs.contains(&rel) {
            Ok((rel.clone(), Node::Dir(rel)))
        } else {
            Err(format!("{path} does not exist"))
        }
    }

    fn text(bytes: Option<&[u8]>) -> Option<String> {
        let bytes = bytes?;
        if bytes.len() > limit("max_file_bytes") || bytes.contains(&0) {
            return None;
        }
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Immediate children of a directory: subdirectories end in "/".
    fn children(&self, dir: &str) -> Vec<String> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let child = |p: &String| p.strip_prefix(&prefix).filter(|rest| !rest.is_empty() && !rest.contains('/')).map(String::from);
        let mut entries: Vec<String> = self
            .dirs
            .iter()
            .filter_map(child)
            .filter(|n| !skipped(n))
            .map(|n| format!("{n}/"))
            .chain(self.files.keys().filter_map(child).filter(|n| !skipped(n)))
            .collect();
        entries.sort_by(|a, b| js_order(a, b));
        entries
    }

    /// Every file under a directory, in order, skipping skipped directories.
    fn walk(&self, dir: &str) -> Vec<(&String, &Option<Vec<u8>>)> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        self.files
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix))
            .filter(|(p, _)| {
                let rest = &p[prefix.len()..];
                let dirs: Vec<&str> = rest.split('/').collect();
                !dirs[..dirs.len() - 1].iter().any(|d| skipped(d))
            })
            .collect()
    }

    fn list_files(&self, args: &Value) -> std::result::Result<String, String> {
        let path = args["path"].as_str().unwrap_or(".");
        let (_, node) = self.node(path)?;
        let Node::Dir(dir) = node else { return Err(format!("{path} is not a directory")) };
        let entries = self.children(&dir);
        let max = limit("max_entries");
        let mut out = entries.iter().take(max).cloned().collect::<Vec<_>>().join("\n");
        if entries.len() > max {
            out.push_str(&format!("\n… {} more", entries.len() - max));
        }
        Ok(out)
    }

    fn read_file(&self, args: &Value) -> std::result::Result<String, String> {
        let path = args["path"].as_str().unwrap_or("");
        let (_, node) = self.node(path)?;
        let Node::File(bytes) = node else { return Err(format!("{path} is a directory")) };
        let Some(content) = Self::text(bytes) else {
            return Ok(format!("{path} is binary or larger than {} bytes", limit("max_file_bytes")));
        };
        let lines: Vec<&str> = content.split('\n').collect();
        let max = limit("max_lines") as i64;
        let start = number(&args["start_line"]).unwrap_or(1).max(1);
        let end = [lines.len() as i64, number(&args["end_line"]).unwrap_or(start + max - 1), start + max - 1].into_iter().min().unwrap();
        let mut out = (start..=end)
            .filter_map(|n| lines.get((n - 1) as usize).map(|line| format!("{n}\t{line}")))
            .collect::<Vec<_>>()
            .join("\n");
        if end < lines.len() as i64 {
            out.push_str(&format!("\n… {} more lines", lines.len() as i64 - end));
        }
        Ok(out)
    }

    fn grep(&self, args: &Value) -> std::result::Result<String, String> {
        let pattern = args["pattern"].as_str().unwrap_or("");
        let regex = fancy_regex::Regex::new(pattern).map_err(|e| format!("invalid regular expression: {e}"))?;
        let (rel, node) = self.node(args["path"].as_str().unwrap_or("."))?;
        let files = match node {
            Node::Dir(dir) => self.walk(&dir),
            Node::File(_) => self.files.get_key_value(&rel).into_iter().collect(),
        };
        let max = limit("max_matches");
        let mut matches = Vec::new();
        for (path, bytes) in files {
            let Some(content) = Self::text(bytes.as_deref()) else { continue };
            for (i, line) in content.split('\n').enumerate() {
                // A pattern too costly to finish counts as no match on that line.
                if !regex.is_match(line).unwrap_or(false) {
                    continue;
                }
                matches.push(format!("{path}:{}: {}", i + 1, js_prefix(line, 300)));
                if matches.len() == max {
                    return Ok(format!("{}\n… stopped at {max} matches", matches.join("\n")));
                }
            }
        }
        Ok(if matches.is_empty() { "no matches".into() } else { matches.join("\n") })
    }

    /// Runs a tool the model called; every outcome is text for the model.
    pub fn call(&self, name: &str, args: &Value) -> String {
        let result = match name {
            "list_files" => self.list_files(args),
            "read_file" => self.read_file(args),
            "grep" => self.grep(args),
            _ => return format!("unknown tool {name}"),
        };
        result.unwrap_or_else(|e| format!("error: {e}"))
    }

    pub fn definitions() -> Vec<Value> {
        spec()["repo_tools"].as_array().cloned().unwrap_or_default()
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// A line number the model sent, as JavaScript would read it.
fn number(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(s) => s.trim().parse::<f64>().ok().map(|f| f.trunc() as i64),
        _ => None,
    }
}

