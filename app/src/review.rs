//! The review's text and its checks, shared with the Action: the prompts,
//! schema and limits come from `review/review.json`, and the code here matches
//! `review/review.mjs` exactly (pinned by `test/fixtures/review-case.json`).
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// `review/review.json`, compiled in.
pub fn spec() -> &'static Value {
    static SPEC: OnceLock<Value> = OnceLock::new();
    SPEC.get_or_init(|| serde_json::from_str(include_str!("../../review/review.json")).expect("review.json is valid"))
}

/// How a review runs unless told otherwise (review.json `defaults`).
pub struct Defaults {
    pub model: String,
    pub passes: u64,
    pub max_turns: u64,
    pub rubric: Vec<String>,
    /// Whether a second pass checks the findings against the code.
    pub verify: bool,
}

pub fn defaults() -> Defaults {
    let d = &spec()["defaults"];
    Defaults {
        model: d["model"].as_str().expect("review.json defaults.model").to_string(),
        passes: d["passes"].as_u64().expect("review.json defaults.passes"),
        max_turns: d["max_turns"].as_u64().expect("review.json defaults.max_turns"),
        rubric: d["rubric"].as_array().expect("review.json defaults.rubric").iter().filter_map(|p| p.as_str().map(String::from)).collect(),
        verify: d["verify"].as_bool().expect("review.json defaults.verify"),
    }
}

fn limit(key: &str) -> usize {
    spec()[key].as_u64().unwrap_or_else(|| panic!("review.json lacks {key}")) as usize
}

/// JavaScript's `string.length`: UTF-16 code units, which the shared limits count.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn system_prompt(rubric: &str) -> String {
    spec()["system_prompt"].as_str().expect("system_prompt").replacen("{rubric}", rubric, 1)
}

/// Text on one line: each line trimmed, blank ones dropped.
fn one_line(text: &str) -> String {
    text.split('\n').map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ")
}

pub fn user_prompt(pr: &Value, files: &[Value], earlier: &[Value]) -> String {
    let (patch_limit, mut budget) = (limit("patch_limit"), limit("prompt_limit"));
    let sections: Vec<String> = files
        .iter()
        .map(|f| {
            let header = format!(
                "### {} ({}, +{} \u{2212}{})",
                f["filename"].as_str().unwrap_or(""),
                f["status"].as_str().unwrap_or(""),
                f["additions"],
                f["deletions"]
            );
            if skipped(f["filename"].as_str().unwrap_or("")) {
                return format!("{header}\n(lockfile, vendored or generated: diff left out)");
            }
            match f["patch"].as_str().filter(|p| !p.is_empty()) {
                None => format!("{header}\n(no text diff)"),
                Some(patch) if js_len(patch) > patch_limit || js_len(patch) > budget => format!("{header}\n(diff too large to include: read the file)"),
                Some(patch) => {
                    budget -= js_len(patch);
                    format!("{header}\n```diff\n{patch}\n```")
                }
            }
        })
        .collect();
    let body = pr["body"].as_str().filter(|b| !b.is_empty()).unwrap_or("(none)");
    let mut prompt = format!(
        "Pull request #{}: {}\nBase: {} ({}). Head: {} ({}).\n\n## Description\n\n{body}\n\n## Changed files ({})\n\n{}",
        pr["number"],
        pr["title"].as_str().unwrap_or(""),
        pr["base"]["ref"].as_str().unwrap_or(""),
        pr["base"]["sha"].as_str().unwrap_or(""),
        pr["head"]["ref"].as_str().unwrap_or(""),
        pr["head"]["sha"].as_str().unwrap_or(""),
        files.len(),
        sections.join("\n\n"),
    );
    if !earlier.is_empty() {
        let list: Vec<String> = earlier
            .iter()
            .map(|f| format!("- `{}`: {}", f["path"].as_str().unwrap_or(""), one_line(f["body"].as_str().unwrap_or(""))))
            .collect();
        prompt.push_str(&format!("\n\n## Your earlier findings on this pull request\n\n{}", list.join("\n")));
    }
    prompt
}

/// Lockfiles, vendored and generated files: listed for the model, their diff left out (review.json `skip`).
pub fn skipped(path: &str) -> bool {
    let skip = &spec()["skip"];
    let has = |key: &str, s: &str| skip[key].as_array().into_iter().flatten().any(|v| v.as_str() == Some(s));
    let mut parts: Vec<&str> = path.split('/').collect();
    let name = parts.pop().unwrap_or("");
    has("names", name) || parts.iter().any(|dir| has("dirs", dir)) || skip["suffixes"].as_array().into_iter().flatten().filter_map(Value::as_str).any(|s| name.ends_with(s))
}

/// The lines a review comment may sit on, by file: added and context lines of
/// the new file, line number to text.
pub type NewLines = BTreeMap<String, BTreeMap<u64, String>>;

pub fn new_lines(files: &[Value]) -> NewLines {
    let mut by_file = NewLines::new();
    for file in files {
        let mut lines = BTreeMap::new();
        let mut line: u64 = 0;
        for row in file["patch"].as_str().unwrap_or("").split('\n') {
            if let Some(start) = hunk_start(row) {
                line = start;
            } else if row.starts_with('+') || row.starts_with(' ') {
                lines.insert(line, row[1..].to_string());
                line += 1;
            }
        }
        if !lines.is_empty() {
            by_file.insert(file["filename"].as_str().unwrap_or("").to_string(), lines);
        }
    }
    by_file
}

/// "path:line" for every line a review comment may sit on.
pub fn commentable_lines(files: &[Value]) -> Vec<String> {
    let mut lines: Vec<String> = new_lines(files).iter().flat_map(|(path, lines)| lines.keys().map(move |line| format!("{path}:{line}"))).collect();
    lines.sort();
    lines
}

/// Where a finding sits on the diff (review.mjs `place`): the changed lines that
/// hold its quoted existing_code, nearest its reported line (`exact`), else its
/// reported line when that is commentable, else nowhere.
#[derive(Debug, PartialEq, Eq)]
pub struct Placed {
    pub start: u64,
    pub end: u64,
    pub exact: bool,
}

pub fn place(finding: &Value, lines: &NewLines) -> Option<Placed> {
    let in_file = lines.get(finding["path"].as_str().unwrap_or(""))?;
    let reported = finding["line"].as_f64().unwrap_or(-1.0);
    let quoted: Vec<&str> = finding["existing_code"].as_str().unwrap_or("").split('\n').collect();
    let first = quoted.iter().position(|l| !l.trim().is_empty());
    let last = quoted.iter().rposition(|l| !l.trim().is_empty());
    let snippet: Vec<&str> = match (first, last) {
        (Some(a), Some(b)) => quoted[a..=b].iter().map(|l| l.trim()).collect(),
        _ => vec![],
    };
    let mut best: Option<Placed> = None;
    if !snippet.is_empty() {
        for &start in in_file.keys() {
            if !snippet.iter().enumerate().all(|(k, text)| in_file.get(&(start + k as u64)).is_some_and(|l| l.trim() == *text)) {
                continue;
            }
            let distance = |s: u64| (s as f64 - reported).abs();
            if best.as_ref().is_none_or(|b| distance(start) < distance(b.start)) {
                best = Some(Placed { start, end: start + snippet.len() as u64 - 1, exact: true });
            }
        }
    }
    if best.is_some() {
        return best;
    }
    let line = finding["line"].as_u64().or_else(|| finding["line"].as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0).map(|f| f as u64))?;
    in_file.contains_key(&line).then_some(Placed { start: line, end: line, exact: false })
}

/// The new file's first line in a hunk header: `^@@ -\d+(?:,\d+)? \+(\d+)`.
fn hunk_start(row: &str) -> Option<u64> {
    let rest = row.strip_prefix("@@ -")?;
    let digits = rest.find(|c: char| !c.is_ascii_digit())?;
    if digits == 0 {
        return None;
    }
    let mut rest = &rest[digits..];
    if let Some(after) = rest.strip_prefix(',') {
        let n = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        if n == 0 {
            return None;
        }
        rest = &after[n..];
    }
    let rest = rest.strip_prefix(" +")?;
    let n = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..n].parse().ok()
}

/// JavaScript's `Number.isInteger` on a JSON value.
fn is_integer(v: &Value) -> bool {
    v.as_i64().is_some() || v.as_u64().is_some() || v.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

/// Why a submission is incomplete, for the model to fix; `None` when it is complete.
pub fn check_submission(submission: &Value) -> Option<String> {
    let (Some(_), Some(findings)) = (submission["summary"].as_str(), submission["findings"].as_array()) else {
        return Some("submit_review needs a summary and a findings array".into());
    };
    let checked = &submission["checked"];
    if !checked.is_null() && !checked.as_array().is_some_and(|c| c.iter().all(Value::is_string)) {
        return Some("checked must be a list of strings".into());
    }
    let bad = findings.iter().position(|f| {
        !f["path"].is_string()
            || !is_integer(&f["line"])
            || !["pass", "severity", "title", "body"].iter().all(|k| f[*k].as_str().is_some_and(|s| !s.is_empty()))
            || ["category", "existing_code", "suggestion", "fix_code"].iter().any(|k| !f[*k].is_null() && !f[*k].is_string())
    })?;
    let keys = findings[bad].as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(", ")).filter(|k| !k.is_empty());
    Some(format!(
        "finding {} needs path (string), line (integer), pass, severity, title and body, and existing_code as text; it has {}",
        bad + 1,
        keys.as_deref().unwrap_or("nothing")
    ))
}

/// Why a verify submission is incomplete; `None` when it is complete.
pub fn check_verdicts(submission: &Value) -> Option<String> {
    let Some(verdicts) = submission["verdicts"].as_array() else {
        return Some("submit_verdicts needs a verdicts array".into());
    };
    let bad = verdicts.iter().position(|v| !is_integer(&v["index"]) || !v["keep"].is_boolean())?;
    Some(format!("verdict {} needs index (integer) and keep (boolean)", bad + 1))
}

/// JavaScript truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// A JSON number as JavaScript prints it (3.0 is "3").
fn js_number(v: &Value) -> String {
    match v.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 9e15 => format!("{}", f as i64),
        _ => v.to_string(),
    }
}

/// Model-written text is untrusted: it cannot open a one-click suggestion
/// block or a hidden HTML comment in what is posted (review.mjs `clean`).
pub fn clean(text: &str) -> String {
    static SUGGESTION: OnceLock<fancy_regex::Regex> = OnceLock::new();
    let re = SUGGESTION.get_or_init(|| fancy_regex::Regex::new(r"(?i)```[ \t]*suggestion").expect("valid"));
    re.replace_all(text, "```text").replace("<!--", "&lt;!--")
}

/// The checked list, each item on one line, cut off once it passes 1500 characters in all.
fn checked_items(checked: &[Value]) -> Vec<String> {
    let mut items = Vec::new();
    let mut length = 0;
    for raw in checked {
        let item = clean(raw.as_str().unwrap_or("")).split_whitespace().collect::<Vec<_>>().join(" ");
        if item.is_empty() {
            continue;
        }
        if length + js_len(&item) > 1500 {
            items.push(format!("\u{2026}and {} more", checked.len() - items.len()));
            break;
        }
        length += js_len(&item);
        items.push(item);
    }
    items
}

/// The review GitHub receives: inline comments on changed lines, the rest in
/// the body, and the proof. Port of `renderReview` in review/review.mjs.
/// `check_url` replaces the checker link in the receipt line (the hosted App's
/// link carries the receipt's location and the subject's salt in its fragment).
pub fn render_review(review: &Value, proof: &[(String, String)], receipt_sha256: &str, run_url: Option<&str>, check_url: Option<&str>, lines: &NewLines) -> Value {
    let spec = spec();
    let text = |k: &str| spec[k].as_str().unwrap_or("").to_string();
    let field = |f: &Value, k: &str| clean(f[k].as_str().unwrap_or(""));
    let checker = text("checker_url");
    let check_link = check_url.map(String::from).unwrap_or_else(|| checker.clone());
    let heading = |f: &Value| format!("**{}, {}: {}**", field(f, "pass"), field(f, "severity"), field(f, "title"));
    let all = review["findings"].as_array().cloned().unwrap_or_default();
    // Findings marked as this reviewer's own earlier ones, still open, are counted, not posted again.
    let findings: Vec<&Value> = all.iter().filter(|f| !truthy(&f["earlier"])).collect();
    let still_open = all.len() - findings.len();
    let placed: Vec<(&Value, Option<Placed>)> = findings.iter().map(|f| (*f, place(f, lines))).collect();

    let mut counts: Vec<(String, usize)> = Vec::new();
    for f in &findings {
        let key = format!("{}, {}", f["pass"].as_str().unwrap_or(""), f["severity"].as_str().unwrap_or(""));
        match counts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => counts.push((key, 1)),
        }
    }
    let mut tally = vec![if !counts.is_empty() {
        counts.iter().map(|(k, n)| format!("{}: {n}", clean(k))).collect::<Vec<_>>().join(" · ")
    } else if still_open > 0 {
        "no new findings".into()
    } else {
        "no findings".into()
    }];
    if still_open > 0 {
        tally.push(format!("{still_open} still open"));
    }

    let dropped = review["dropped"].as_u64().unwrap_or(0);
    let verification = match review["verification"].as_str() {
        Some("verified") if dropped > 0 => text("dropped_note").replacen("{dropped}", &if dropped == 1 { "1 finding".to_string() } else { format!("{dropped} findings") }, 1),
        Some("verified") => text("verified_note"),
        Some("unverified") => text("unverified_note"),
        _ => String::new(),
    };
    let checked = checked_items(review["checked"].as_array().map(Vec::as_slice).unwrap_or(&[]));

    let mut details = vec!["<details><summary>What was verified</summary>".to_string(), String::new()];
    details.extend(proof.iter().map(|(claim, text)| format!("- **{claim}:** {text}")));
    details.push(format!(
        "- **Receipt:** sha256 `{receipt_sha256}`{}. Anyone can [check it]({check_link}).",
        run_url.map(|u| format!(" in the [run's artifacts]({u})")).unwrap_or_default()
    ));
    details.extend([String::new(), "</details>".to_string()]);

    let mut parts = vec![format!("**{}** ({})", text("name"), tally.join(" · "))];
    parts.push(clean(review["summary"].as_str().unwrap_or("")));
    if still_open > 0 {
        parts.push(if still_open == 1 { "1 earlier finding is still open, and not posted again.".into() } else { format!("{still_open} earlier findings are still open, and not posted again.") });
    }
    parts.push(verification);
    parts.extend([text("limits_note"), text("feedback_note")]);
    let elsewhere: Vec<&Value> = placed.iter().filter(|(_, at)| at.is_none()).map(|(f, _)| *f).collect();
    if !elsewhere.is_empty() {
        let mut list = vec!["**Not on a changed line**".to_string()];
        list.extend(elsewhere.iter().map(|f| format!("- `{}:{}` {} {}", field(f, "path"), js_number(&f["line"]), heading(f), field(f, "body"))));
        parts.push(list.join("\n"));
    }
    if !checked.is_empty() {
        let mut list = vec![format!("<details><summary>What was traced ({})</summary>", checked.len()), String::new()];
        list.extend(checked.iter().map(|item| format!("- {item}")));
        list.extend([String::new(), "</details>".to_string()]);
        parts.push(list.join("\n"));
    }
    // The hosted App's own proof sentence, linking its receipt; the Action's otherwise.
    match check_url {
        Some(link) => parts.push(text("app_proof_line").replacen("{checker}", link, 1)),
        None => parts.push(text("proof_line").replacen("{checker}", &checker, 1)),
    }
    parts.push(details.join("\n"));
    let body = parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n\n");

    let comments: Vec<Value> = placed
        .iter()
        .filter_map(|(f, at)| at.as_ref().map(|at| (f, at)))
        .map(|(f, at)| {
            let mut comment = serde_json::Map::new();
            comment.insert("path".into(), f["path"].clone());
            if at.end > at.start {
                comment.insert("start_line".into(), json!(at.start));
                comment.insert("start_side".into(), json!("RIGHT"));
            }
            comment.insert("line".into(), json!(at.end));
            comment.insert("side".into(), json!("RIGHT"));
            comment.insert("body".into(), json!(comment_body(f, at.exact, &heading(f))));
            Value::Object(comment)
        })
        .collect();
    json!({ "body": body, "comments": comments })
}

/// One inline finding: its heading and body, the fix in prose, and a one-click
/// suggestion when it replaces exactly the quoted lines.
fn comment_body(f: &Value, exact: bool, heading: &str) -> String {
    let mut parts = vec![heading.to_string(), clean(f["body"].as_str().unwrap_or(""))];
    if let Some(suggestion) = f["suggestion"].as_str().filter(|s| !s.trim().is_empty()) {
        parts.push(format!("**Suggested fix:** {}", clean(suggestion)));
    }
    if let (true, Some(fix)) = (exact, f["fix_code"].as_str()) {
        parts.push(format!("```suggestion\n{}\n```", fix.replace("```", "ˋˋˋ")));
    }
    parts.join("\n\n")
}

/// Whether a review is this reviewer's own: posted by one of its accounts
/// (review.json `authors`) under its heading. A heading alone is something anyone can type.
pub fn is_our_review(review: &Value) -> bool {
    let author = review["user"]["login"].as_str().is_some_and(|login| spec()["authors"].as_array().into_iter().flatten().any(|a| a.as_str() == Some(login)));
    let mut headings = std::iter::once(format!("**{}**", spec()["name"].as_str().unwrap_or(""))).chain(spec()["legacy_headings"].as_array().into_iter().flatten().filter_map(|h| h.as_str().map(String::from)));
    author && review["body"].as_str().is_some_and(|b| headings.any(|h| b.starts_with(h.as_str())))
}

/// The inline findings of this reviewer's own reviews, once each (review.mjs `ownFindings`).
pub fn own_findings(reviews: &[Value], comments: &[Value]) -> Vec<Value> {
    let ours: Vec<u64> = reviews.iter().filter(|r| is_our_review(r)).filter_map(|r| r["id"].as_u64()).collect();
    let mut seen = std::collections::HashSet::new();
    comments
        .iter()
        .filter(|c| c["pull_request_review_id"].as_u64().is_some_and(|id| ours.contains(&id)))
        .map(|c| json!({ "path": c["path"], "body": finding_text(c["body"].as_str().unwrap_or("")) }))
        .filter(|f| seen.insert(format!("{}\n{}", f["path"], f["body"])))
        .collect()
}

/// A posted finding without its fix: what a re-review needs to recognise it.
fn finding_text(body: &str) -> &str {
    let cut = ["\n\n**Suggested fix:**", "\n\n```suggestion"].iter().filter_map(|m| body.find(m)).min();
    cut.map_or(body, |i| &body[..i])
}

/// The same finding, however its line moved: its file and its title, lowercased, punctuation dropped.
pub fn fingerprint(f: &Value) -> String {
    let title = f["title"].as_str().unwrap_or("").to_lowercase();
    let words: Vec<&str> = title.split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit()).filter(|w| !w.is_empty()).collect();
    format!("{}\n{}", f["path"].as_str().unwrap_or(""), words.join(" "))
}

/// Findings from several passes, once each (review.mjs `mergeFindings`): the
/// first one reported is kept, and a later one is the same finding when its
/// comment would sit on the same line (where its quoted code ends, by `lines`,
/// else the line it names), or when its fingerprint matches (its line moved).
pub fn merge_findings(lists: &[Value], lines: &NewLines) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    lists
        .iter()
        .flat_map(|l| l.as_array().cloned().unwrap_or_default())
        .filter(|f| {
            let anchor = place(f, lines).map_or_else(|| js_number(&f["line"]), |at| at.end.to_string());
            let keys = [fingerprint(f), format!("{}:{anchor}", f["path"].as_str().unwrap_or(""))];
            if keys.iter().any(|k| seen.contains(k)) {
                return false;
            }
            seen.extend(keys);
            true
        })
        .collect()
}

/// The verify pass's prompt: the review's own prompt, then the candidate findings, numbered.
pub fn verify_prompt(prompt: &str, findings: &[Value]) -> String {
    let numbered: Vec<Value> = findings
        .iter()
        .enumerate()
        .map(|(index, f)| {
            let mut entry = serde_json::Map::new();
            entry.insert("index".into(), json!(index));
            for key in ["path", "line", "category", "title", "body", "existing_code"] {
                if !f[key].is_null() {
                    entry.insert(key.into(), if key == "line" { serde_json::from_str(&js_number(&f[key])).unwrap_or(f[key].clone()) } else { f[key].clone() });
                }
            }
            Value::Object(entry)
        })
        .collect();
    format!("{prompt}\n\n## Findings to check\n\n```json\n{}\n```", serde_json::to_string_pretty(&numbered).unwrap_or_default())
}

/// Applies the verify pass's verdicts (review.mjs `applyVerdicts`). A finding
/// without a verdict is kept; protected categories are removed only as
/// duplicates, and a duplicate only while the finding it repeats stays.
pub fn apply_verdicts(findings: &[Value], verdicts: &[Value]) -> Vec<Value> {
    static DUPLICATE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    let duplicate = DUPLICATE.get_or_init(|| fancy_regex::Regex::new(r"(?i)^duplicate of #?(\d+)").expect("valid"));
    let protected = |f: &Value| spec()["protected_categories"].as_array().into_iter().flatten().any(|c| c.as_str().is_some() && c.as_str() == f["category"].as_str());
    let mut rejected = std::collections::HashSet::new();
    for v in verdicts {
        let Some(index) = v["index"].as_u64().map(|i| i as usize) else { continue };
        if v["keep"] != false || rejected.contains(&index) || index >= findings.len() {
            continue;
        }
        let target = duplicate.captures(v["reason"].as_str().unwrap_or("")).ok().flatten().and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<usize>().ok());
        match target {
            Some(target) => {
                if target != index && target < findings.len() && !rejected.contains(&target) {
                    rejected.insert(index);
                }
            }
            None if !protected(&findings[index]) => {
                rejected.insert(index);
            }
            None => {}
        }
    }
    findings.iter().enumerate().filter(|(i, _)| !rejected.contains(i)).map(|(_, f)| f.clone()).collect()
}
