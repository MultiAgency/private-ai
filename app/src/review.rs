//! The review's text and its checks, shared with the Action: the prompts,
//! schema and limits come from `review/review.json`, and the code here matches
//! `review/review.mjs` exactly (pinned by `test/fixtures/review-case.json`).
use serde_json::Value;
use std::sync::OnceLock;

/// `review/review.json`, compiled in.
pub fn spec() -> &'static Value {
    static SPEC: OnceLock<Value> = OnceLock::new();
    SPEC.get_or_init(|| serde_json::from_str(include_str!("../../review/review.json")).expect("review.json is valid"))
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
            .map(|f| format!("- `{}`: {}", f["path"].as_str().unwrap_or(""), f["body"].as_str().unwrap_or("")))
            .collect();
        prompt.push_str(&format!("\n\n## Your earlier findings on this pull request\n\n{}", list.join("\n")));
    }
    prompt
}

/// "path:line" for every line a review comment may sit on: added and context lines of the new file.
pub fn commentable_lines(files: &[Value]) -> Vec<String> {
    let mut lines = std::collections::BTreeSet::new();
    for file in files {
        let name = file["filename"].as_str().unwrap_or("");
        let mut line: u64 = 0;
        for row in file["patch"].as_str().unwrap_or("").split('\n') {
            if let Some(start) = hunk_start(row) {
                line = start;
            } else if row.starts_with('+') || row.starts_with(' ') {
                lines.insert(format!("{name}:{line}"));
                line += 1;
            }
        }
    }
    lines.into_iter().collect()
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
    let bad = findings.iter().position(|f| {
        !f["path"].is_string() || !is_integer(&f["line"]) || !["pass", "severity", "body"].iter().all(|k| f[*k].as_str().is_some_and(|s| !s.is_empty()))
    })?;
    let keys = findings[bad].as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(", ")).filter(|k| !k.is_empty());
    Some(format!(
        "finding {} needs path (string), line (integer), pass, severity and body; it has {}",
        bad + 1,
        keys.as_deref().unwrap_or("nothing")
    ))
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

/// The review GitHub receives: inline comments on changed lines, the rest in
/// the body, and the proof. Port of `renderReview` in review/review.mjs.
/// `check_url` replaces the checker link in the receipt line (the hosted App's
/// link carries the receipt's location and the subject's salt in its fragment).
pub fn render_review(review: &Value, proof: &[(String, String)], receipt_sha256: &str, run_url: Option<&str>, check_url: Option<&str>, commentable: &[String]) -> Value {
    let spec = spec();
    let text = |k: &str| spec[k].as_str().unwrap_or("").to_string();
    let checker = text("checker_url");
    let check_link = check_url.map(String::from).unwrap_or_else(|| checker.clone());
    let label = |f: &Value| format!("**{}, {}:**", f["pass"].as_str().unwrap_or(""), f["severity"].as_str().unwrap_or(""));
    let at = |f: &Value| format!("{}:{}", f["path"].as_str().unwrap_or(""), js_number(&f["line"]));
    let all = review["findings"].as_array().cloned().unwrap_or_default();
    // Findings marked as this reviewer's own earlier ones, still open, are counted, not posted again.
    let findings: Vec<&Value> = all.iter().filter(|f| !truthy(&f["earlier"])).collect();
    let still_open = all.len() - findings.len();
    let (inline, elsewhere): (Vec<&Value>, Vec<&Value>) = findings.iter().partition(|f| commentable.contains(&at(f)));

    let mut counts: Vec<(String, usize)> = Vec::new();
    for f in &findings {
        let key = format!("{}, {}", f["pass"].as_str().unwrap_or(""), f["severity"].as_str().unwrap_or(""));
        match counts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => counts.push((key, 1)),
        }
    }
    let mut tally = vec![if !counts.is_empty() {
        counts.iter().map(|(k, n)| format!("{k}: {n}")).collect::<Vec<_>>().join(" · ")
    } else if still_open > 0 {
        "no new findings".into()
    } else {
        "no findings".into()
    }];
    if still_open > 0 {
        tally.push(format!("{still_open} still open"));
    }

    let mut details = vec!["<details><summary>What was verified</summary>".to_string(), String::new()];
    details.extend(proof.iter().map(|(claim, text)| format!("- **{claim}:** {text}")));
    details.push(format!(
        "- **Receipt:** sha256 `{receipt_sha256}`{}. Anyone can [check it]({check_link}).",
        run_url.map(|u| format!(" in the [run's artifacts]({u})")).unwrap_or_default()
    ));
    details.extend([String::new(), "</details>".to_string()]);

    let mut parts = vec![format!("**{}** ({})", text("name"), tally.join(" · "))];
    parts.push(review["summary"].as_str().unwrap_or("").to_string());
    if still_open > 0 {
        parts.push(if still_open == 1 { "1 earlier finding is still open, and not posted again.".into() } else { format!("{still_open} earlier findings are still open, and not posted again.") });
    }
    parts.extend([text("limits_note"), text("feedback_note")]);
    if !elsewhere.is_empty() {
        let mut list = vec!["**Not on a changed line**".to_string()];
        list.extend(elsewhere.iter().map(|f| format!("- `{}` {} {}", at(f), label(f), f["body"].as_str().unwrap_or(""))));
        parts.push(list.join("\n"));
    }
    // The hosted App's own proof sentence, linking its receipt; the Action's otherwise.
    match check_url {
        Some(link) => parts.push(text("app_proof_line").replacen("{checker}", link, 1)),
        None => parts.push(text("proof_line").replacen("{checker}", &checker, 1)),
    }
    parts.push(details.join("\n"));
    let body = parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n\n");

    let comments: Vec<Value> = inline
        .iter()
        .map(|f| serde_json::json!({ "path": f["path"], "line": f["line"].as_f64().map(|l| l as i64), "side": "RIGHT", "body": format!("{} {}", label(f), f["body"].as_str().unwrap_or("")) }))
        .collect();
    serde_json::json!({ "body": body, "comments": comments })
}

/// Findings from several passes, keeping the first one reported for each line.
pub fn merge_findings(lists: &[Value]) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    lists.iter().flat_map(|l| l.as_array().cloned().unwrap_or_default()).filter(|f| seen.insert(format!("{}:{}", f["path"].as_str().unwrap_or(""), js_number(&f["line"])))).collect()
}
