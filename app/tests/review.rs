//! The golden case test/review.test.mjs also checks: the hosted App's review
//! text must be the Action's, byte for byte.
use private_investigator::review::{apply_verdicts, check_submission, check_verdicts, clean, commentable_lines, merge_findings, new_lines, own_findings, place, skipped, system_prompt, user_prompt, verify_prompt, Placed};
use serde_json::Value;

#[test]
fn the_golden_case_matches_the_action() {
    let text = std::fs::read_to_string(format!("{}/../test/fixtures/review-case.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let c: Value = serde_json::from_str(&text).unwrap();
    let list = |k: &str| c[k].as_array().unwrap().clone();
    assert_eq!(system_prompt(c["rubric"].as_str().unwrap()), c["system_prompt"].as_str().unwrap());
    assert_eq!(user_prompt(&c["pr"], &list("files"), &list("earlier")), c["user_prompt"].as_str().unwrap());
    let expected: Vec<String> = list("commentable").iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(commentable_lines(&list("files")), expected);
    for case in list("submissions") {
        assert_eq!(check_submission(&case[0]), case[1].as_str().map(String::from), "{}", case[0]);
    }
    let own = &c["own_findings"];
    assert_eq!(own_findings(own["reviews"].as_array().unwrap(), own["comments"].as_array().unwrap()), *own["expected"].as_array().unwrap());
    for case in list("merges") {
        assert_eq!(merge_findings(case["lists"].as_array().unwrap(), &new_lines(&list("files"))), *case["expected"].as_array().unwrap(), "{}", case["lists"]);
    }
    let v = &c["verdicts"];
    assert_eq!(apply_verdicts(v["findings"].as_array().unwrap(), v["verdicts"].as_array().unwrap()), *v["expected"].as_array().unwrap());
    let mut first = v["findings"][0].clone();
    first["line"] = serde_json::json!(3.0);
    first["earlier"] = serde_json::json!(false);
    first["suggestion"] = serde_json::json!("s");
    let second = serde_json::json!({ "path": "b.js", "line": 7, "pass": "Bugs", "severity": "Nit", "title": "No code", "body": "b" });
    assert_eq!(verify_prompt("The prompt.", &[first, second]), c["verify_prompt"].as_str().unwrap());
}

#[test]
fn findings_are_placed_by_the_code_they_quote() {
    let files = vec![serde_json::json!({ "filename": "lib/pay.mjs", "patch": "@@ -10,4 +10,6 @@\n   const total = sum(job);\n-  if (total > 0) send(total);\n+  if (total >= 0) send(total);\n+  log(\"paid\", total);\n+  if (total >= 0) send(total);\n   return total;" })];
    let lines = new_lines(&files);
    let at = |line: f64, code: &str| place(&serde_json::json!({ "path": "lib/pay.mjs", "line": line, "existing_code": code }), &lines);
    assert_eq!(at(3.0, "if (total >= 0) send(total);"), Some(Placed { start: 11, end: 11, exact: true }));
    assert_eq!(at(14.0, "if (total >= 0) send(total);"), Some(Placed { start: 13, end: 13, exact: true }));
    assert_eq!(at(1.0, "\n  if (total >= 0) send(total);\n  log(\"paid\", total);\n"), Some(Placed { start: 11, end: 12, exact: true }));
    assert_eq!(at(12.0, "not in the diff"), Some(Placed { start: 12, end: 12, exact: false }));
    assert_eq!(at(40.0, "not in the diff"), None);
    assert_eq!(place(&serde_json::json!({ "path": "lib/pay.mjs", "line": 12 }), &lines), Some(Placed { start: 12, end: 12, exact: false }));
}

#[test]
fn model_text_cannot_open_a_suggestion_or_a_hidden_comment() {
    assert_eq!(clean("see ```Suggestion\nrm -rf\n``` <!-- state -->"), "see ```text\nrm -rf\n``` &lt;!-- state -->");
}

#[test]
fn lockfiles_and_generated_files_are_skipped() {
    for path in ["package-lock.json", "app/Cargo.lock", "node_modules/x/index.js", "web/dist/app.js", "a.min.js", "x.js.map"] {
        assert!(skipped(path), "{path}");
    }
    for path in ["src/build.rs", "distance.js", "lock.json", "lib/pay.mjs"] {
        assert!(!skipped(path), "{path}");
    }
}

#[test]
fn verdicts_must_name_an_index_and_a_decision() {
    assert_eq!(check_verdicts(&serde_json::json!({ "verdicts": [{ "index": 0, "keep": true, "reason": "" }] })), None);
    assert_eq!(check_verdicts(&serde_json::json!({ "verdicts": [{ "index": "0", "keep": true }] })).as_deref(), Some("verdict 1 needs index (integer) and keep (boolean)"));
    assert_eq!(check_verdicts(&serde_json::json!({})).as_deref(), Some("submit_verdicts needs a verdicts array"));
}

#[test]
fn a_dollar_sign_in_a_rubric_is_kept_as_written() {
    assert!(system_prompt("costs $& and $1").ends_with("costs $& and $1"));
}

#[test]
fn reviews_render_exactly_as_the_action_renders_them() {
    use private_investigator::attest::Summary;
    use private_investigator::receipt::proven_claims;
    use private_investigator::review::render_review;
    let text = std::fs::read_to_string(format!("{}/../test/fixtures/review-case.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let c: Value = serde_json::from_str(&text).unwrap();
    for r in c["renders"].as_array().unwrap() {
        let summary = |tcb: &str, signer: &str, compose: &str| Summary { tcb: tcb.into(), advisories: vec![], signer: signer.into(), compose_hash: compose.into() };
        let model = summary(r["tcb"].as_str().unwrap(), &format!("{:0<64}", "5a02"), &format!("{:0<64}", "945b"));
        let gateway = summary("OutOfDate", "", "");
        let proof = proven_claims("z-ai/glm-5.3-flash", &model, &gateway, r["turns"].as_u64().unwrap() as usize);
        let rendered = render_review(&r["review"], &proof, &"ab".repeat(32), r["run_url"].as_str(), None, &new_lines(c["files"].as_array().unwrap()));
        assert_eq!(rendered["body"], r["expected"]["body"]);
        assert_eq!(rendered["comments"], r["expected"]["comments"]);
    }
}
