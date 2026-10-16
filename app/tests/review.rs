//! The golden case test/review.test.mjs also checks: the hosted App's review
//! text must be the Action's, byte for byte.
use private_investigator::review::{check_submission, commentable_lines, merge_findings, own_findings, system_prompt, user_prompt};
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
        assert_eq!(merge_findings(case["lists"].as_array().unwrap()), *case["expected"].as_array().unwrap(), "{}", case["lists"]);
    }
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
    let commentable: Vec<String> = c["commentable"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    for r in c["renders"].as_array().unwrap() {
        let summary = |tcb: &str, signer: &str, compose: &str| Summary { tcb: tcb.into(), advisories: vec![], signer: signer.into(), compose_hash: compose.into() };
        let model = summary(r["tcb"].as_str().unwrap(), &format!("{:0<64}", "5a02"), &format!("{:0<64}", "945b"));
        let gateway = summary("OutOfDate", "", "");
        let proof = proven_claims("z-ai/glm-5.3-flash", &model, &gateway, r["turns"].as_u64().unwrap() as usize);
        let rendered = render_review(&r["review"], &proof, &"ab".repeat(32), r["run_url"].as_str(), None, &commentable);
        assert_eq!(rendered["body"], r["expected"]["body"]);
        assert_eq!(rendered["comments"], r["expected"]["comments"]);
    }
}

#[test]
fn quality_policy_matches_the_actions_shared_cases() {
    use private_investigator::review::{check_consolidation, finalize_review};
    let text = std::fs::read_to_string(format!("{}/../test/fixtures/review-quality.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let cases: Value = serde_json::from_str(&text).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let candidates = case["candidates"].as_array().unwrap();
        assert_eq!(check_consolidation(&case["decision"], candidates), None);
        assert_eq!(finalize_review(candidates, &case["decision"]).unwrap(), case["expected"]);
    }
}

#[test]
fn invalid_labels_and_excess_new_nits_need_model_repair() {
    use serde_json::json;
    let f = json!({ "path": "a", "line": 1, "pass": "Bugs", "severity": "Nit", "body": "Issue" });
    for (key, value) in [("pass", json!("Nit")), ("severity", json!("Critical")), ("earlier", json!("true"))] {
        let mut invalid = f.clone(); invalid[key] = value;
        assert!(check_submission(&json!({ "summary": "Checked", "findings": [invalid] })).is_some());
    }
    assert_eq!(check_submission(&json!({ "summary": "Checked", "findings": vec![f.clone(); 6] })), Some("submit at most 5 new Nit findings".into()));
    let mut important = f.clone(); important["severity"] = json!("Important");
    assert_eq!(check_submission(&json!({ "summary": "Checked", "findings": vec![important; 6] })), None);
    let mut earlier = f; earlier["earlier"] = json!(true);
    assert_eq!(check_submission(&json!({ "summary": "Checked", "findings": vec![earlier; 6] })), None);
}

#[test]
fn groups_must_be_a_complete_partition_without_crossing_files_or_earlier_status() {
    use private_investigator::review::{check_consolidation, finalize_review};
    use serde_json::json;
    let f = json!({ "path": "a", "line": 1, "pass": "Bugs", "severity": "Nit", "body": "Issue" });
    for groups in [json!([]), json!([[0, 0]]), json!([[1]]), json!([[-1]]), json!([[0.5]]), json!([[]])] {
        assert!(check_consolidation(&json!({ "summary": "Checked", "groups": groups }), &[f.clone()]).is_some());
    }
    for change in [json!({ "path": "b" }), json!({ "earlier": true })] {
        let mut other = f.clone();
        for (k, v) in change.as_object().unwrap() { other[k] = v.clone(); }
        assert!(check_consolidation(&json!({ "summary": "Checked", "groups": [[0,1]] }), &[f.clone(), other]).is_some());
    }
    let mut important = f.clone(); important["severity"] = json!("Important");
    let result = finalize_review(&[f, important.clone()], &json!({ "summary": "Checked", "groups": [[0,1]] })).unwrap();
    assert_eq!(result["findings"], json!([important]));
}

#[test]
fn verified_history_resolves_conflicting_flags_without_hiding_new_findings() {
    use private_investigator::review::{verified_earlier, finalize_review};
    use serde_json::json;
    let f = json!({ "path": "a", "line": 1, "pass": "Bugs", "severity": "Important", "body": "Known issue", "earlier": false });
    let mut repeated = f.clone(); repeated["earlier"] = json!(true);
    let mut new = repeated.clone(); new["body"] = json!("Different new issue");
    let normalized = verified_earlier(&json!([f, repeated, new]), &[json!({"path":"a", "body":"**Bugs, Important:** Known issue"})]);
    let candidates = merge_findings(&[normalized]);
    assert_eq!(candidates.len(), 2);
    let review = finalize_review(&candidates, &json!({"summary":"Checked", "groups":[[0],[1]]})).unwrap();
    assert_eq!(review["findings"].as_array().unwrap().iter().filter(|f| f["earlier"] != true).count(), 1);
    assert_eq!(review["findings"][1]["body"], "Different new issue");
}
