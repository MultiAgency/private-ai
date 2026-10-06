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
