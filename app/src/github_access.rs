//! GitHub's effective permission controls access; custom role names are labels.
use serde_json::Value;

pub fn may_review(access: &Value) -> bool {
    matches!(access["permission"].as_str(), Some("admin" | "write"))
}

#[cfg(test)]
mod tests {
    use super::may_review;
    use serde_json::json;

    #[test]
    fn effective_write_access_allows_standard_and_custom_roles() {
        for access in [
            json!({"permission": "admin", "role_name": "admin"}),
            json!({"permission": "write", "role_name": "maintain"}),
            json!({"permission": "write", "role_name": "write"}),
            json!({"permission": "write", "role_name": "review-maintainer"}),
            json!({"permission": "admin", "role_name": "custom-admin"}),
            json!({"permission": "write"}),
        ] {
            assert!(may_review(&access), "{access}");
        }
    }

    #[test]
    fn read_only_missing_and_unknown_permissions_fail_closed() {
        for access in [
            json!({"permission": "read", "role_name": "read"}),
            json!({"permission": "read", "role_name": "custom-triage"}),
            json!({"permission": "none", "role_name": "none"}),
            json!({"permission": "unexpected", "role_name": "write"}),
            json!({"role_name": "admin"}),
            json!({"permission": null, "role_name": "admin"}),
            json!(null),
        ] {
            assert!(!may_review(&access), "{access}");
        }
    }
}
