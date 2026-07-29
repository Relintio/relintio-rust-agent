//! Evaluation of one synced rule against one request.
//!
//! The semantics are `contracts/rule-conditions-v1.json`, which this crate's
//! own suite asserts vector by vector. Two of them were wrong here: `regex` was
//! accepted and then substring-matched, so a rule authored as `^/admin$`
//! matched `/administrator`; and anything that was not `equals` fell through to
//! the substring branch, so an unrecognised condition matched rather than
//! failing closed.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use regex::Regex;
use serde_json::Value;

/// The request as the rule matcher sees it.
pub struct RequestFacts<'a> {
    pub ip: &'a str,
    pub path: &'a str,
    pub user_agent: &'a str,
    pub headers: &'a HashMap<String, String>,
}

/// True when the rule applies to this request.
///
/// An unrecognised type or condition never matches. That is deliberate: a rule
/// that quietly means something other than what its author wrote is worse than
/// one that does nothing.
pub fn rule_matches(rule: &Value, facts: &RequestFacts) -> bool {
    let pattern = rule.get("pattern").and_then(Value::as_str).unwrap_or("");
    let condition = rule.get("condition").and_then(Value::as_str).unwrap_or("");

    // Checked before the type, or the presence form of a header rule would
    // match on a condition this agent cannot evaluate.
    if !matches!(condition, "equals" | "contains" | "regex") {
        return false;
    }

    match rule.get("type").and_then(Value::as_str).unwrap_or("") {
        "ip" => match_value(facts.ip, pattern, condition),
        "user_agent" => match_value(facts.user_agent, pattern, condition),
        "path" => match_value(facts.path, pattern, condition),
        "header" => match_header(facts.headers, pattern, condition),
        _ => false,
    }
}

/// The two shapes a header pattern takes: a bare name tests presence with a
/// non-empty value, and `Name: value` tests the named header against the value.
/// Whitespace around the colon is not significant.
fn match_header(headers: &HashMap<String, String>, pattern: &str, condition: &str) -> bool {
    let (name, value) = match pattern.split_once(':') {
        Some((name, value)) => (name.trim(), value.trim()),
        None => (pattern.trim(), ""),
    };
    if name.is_empty() {
        return false;
    }

    let present = header_value(headers, name);

    // An empty header is not a signal.
    if value.is_empty() {
        return !present.is_empty();
    }

    match_value(present, value, condition)
}

/// Header names are case-insensitive on the wire, so they are matched that way
/// here rather than relying on whichever casing the adapter collected.
fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> &'a str {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .unwrap_or("")
}

/// `equals` and `contains` both fold case — an IPv6 address carries hex letters
/// that runtimes render in different cases, and the same dashboard rule has to
/// mean the same thing in all of them.
fn match_value(candidate: &str, pattern: &str, condition: &str) -> bool {
    match condition {
        "equals" => candidate.eq_ignore_ascii_case(pattern),
        "contains" => candidate.to_lowercase().contains(&pattern.to_lowercase()),
        "regex" => rule_regex(pattern).is_some_and(|expression| expression.is_match(candidate)),
        _ => false,
    }
}

/// Compile a rule pattern once and keep it.
///
/// The key space is the set of patterns the control plane has sent, bounded by
/// the customer's rule list; the cap is there so a pathological rule set cannot
/// grow it without limit. A pattern that does not compile is cached as a miss:
/// it never matches, and it is not recompiled on every request to find that out
/// again.
const REGEX_CACHE_LIMIT: usize = 256;

fn rule_regex(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();

    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(cached) = cache.get(pattern) {
        return cached.clone();
    }

    if cache.len() >= REGEX_CACHE_LIMIT {
        cache.clear();
    }

    let compiled = Regex::new(pattern).ok();
    cache.insert(pattern.to_string(), compiled.clone());

    compiled
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    /// Conformance against contracts/rule-conditions-v1.json.
    ///
    /// The vectors are shared by every SDK that evaluates synced rules. A
    /// failure here means a rule an operator authored in the dashboard means
    /// something different in this runtime than it does in the next one — which
    /// is how a `regex` rule ends up matched as a substring.
    fn vectors() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/rule-conditions-v1.json");

        serde_json::from_str(&fs::read_to_string(path).expect("vectors present")).expect("vectors parse")
    }

    /// This SDK evaluates `regex` conditions with the `regex` crate, so no
    /// vector is skipped. The contract permits an SDK to skip the vectors
    /// marked `skip_if_unsupported` — never to approximate them with a
    /// substring match — and a skip taken here is printed rather than passing
    /// quietly.
    const REGEX_CONDITION_SUPPORTED: bool = true;

    #[test]
    fn matching_follows_the_shared_vectors() {
        let v = vectors();
        let cases = v["vectors"].as_array().expect("vectors is an array");
        assert!(!cases.is_empty());

        let mut failures = Vec::new();

        for case in cases {
            let name = case["name"].as_str().unwrap_or("<unnamed>");

            if case["skip_if_unsupported"].as_bool().unwrap_or(false) && !REGEX_CONDITION_SUPPORTED {
                println!(
                    "SKIP {name}: this SDK does not implement the {} condition",
                    case["rule"]["condition"].as_str().unwrap_or("")
                );
                continue;
            }

            let request = &case["request"];
            let headers: HashMap<String, String> = request["headers"]
                .as_object()
                .map(|map| {
                    map.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let facts = RequestFacts {
                ip: request["ip"].as_str().unwrap_or(""),
                path: request["path"].as_str().unwrap_or(""),
                user_agent: request["user_agent"].as_str().unwrap_or(""),
                headers: &headers,
            };

            let got = rule_matches(&case["rule"], &facts);
            let want = case["matches"].as_bool().expect("every vector states its expectation");

            if got != want {
                failures.push(format!("{name}: matched = {got}, want {want}"));
            }
        }

        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The vectors carry no unknown-condition case for the `header` type, and
    /// that is the one shape where failing closed is not free: presence does not
    /// consult the pattern as a value, so without a guard a `starts_with` header
    /// rule would match on the strength of the header existing.
    #[test]
    fn an_unknown_condition_never_matches_a_header_rule() {
        let headers = HashMap::from([("x-scanner".to_string(), "nuclei".to_string())]);
        let facts = RequestFacts { ip: "", path: "", user_agent: "", headers: &headers };

        assert!(!rule_matches(
            &serde_json::json!({"type": "header", "pattern": "X-Scanner", "condition": "starts_with"}),
            &facts
        ));
        assert!(rule_matches(
            &serde_json::json!({"type": "header", "pattern": "X-Scanner", "condition": "contains"}),
            &facts
        ));
    }

    /// A rule that arrives with no condition at all is a rule with an unknown
    /// condition, not one that quietly means `contains`.
    #[test]
    fn a_rule_with_no_condition_never_matches() {
        let headers = HashMap::new();
        let facts = RequestFacts { ip: "", path: "/wp-admin", user_agent: "", headers: &headers };

        assert!(!rule_matches(&serde_json::json!({"type": "path", "pattern": "/wp-admin"}), &facts));
    }
}
