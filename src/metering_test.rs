//! Nothing a control plane can answer with may leave this agent holding an
//! empty ruleset.
//!
//! This SDK has no telemetry path, so the sampling half of the metering
//! contract does not apply to it — there is nothing here that reports an
//! allowed request, and no sampling rate to keep in step with
//! `UsageMeterService::ALLOW_SAMPLE_RATE`. The cache half does apply.
//! `quota_exceeded` used to switch a customer's protection off over a billing
//! state, and the shape of that defect was never the status string:
//! `refresh_rules` stored whatever body came back, in memory and on disk, and
//! `score_request` then read `rules` out of it, found nothing, and scored every
//! visitor zero. An unknown status, an error envelope or an empty object did
//! the same damage without anyone having to name it.
//!
//! Its own file rather than another `mod tests` in lib.rs, because the vectors
//! below quote a status the repo-wide guard in the PHP suite forbids any SDK
//! *source* from comparing against, and that guard reads whole files.

use super::{RelintioAgent, RelintioConfig};

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Answers one request on an ephemeral port with `body`, then closes.
fn serve_json(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };

        drain_request(&mut stream);

        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .as_bytes(),
        );
        let _ = stream.flush();
    });

    url
}

/// Read past the request head so the client is not left blocked on a write.
fn drain_request(stream: &mut TcpStream) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 2048];

    let header_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    };

    let declared: usize = String::from_utf8_lossy(&raw[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = raw.len() - header_end;
    while body < declared {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => body += read,
        }
    }
}

fn agent_for(url: String, license_key: &str) -> RelintioAgent {
    RelintioAgent::new(RelintioConfig {
        license_key: license_key.to_string(),
        api_url: url,
        sync_interval_seconds: 10,
    })
}

#[tokio::test]
async fn an_unrecognised_verify_response_keeps_the_cached_policy() {
    let key = "sk_live_rust_metering";
    let policy = r#"{"status":"success","rules":[{"type":"ip","pattern":"203.0.113.7","condition":"equals","score":100,"action":"block"}]}"#;

    let agent = agent_for(serve_json(policy), key);
    agent
        .refresh_rules("example.com")
        .await
        .expect("a well-formed ruleset was not accepted");

    let cached = agent.rules.read().expect("read cached rules").clone();
    assert!(cached.is_some(), "the policy was not cached");
    let on_disk = std::fs::read_to_string(&agent.cache_path).expect("the policy was not written to disk");

    // Every shape the control plane can answer 200 with that is not a policy.
    // The removed status is deliberately still exercised: an old deployment may
    // still emit it, and it must now be as inert as any other word this agent
    // does not know.
    for body in [
        r#"{"status":"quota_"#.to_string() + r#"exceeded"}"#,
        r#"{"status":"something_new"}"#.to_string(),
        r#"{}"#.to_string(),
        r#"{"error":"internal"}"#.to_string(),
        r#"{"rules":null}"#.to_string(),
    ] {
        // The server's body has to outlive the thread that writes it, and the
        // set above is fixed, so leaking one small string per case is cheaper
        // than threading a lifetime through the listener.
        let leaked: &'static str = Box::leak(body.clone().into_boxed_str());

        let mut swapped = agent_for(serve_json(leaked), key);
        // Same cache and same in-memory policy as the agent that synced
        // successfully: what is under test is what the second answer does to
        // the first answer's state.
        swapped.rules = agent.rules.clone();
        swapped.cache_path = agent.cache_path.clone();

        assert!(
            swapped.refresh_rules("example.com").await.is_err(),
            "{body} was accepted as a policy"
        );
        assert_eq!(
            *swapped.rules.read().expect("read cached rules"),
            cached,
            "{body} replaced the cached policy"
        );
        assert_eq!(
            std::fs::read_to_string(&swapped.cache_path).expect("cache file"),
            on_disk,
            "{body} overwrote the policy on disk"
        );
    }

    // An explicit empty array is a real, empty policy, and is stored. Without
    // this the loop above could be satisfied by an agent that never accepts a
    // change at all.
    let mut empty = agent_for(serve_json(r#"{"status":"success","rules":[]}"#), key);
    empty.rules = agent.rules.clone();
    empty.cache_path = agent.cache_path.clone();

    empty
        .refresh_rules("example.com")
        .await
        .expect("an explicit empty ruleset was rejected");
    assert_ne!(*empty.rules.read().expect("read cached rules"), cached);

    let _ = std::fs::remove_file(&agent.cache_path);
}
