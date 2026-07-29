<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/relintio-logo-dark.svg">
    <img src="./assets/relintio-logo-light.svg" alt="Relintio" width="260">
  </picture>

  <h1>relintio-agent</h1>

  <p>
    <a href="https://crates.io/crates/relintio-agent"><img alt="crates.io" src="https://img.shields.io/crates/v/relintio-agent?color=efd420"></a>
    <a href="https://docs.rs/relintio-agent"><img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-relintio--agent-efd420"></a>
    <a href="./Cargo.toml"><img alt="license" src="https://img.shields.io/badge/license-MIT-efd420"></a>
  </p>

  <p><strong>The Relintio agent for Rust.</strong></p>
</div>

---

An in-process agent that scores every request before your handlers see it. It synchronizes the rule set from the control plane, mirrors it to the OS temp directory so a restart is not a cold start, and decides — allow, delay, challenge, decoy, block — from memory. Passports are verified offline with the licence key alone. `middleware::from_fn` for Axum, a `Transform` for Actix-web. No proxy, no DNS change, no sidecar.

```rust
use std::sync::Arc;

use axum::{middleware, routing::get, Router};
use relintio_agent::middleware::axum::relintio_middleware;
use relintio_agent::{RelintioAgent, RelintioConfig};

#[tokio::main]
async fn main() {
    let agent = Arc::new(RelintioAgent::new(RelintioConfig {
        license_key: std::env::var("UP_LICENSE_KEY").expect("UP_LICENSE_KEY"),
        api_url: "https://api.relintio.com/v1".to_string(),
        sync_interval_seconds: 10,
    }));

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(middleware::from_fn(move |req, next| {
            relintio_middleware(agent.clone(), req, next)
        }));

    axum::Server::bind(&([0, 0, 0, 0], 3000).into())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

## Installation

```toml
[dependencies]
relintio-agent = "0.1.2"
```

Both framework integrations are on by default. Turn off the one you do not use — it is a whole web framework of compile time:

```toml
[dependencies]
relintio-agent = { version = "0.1.2", default-features = false, features = ["axum"] }
```

| Feature | Default | Enables |
| --- | --- | --- |
| `axum` | on | `middleware::axum::relintio_middleware`, against **axum 0.6** |
| `actix-web` | on | `middleware::actix::RelintioActixMiddleware`, against **actix-web 4** |

The axum pin matters. `relintio_middleware` takes `Next<Body>`, which axum 0.7 removed, and the sample above uses `axum::Server` rather than `axum::serve` for the same reason. On axum 0.7 or newer this does not compile, and the error points at the middleware signature rather than at the version.

## Registration

Register the layer **outside** your routes, as in the sample. A layer applied to a single route protects that route only. Actix has no equivalent ordering trap: `wrap` on the `App` is app-wide and covers every service on it, registered before or after.

```rust
App::new()
    .wrap(RelintioActixMiddleware::new(agent.clone()))
    .service(hello)
```

`RelintioAgent::new` spawns nothing. There is no background task and no `start` call: the agent syncs lazily, inside `evaluate`, once the next-sync deadline has passed. An `AtomicBool` compare-exchange means only one request performs the fetch while the others score against the rules already in memory — but that one request awaits the round trip, so the first request after boot, and one request per sync interval after that, pays the sync latency.

## Configuration

| Field | Type | Meaning |
| --- | --- | --- |
| `license_key` | `String` | Keys every signature and every passport. **Secret** — see below. |
| `api_url` | `String` | Required; there is no default. `https://api.relintio.com/v1`. A trailing `/` is trimmed per call. |
| `sync_interval_seconds` | `u64` | Target cadence. Floored at 10; backoff and jitter apply on top. |

The licence key is a **secret**. It signs outbound requests and mints passports, so anything holding it can forge both. Keep it in the environment, never in a repository, and never in code that reaches a browser — that is what publishable keys are for, and those belong to the React and Shopify SDKs, not this one.

## What happens on a request

The passport is checked first. `?up_token` is exchanged for a cookie, then a valid `relintio_passport` cookie short-circuits straight to the handler — a visitor who has already proved themselves is not re-scored on every page. Only then does `evaluate` run.

Signals are additive and the total is clamped to 100.

| Signal | Weight | Fires when |
| --- | --- | --- |
| Empty user agent | +40 | No `User-Agent` at all |
| Bot keyword | +35 | UA contains `googlebot`, `bingbot`, `yandex`, `baiduspider`, `curl`, `wget`, `httpclient` or `python-urllib` |
| Rate burst | +35 | Token bucket exhausted |
| Headless keyword | +25 | UA contains `puppeteer`, `playwright`, `phantomjs`, `headlesschrome` or `selenium` |
| POST without referer | +20 | `POST` and no `Referer` |
| No accept header | +15 | No `Accept` |

The headless and bot lists are checked independently, so a user agent matching both scores +60. An empty user agent skips both — it has already earned +40 and there is nothing left to match against. Per-licence rules from the control plane add their own scores on top.

`crate::rules::rule_matches` decides those, against the semantics in `contracts/rule-conditions-v1.json`, which `rules.rs` asserts vector by vector. The types are `ip`, `user_agent`, `path` and `header`; a header pattern with no colon tests that the header is present with a non-empty value, and `Name: value` tests the named header against the value, with whitespace around the colon trimmed and the name matched case-insensitively. The conditions are `equals` (exact, case-insensitive), `contains` (substring, case-insensitive) and `regex`, compiled with the `regex` crate once per pattern and cached; a pattern that does not compile never matches and never panics.

An unrecognised type or condition never matches. That is deliberate: a rule that quietly means something other than what its author wrote is worse than one that does nothing. `regex` used to fall through to the substring branch — so a rule authored as `^/admin$` matched `/administrator` — and so did every unrecognised condition, and `header` had no branch at all.

| Tier | Score | Response |
| --- | --- | --- |
| ALLOW | 0–39 | Passes through |
| SLOW | 40–59 | `tokio::time::sleep` for two seconds, then passes through |
| CHALLENGE | 60–74 | `302` to the hosted challenge |
| DECOY | 75–84 | `200` with a maintenance page |
| BLOCK | 85–100 | `403` with a block page |

No single signal reaches BLOCK on its own. A plain `curl` lands at +50 — bot keyword plus a missing `Accept` — which is SLOW, not a block. These thresholds are compile-time constants; the dashboard `sensitivity` setting does not move them in this agent.

### Rate limiting

A per-IP token bucket: 8 tokens per second, 24 in the burst, refilled continuously rather than reset on a boundary. Exhausting it contributes +35 to the score; it does not block on its own. Route multipliers scale both the refill rate and the ceiling:

| Route prefix | Multiplier |
| --- | --- |
| `/assets/` | 2.0 |
| `/api/` | 0.7 |
| `/login`, `/auth` | 0.4 |

The first matching prefix wins. Buckets are keyed by IP alone, so a client moving between `/login` and `/assets/` shares one bucket whose size changes underneath it. Buckets live in process memory and are never swept, so a long-lived process facing a wide address range grows one map entry per IP it has ever seen.

## Passport v2

A visitor who passes the challenge returns with `?up_token=<v2 token>`. Both middlewares verify it, mint a fresh passport with the `ttl` the token asked for — clamped to 300–604800 seconds, because it arrives signed but a bug upstream should not be able to mint a ten-year cookie — set it as the `relintio_passport` cookie, and `302` back to the same path with the token stripped. An invalid `up_token` is a `403 Invalid Token`, not a pass-through: the only way to hold one is to have just passed the challenge.

A token is `v2.<payload>.<signature>`: base64url JSON carrying an absolute expiry and a binding hash, signed with HMAC-SHA256 under the licence key. The binding is `sha256(licenceKey|userAgent|acceptLanguage)` truncated to 16 hex characters, over the **raw** header values — both middlewares take `ua_header` and `lang_header` from the header map verbatim for exactly this reason, because trimming or lowercasing them makes this agent disagree with the challenge server and locks out every visitor rather than a few. Verification is offline; `passport.rs` makes no network call, because the edge has to keep deciding when the control plane does not. The signature is compared with `Mac::verify_slice` and the binding with a hand-rolled comparison that does not return early, both constant time, and `exp` is allowed 60 seconds of skew.

The predecessor was `sha256("verified" + licenceKey)` — one constant string, identical for every visitor of a site. One leaked cookie bypassed the agent entirely until the key was rotated. Anything not beginning `v2.` is rejected outright, so tokens in that form simply challenge again.

**The cookie is set `Path=/`, `Max-Age=<ttl>`, `HttpOnly`, and nothing else.** The protocol asks for `SameSite=Lax` and `Secure` over HTTPS; neither middleware sets them. Until they do, a passport issued over HTTPS can be replayed over plaintext by anyone able to force the downgrade, and it rides cross-site requests. If your ingress can add cookie attributes on the way out, do.

## Request signing

Every outbound call carries:

```
X-Relintio-Timestamp: 1785120000
X-Relintio-Nonce:     <24 hex chars>
X-Relintio-Signature: v1=<64 hex>
```

The signature is `HMAC-SHA256("v1:" + timestamp + ":" + nonce + ":" + sha256(body), licenceKey)`. The server checks the timestamp within ±300 seconds, the nonce unused within 600 seconds per credential, and the signature in constant time — and burns the nonce last, so a forged request cannot consume one the real agent is about to use.

The server's `agent_signature_mode` has three settings. `off` checks nothing. `optional` accepts an absent signature but still rejects a bad one, so corrupting the header cannot be used as a downgrade. `required` rejects unsigned ingest with `401`, and is both the default and the steady state.

All three outbound calls — `/agent/verify`, `/agent/heartbeat` and `/agent/challenge/init` — go through the private `signed_post`, which runs `serde_json::to_vec` **once** and gives that same `Vec<u8>` to both `signing_headers` and `RequestBuilder::body`. This is the part that is easy to get wrong: handing reqwest a `Value` and letting it serialise puts the signature over a byte sequence that never reached the wire, and nothing obliges two `serde_json` passes to agree on spacing or key order. The server hashes what it received, so it rejects everything, with nothing in any log to explain it. An endpoint added around `signed_post` rather than through it does not degrade gracefully; it `401`s, and the edge goes blind.

`challenge_url` is inside the chokepoint on purpose. It is the one signed call sitting on the request path, and an unsigned one there would fail the request that sends a suspicious visitor to the challenge — and an unchallenged visitor is an allowed one.

The tests in `src/lib.rs` assert this against a hand-rolled `TcpListener` on loopback: they take the bytes reqwest actually transmitted and re-derive the signature from *those*, not from the payload object. Recomputing from the object would have passed while a sign-once/send-twice bug was live, which is the one bug worth testing for here.

The nonce is `sha256(nanoseconds || body)` truncated to 24 hex characters rather than random bytes — no RNG dependency, and the server treats a nonce as single-use regardless.

## Challenge disabled

`challenge_enabled` is a policy setting and it is also plan-gated: a licence without the bot challenge has it forced off server-side. Being over a monthly allowance used to do the same, and no longer does — overage warns and bills, and never takes a defence away.

Rather than have each agent read the flag, `/agent/challenge/init` refuses to issue a token when it is off and answers `200` with `{"status": "challenge_disabled", "fallback": "allow"|"block"}`. The `200` is deliberate — this is a policy answer, not an outage, and an agent that treated it as a failure would fail closed on a setting the customer turned off on purpose.

**This agent reads `fallback`.** `challenge_url` returns a three-case outcome rather than an `Option`: a redirect, `Disabled { block }` carrying the customer's fallback, or `Unavailable`. `evaluate` turns `Disabled { block: true }` into `Decision::Block` and `Disabled { block: false }` into `Decision::Allow`. The flag is read as block unless it says `allow`, so a response that omits it blocks rather than passing traffic through. Scores at or above the DECOY and BLOCK thresholds never reach this call; only the 60–74 band is affected.

Do not confuse this with a failed call. `challenge_disabled` is a policy answer carrying what to do instead; a timeout, a refused connection or an unreadable body is `Unavailable`, which has no fallback to honour and becomes `Decision::Block`. No challenge was issued, so nothing was passed, and the score that sent the visitor here still stands — an unreachable token service is not the way in. They are separate arms of the same `match` for exactly that reason, and anything built on top of them must keep them apart.

## Edge cases

**`domain` comes from the `Host` header, which the client controls.** Both middlewares read `Host` first, fall back to the URI authority, and only then to `localhost` — the URI carries an authority for essentially no origin-form HTTP/1.1 traffic, which is why the header is read first. That value is the domain reported on every rule sync and the host the challenge `return_url` is built from, so a request arriving with a forged `Host` reports that name to the control plane and sends the challenged visitor back to it. Reject or normalise the header at your ingress if you cannot trust it.

**The disk cache is plaintext and unauthenticated.** Rules are mirrored to `<temp>/relintio/up_rules_<hash>.json`, where the hash is the first 16 hex characters of the MD5 of the licence key, and reloaded on construction with no integrity check. On a host where another process can write your temp directory, that file is a policy bypass. It is a latency optimisation, not a trust boundary.

**Sync failure fails open.** A failed `refresh_rules` leaves the previous rules in place and backs off by powers of two from `sync_interval_seconds` to a five-minute ceiling, with 80–120% jitter so a fleet restarting together does not synchronize into a thundering herd. A `200` carrying no `rules` array counts as a failure for the same reason: an unknown status, an error envelope or an empty object is not a policy, and applying it as one would empty the cache and leave the site unprotected. That is what `quota_exceeded` used to do deliberately — a billing state switching off a defence — and what any unrecognised answer did by accident. With no rules at all the built-in signals still score, so a cold start is degraded rather than blind.

**Obsidian injection is Axum-only and buffers the response.** On an `Allow` decision with a `text/html` content type, the Axum middleware reads the whole body into memory, splices in the client-side script, and rewrites `Content-Length`. Bodies over 2 MiB are passed through untouched, and the Actix middleware does not inject at all. A streaming or SSE response that declares `text/html` is collected before any of it is sent.

**A poisoned lock does not panic.** Every `RwLock` and `Mutex` here recovers with `unwrap_or_else(|poisoned| poisoned.into_inner())`. A panic inside one critical section degrades that read; it does not take the process down.

## In production

Start in observe mode, watch a day of real traffic, and only then enforce. The dashboard shows what the agent scored and why, so the question to settle before enforcement is whether the traffic you expect is scored the way you expect.

Run at least one deploy with `agent_signature_mode` at `optional` and the adoption page open. It records which credentials are signing and which are not, and that is the only way to know whether flipping to `required` will take part of the fleet dark.

`send_heartbeat` is public and nothing calls it. If you want the dashboard to show this instance as live, drive it from your own `tokio::spawn` loop; it carries a two-second timeout and discards its own result, so it cannot stall or panic a task.

## Links

- [Documentation](https://relintio.com/docs)
- [Quickstart](https://relintio.com/docs/quickstart/rust)
- [API reference](https://relintio.com/docs/api-reference)
- [Licenses](https://relintio.com/licenses)

Security reports go to **support@relintio.com**, not to a public issue.

## License

MIT, as declared in [`Cargo.toml`](./Cargo.toml).
