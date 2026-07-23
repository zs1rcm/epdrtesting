# EPDR / Zero-Trust Test Suite

Safe validation of WatchGuard EPDR on a hosted Ubuntu 24 endpoint. Uses only
the industry-standard **EICAR** test string and a freshly-built **benign**
binary. Nothing here performs any real malicious action — it just observes how
EPDR reacts and prints a PASS/FAIL report.

## What each test exercises

| # | Test               | EPDR engine                | Expected on protected host |
|---|--------------------|----------------------------|----------------------------|
| 1 | EICAR to disk      | Real-time AV (on-write)    | file quarantined/removed   |
| 2 | EICAR in ZIP       | Archive scanning           | archive quarantined        |
| 3 | EICAR via HTTPS    | Web / on-access AV         | download blocked/removed   |
| 4 | Novel binary exec  | **Zero-Trust attestation** | execution blocked (Lock)   |

`PASS` = EPDR reacted as expected. The **EPDR web console is the source of
truth** — cross-check every result against Security events / Zero-Trust
activity for the host.

## Build (on a build host with Rust)

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Produces a fully static binary at
`target/x86_64-unknown-linux-musl/release/ztas-test` (no glibc dependency, runs
on any x86-64 Linux). To force a fresh, never-before-seen hash, edit
`BUILD_NONCE` in `src/main.rs` and rebuild.

## Deploy to the target

```bash
scp target/x86_64-unknown-linux-musl/release/ztas-test run-suite.sh user@target:/tmp/
ssh user@target 'chmod +x /tmp/ztas-test /tmp/run-suite.sh && /tmp/run-suite.sh /tmp/ztas-test'
```

## Cleanup

```bash
rm -f /tmp/ztas-test /tmp/run-suite.sh /tmp/ztas-test-*.marker
rm -rf /tmp/epdr-test.* /tmp/epdr-test.*/
```

> Authorized testing only. Run this against endpoints you administer.
