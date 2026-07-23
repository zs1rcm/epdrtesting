//! ZTAS / EPDR execution test harness.
//!
//! This is a completely benign binary whose only purpose is to be an
//! *unclassified* executable so we can observe how WatchGuard EPDR's
//! Zero-Trust Application Service reacts when it runs.
//!
//! It does nothing malicious: prints a banner, writes a marker file, exits.
//! The embedded BUILD_NONCE guarantees a unique SHA-256 so the cloud has
//! never seen this hash before (i.e. it will be "unknown").

use std::io::Write;

// Unique per-build nonce -> guarantees a novel file hash (unclassified).
// Change this string and rebuild to produce a fresh, unseen binary.
const BUILD_NONCE: &str = "4e9d8ddc338517f907a229548e269e55";

fn main() {
    let banner = format!(
        "==============================================\n\
         ZTAS EXECUTION TEST\n\
         nonce : {nonce}\n\
         pid   : {pid}\n\
         host  : {host}\n\
         If you can read this line, execution was ALLOWED.\n\
         ==============================================",
        nonce = BUILD_NONCE,
        pid = std::process::id(),
        host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
    );
    println!("{banner}");

    // Drop a marker file next to the binary so you can tell it ran even if
    // stdout was not captured (e.g. launched via a service or double-click).
    let marker = format!("/tmp/ztas-test-{BUILD_NONCE}.marker");
    match std::fs::File::create(&marker) {
        Ok(mut f) => {
            let _ = writeln!(f, "ztas-test executed, nonce={BUILD_NONCE}, pid={}", std::process::id());
            println!("marker written: {marker}");
        }
        Err(e) => eprintln!("could not write marker {marker}: {e}"),
    }
}
