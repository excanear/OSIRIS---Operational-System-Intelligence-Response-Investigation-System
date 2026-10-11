//! Seeded osiris-server for the Console Playwright suite. Writes connection
//! details to --out once data is queryable; exits when stdin closes.
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_real_linux_tests::seed;
use osiris_real_linux_tests::stack::{Stack, StackOptions};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let out = arg("--out").expect("--out <file.json>");
    let port: u16 = arg("--port").map(|p| p.parse().unwrap()).unwrap_or(8080);

    let stack = Stack::start(StackOptions {
        api_port: Some(port),
        dev_cors: true,
        ..Default::default()
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Scenarios end ~70 s after base; start them 10 min ago so default time
    // ranges in the Console include them.
    let lines = seed::scenario_lines(now - 600_000_000_000);
    let mut spool = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(stack.spool_path())
        .unwrap();
    spool
        .write_all((lines.join("\n") + "\n").as_bytes())
        .unwrap();
    stack.wait_for("/api/v1/alerts", Duration::from_secs(60), |v| {
        v.as_array().is_some_and(|a| !a.is_empty())
    });
    std::fs::write(
        &out,
        serde_json::json!({
            "base_url": stack.base_url(),
            "username": "admin",
            "password": stack.admin_password(),
        })
        .to_string(),
    )
    .unwrap();
    eprintln!("osiris-stack ready on {}", stack.base_url());
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}
