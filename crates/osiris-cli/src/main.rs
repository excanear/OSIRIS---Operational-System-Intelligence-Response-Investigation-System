use clap::{Parser, Subcommand};
use osiris_cli::client::{events_url, format_events_table};
use osiris_schema::CanonicalEvent;

#[derive(Parser)]
#[command(
    name = "osiris",
    about = "OSIRIS CLI — thin HTTP client over the Server API and the Agent's local status endpoint"
)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, default_value = "http://127.0.0.1:9200")]
    agent: String,
    #[arg(long, default_value = "table")]
    format: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Local Agent lifecycle/sensor health — the one local-only subcommand
    /// this phase implements (ARCHITECTURE.md §15; `sensors`/`config` are
    /// deferred, not exit-criterion-blocking).
    Status,
    /// Server storage health.
    Health,
    /// List events (a Timeline, per plan Global Constraints #9).
    Events {
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// List processes, or show one process's exec record + children (a
    /// Process Tree, per plan Global Constraints #9).
    Processes { process_key: Option<String> },
}

fn main() {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::new();

    let result = match &cli.command {
        Command::Status => client
            .get(format!("{}/status", cli.agent.trim_end_matches('/')))
            .send()
            .and_then(|r| r.text()),
        Command::Health => client
            .get(format!("{}/api/v1/health", cli.server.trim_end_matches('/')))
            .send()
            .and_then(|r| r.text()),
        Command::Events { event_type, since, until, limit } => {
            let url = events_url(&cli.server, event_type, since, until, limit);
            client.get(url).send().and_then(|r| r.text())
        }
        Command::Processes { process_key } => {
            let url = match process_key {
                Some(key) => format!("{}/api/v1/processes/{}", cli.server.trim_end_matches('/'), key),
                None => format!("{}/api/v1/processes", cli.server.trim_end_matches('/')),
            };
            client.get(url).send().and_then(|r| r.text())
        }
    };

    match result {
        Ok(body) => {
            if cli.format == "json" {
                println!("{}", body);
            } else if let Command::Events { .. } = &cli.command {
                match serde_json::from_str::<Vec<CanonicalEvent>>(&body) {
                    Ok(events) => print!("{}", format_events_table(&events)),
                    Err(_) => println!("{}", body),
                }
            } else {
                println!("{}", body);
            }
        }
        Err(e) => {
            eprintln!("request failed: {}", e);
            std::process::exit(1);
        }
    }
}
