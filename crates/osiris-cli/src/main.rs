use clap::{Parser, Subcommand};
use osiris_cli::client::{
    chain_url, container_story_url, events_url, format_events_table, hunt_url, risk_url,
};
use osiris_cli::hunts::template;
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
    /// Show a container's whole observed lifecycle/activity timeline (Phase
    /// 5 plan Task 11 — this CLI's first `*_story` subcommand).
    ContainerStory { container_id: String },
    /// Show the bounded BehavioralChain graph walk seeded from an entity
    /// (Phase 6 plan Task 12). `entity` is the tagged string
    /// `EntityRef::storage_key()` produces, e.g. `PROCESS:<hex>`.
    Chain {
        entity: String,
        #[arg(long)]
        depth: Option<usize>,
    },
    /// Show risk scores, filtered by process_key and/or event_id (Phase 6
    /// plan Task 12).
    Risk {
        #[arg(long)]
        process_key: Option<String>,
        #[arg(long)]
        event_id: Option<String>,
    },
    /// Run a saved or ad-hoc OQL hunt (ARCHITECTURE.md §12.2). Exactly one
    /// of `query` or `--template` must be given.
    Hunt {
        query: Option<String>,
        #[arg(long)]
        template: Option<String>,
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        until: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

/// Sends the request, then treats a non-2xx HTTP status as a failure —
/// `reqwest::send()` alone only errors on connection/transport failure, not
/// on 4xx/5xx responses, which would otherwise let a `400`/`404`/`500` print
/// its body and exit 0 (a broken contract for any script driving this CLI).
fn get(client: &reqwest::blocking::Client, url: String) -> Result<String, String> {
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("request failed: {}", e))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("request failed: {}", e))?;
    if !status.is_success() {
        return Err(format!("request failed: HTTP {}: {}", status, body));
    }
    Ok(body)
}

fn main() {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::new();

    let result = match &cli.command {
        Command::Status => get(
            &client,
            format!("{}/status", cli.agent.trim_end_matches('/')),
        ),
        Command::Health => get(
            &client,
            format!("{}/api/v1/health", cli.server.trim_end_matches('/')),
        ),
        Command::Events {
            event_type,
            since,
            until,
            limit,
        } => {
            let url = events_url(&cli.server, event_type, since, until, limit);
            get(&client, url)
        }
        Command::Processes { process_key } => {
            let url = match process_key {
                Some(key) => format!(
                    "{}/api/v1/processes/{}",
                    cli.server.trim_end_matches('/'),
                    key
                ),
                None => format!("{}/api/v1/processes", cli.server.trim_end_matches('/')),
            };
            get(&client, url)
        }
        Command::ContainerStory { container_id } => {
            let url = container_story_url(&cli.server, container_id);
            get(&client, url)
        }
        Command::Chain { entity, depth } => {
            let url = chain_url(&cli.server, entity, depth);
            get(&client, url)
        }
        Command::Risk {
            process_key,
            event_id,
        } => {
            let url = risk_url(&cli.server, process_key, event_id);
            get(&client, url)
        }
        Command::Hunt { query, template: template_name, since, until, limit } => {
            let resolved = match (query, template_name) {
                (Some(q), None) => q.clone(),
                (None, Some(name)) => match template(name) {
                    Some(oql) => oql.to_string(),
                    None => {
                        eprintln!("unknown hunt template: {}", name);
                        std::process::exit(1);
                    }
                },
                (Some(_), Some(_)) => {
                    eprintln!("provide either a query or --template, not both");
                    std::process::exit(1);
                }
                (None, None) => {
                    eprintln!("provide either a query or --template");
                    std::process::exit(1);
                }
            };
            let url = hunt_url(&cli.server, &resolved, since, until, limit);
            get(&client, url)
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
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
