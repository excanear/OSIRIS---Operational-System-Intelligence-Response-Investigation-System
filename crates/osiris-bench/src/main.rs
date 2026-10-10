use clap::{Parser, Subcommand};

mod agent;
mod ingest;
mod pipeline;
mod query;
mod stats;

#[derive(Parser)]
#[command(about = "OSIRIS benchmarks (ARCHITECTURE.md §19.2) — results go to PERFORMANCE.md")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Pipeline {
        #[arg(long, default_value_t = 200_000)]
        events: u64,
    },
    Query {
        #[arg(long, default_value_t = 100_000)]
        events: u64,
    },
    Ingest {
        #[arg(long)]
        rate: u64,
        #[arg(long, default_value_t = 30)]
        duration: u64,
    },
    Agent {
        #[arg(long)]
        rate: u64,
        #[arg(long, default_value_t = 30)]
        duration: u64,
    },
    All,
}

fn main() {
    let records = match Cli::parse().cmd {
        Cmd::Pipeline { events } => vec![pipeline::run(events)],
        Cmd::Query { events } => vec![query::run(events)],
        Cmd::Ingest { rate, duration } => vec![ingest::run(rate, duration)],
        Cmd::Agent { rate, duration } => vec![agent::run(rate, duration)],
        Cmd::All => {
            let mut v = vec![pipeline::run(200_000)];
            for n in [10_000, 100_000, 1_000_000] {
                v.push(query::run(n));
            }
            for r in [1_000, 10_000, 100_000] {
                v.push(ingest::run(r, 30));
            }
            for r in [0, 1_000, 10_000] {
                v.push(agent::run(r, 30));
            }
            v
        }
    };
    for r in &records {
        println!("{}", serde_json::to_string(r).unwrap());
    }
}
