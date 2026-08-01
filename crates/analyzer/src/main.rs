use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use schemars::schema_for;
use zkevm_analyzer::{AnalyzeOptions, analyze, model::ReportV1};

#[derive(Debug, Parser)]
#[command(name = "zkevm-analyzer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Analyze a published ere-guests release.
    Analyze {
        /// "latest" or an explicit release tag.
        #[arg(long, default_value = "latest")]
        release: String,
        /// The merged zkevm-standards Git ref to resolve.
        #[arg(long, default_value = "main")]
        standards_ref: String,
        /// Atomic rule catalog.
        #[arg(long, default_value = "rules/standards.yml")]
        rules: PathBuf,
        /// Destination report JSON.
        #[arg(long)]
        output: PathBuf,
    },
    /// Emit the versioned report JSON Schema.
    Schema {
        /// Destination schema JSON.
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze {
            release,
            standards_ref,
            rules,
            output,
        } => {
            let report = analyze(AnalyzeOptions {
                release,
                standards_ref,
                rules_path: rules,
            })
            .await?;
            write_json(&output, &report)?;
            eprintln!(
                "analyzed {} artifacts from {}: {} failures, {} unknowns",
                report.artifacts.len(),
                report.release.tag,
                report.summary.fail,
                report.summary.unknown
            );
        }
        Command::Schema { output } => {
            let schema = schema_for!(ReportV1);
            write_json(&output, &schema)?;
        }
    }
    Ok(())
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}
