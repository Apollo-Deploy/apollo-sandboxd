use apollo_sandboxd::{
    api::client,
    config::Config,
    doctor,
    error::{Error, Result},
};
use clap::{Args, Parser, Subcommand};
use sandboxd_protocol::exec::SecretValue;
use sandboxd_protocol::*;
use std::{fs::File, io::Read, path::PathBuf, time::Duration};
mod sandboxctl;

#[derive(Parser)]
#[command(
    version,
    about = "Standalone sandboxd client; capability discovery reports operational scope"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "/run/apollo-sandboxd/sandboxd.sock"
    )]
    socket: PathBuf,
    #[arg(
        long,
        global = true,
        default_value = "/etc/apollo-sandboxd/config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Read-only structural/artifact checks. Never starts a VM.
    Doctor,
    Capabilities,
    Health,
    OperationWatermark,
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Image {
        #[command(subcommand)]
        command: ImageCommandLine,
    },
    Snapshot {
        #[command(subcommand)]
        command: sandboxctl::snapshot::SnapshotCommandLine,
    },
    Checkpoint {
        #[command(flatten)]
        target: Target,
        #[command(subcommand)]
        command: sandboxctl::checkpoint::CheckpointCommandLine,
    },
    /// Generation-fenced sandbox lifecycle.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    File {
        #[command(flatten)]
        target: Target,
        #[command(subcommand)]
        command: sandboxctl::files::FileCommand,
    },
    Exec {
        #[command(flatten)]
        target: Target,
        #[command(subcommand)]
        command: sandboxctl::exec::ExecCommand,
    },
    Events {
        #[arg(long, default_value_t = 1)]
        from_sequence: u64,
        #[arg(long, default_value_t = 64)]
        limit: u16,
    },
}
#[derive(Subcommand)]
enum RuntimeCommand {
    List,
}
#[derive(Subcommand)]
enum ImageCommandLine {
    Inspect {
        digest: String,
    },
    List {
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 64)]
        limit: u16,
    },
    Pull {
        reference: String,
        #[arg(long)]
        operation: OperationId,
        #[arg(long)]
        operation_sequence: u64,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    ImportLayout {
        relative_layout: String,
        #[arg(long)]
        operation: OperationId,
        #[arg(long)]
        operation_sequence: u64,
    },
}
#[derive(Subcommand)]
enum SandboxCommand {
    Create {
        #[arg(long)]
        id: SandboxId,
        #[arg(long)]
        operation: OperationId,
        #[arg(long)]
        operation_sequence: u64,
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        expected_generation: Option<u64>,
        #[arg(long, default_value_t = 300)]
        lease_seconds: u32,
    },
    Inspect {
        id: SandboxId,
    },
    List {
        #[arg(long)]
        after: Option<SandboxId>,
        #[arg(long, default_value_t = 64)]
        limit: u16,
    },
    Destroy {
        #[command(flatten)]
        target: Target,
    },
    Start {
        #[command(flatten)]
        target: Target,
    },
    Stop {
        #[command(flatten)]
        target: Target,
    },
    Pause {
        #[command(flatten)]
        target: Target,
    },
    Resume {
        #[command(flatten)]
        target: Target,
    },
    Renew {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        duration_seconds: u32,
    },
    /// Acquire a new finite lease for stopped identity metadata after expiry.
    AcquireLease {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        duration_seconds: u32,
    },
}
#[derive(Args)]
struct Target {
    #[arg(long)]
    id: SandboxId,
    #[arg(long)]
    generation: u64,
    #[arg(long)]
    session_generation: Option<u64>,
    #[arg(long)]
    lease: LeaseId,
    #[arg(long)]
    operation: OperationId,
    #[arg(long)]
    operation_sequence: u64,
}
impl Target {
    fn canonical_operation(&self) -> Result<OperationId> {
        OperationId::with_sequence(self.operation_sequence, self.operation.as_str())
            .map_err(|_| Error::Config("operation ID/sequence is invalid"))
    }

    fn fence(&self) -> Result<Fence> {
        Ok(Fence {
            sandbox: self.id.clone(),
            generation: SandboxGeneration::new(self.generation).map_err(Error::Config)?,
            session_generation: self
                .session_generation
                .map(SessionGeneration::new)
                .transpose()
                .map_err(Error::Config)?,
            lease: self.lease.clone(),
        })
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<bool> {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Doctor) {
        let config = Config::load(&cli.config);
        let report = doctor::inspect(config.as_ref().ok()).await;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| Error::State)?
        );
        return Ok(report.passed);
    }
    let request = match cli.command {
        Command::Exec { target, command } => {
            return sandboxctl::exec::run(&cli.socket, target, command).await;
        }
        Command::File { target, command } => {
            return sandboxctl::files::run(&cli.socket, target, command).await;
        }
        Command::Snapshot { command } => sandboxctl::snapshot::request(command)?,
        Command::Checkpoint { target, command } => {
            sandboxctl::checkpoint::request(target, command)?
        }
        Command::Doctor => return Err(Error::State),
        Command::Capabilities => Request::Capabilities,
        Command::Health => Request::Health,
        Command::OperationWatermark => Request::OperationWatermark,
        Command::Runtime {
            command: RuntimeCommand::List,
        } => Request::RuntimeList,
        Command::Image { command } => match command {
            ImageCommandLine::Inspect { digest } => Request::ImageInspect {
                digest: ImageDigest::new(digest).map_err(Error::Config)?,
            },
            ImageCommandLine::List { after, limit } => Request::ImageList {
                after: after
                    .map(|value| ImageDigest::new(value).map_err(Error::Config))
                    .transpose()?,
                limit,
            },
            ImageCommandLine::Pull {
                reference,
                operation,
                operation_sequence,
                username,
                password,
            } => Request::Image {
                operation: OperationId::with_sequence(operation_sequence, operation.as_str())
                    .map_err(|_| Error::Config("operation ID/sequence is invalid"))?,
                operation_sequence,
                command: Box::new(sandboxd_protocol::ImageCommand::Pull {
                    reference,
                    username,
                    password: password.map(SecretValue),
                }),
            },
            ImageCommandLine::ImportLayout {
                relative_layout,
                operation,
                operation_sequence,
            } => Request::Image {
                operation: OperationId::with_sequence(operation_sequence, operation.as_str())
                    .map_err(|_| Error::Config("operation ID/sequence is invalid"))?,
                operation_sequence,
                command: Box::new(sandboxd_protocol::ImageCommand::ImportLayout {
                    relative_layout,
                }),
            },
        },
        Command::Events {
            from_sequence,
            limit,
        } => Request::Events {
            from_sequence,
            limit,
        },
        Command::Sandbox { command } => match command {
            SandboxCommand::Create {
                id,
                operation,
                operation_sequence,
                spec,
                expected_generation,
                lease_seconds,
            } => {
                let mut bytes = Vec::new();
                File::open(spec)?.take(131_073).read_to_end(&mut bytes)?;
                if bytes.len() > 131_072 {
                    return Err(Error::Config("sandbox specification size limit"));
                }
                let spec: SandboxSpec = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::Config("invalid sandbox specification"))?;
                spec.validate()?;
                Request::Mutate {
                    operation: OperationId::with_sequence(operation_sequence, operation.as_str())
                        .map_err(|_| Error::Config("operation ID/sequence is invalid"))?,
                    operation_sequence,
                    mutation: Box::new(Mutation::Create {
                        sandbox: id,
                        expected_generation: expected_generation
                            .map(SandboxGeneration::new)
                            .transpose()
                            .map_err(Error::Config)?,
                        spec: Box::new(spec),
                        lease_seconds,
                    }),
                }
            }
            SandboxCommand::Inspect { id } => Request::Inspect { sandbox: id },
            SandboxCommand::List { after, limit } => Request::List { after, limit },
            SandboxCommand::Destroy { target } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Destroy {
                    fence: target.fence()?,
                }),
            },
            SandboxCommand::Start { target } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Session {
                    fence: target.fence()?,
                    control: SessionControl::Start,
                }),
            },
            SandboxCommand::Stop { target } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Session {
                    fence: target.fence()?,
                    control: SessionControl::Stop,
                }),
            },
            SandboxCommand::Pause { target } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Session {
                    fence: target.fence()?,
                    control: SessionControl::Pause,
                }),
            },
            SandboxCommand::Resume { target } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Session {
                    fence: target.fence()?,
                    control: SessionControl::Resume,
                }),
            },
            SandboxCommand::Renew {
                target,
                sequence,
                duration_seconds,
            } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::Renew {
                    fence: target.fence()?,
                    sequence,
                    duration_seconds,
                }),
            },
            SandboxCommand::AcquireLease {
                target,
                duration_seconds,
            } => Request::Mutate {
                operation: target.canonical_operation()?,
                operation_sequence: target.operation_sequence,
                mutation: Box::new(Mutation::AcquireLease {
                    fence: target.fence()?,
                    duration_seconds,
                }),
            },
        },
    };
    let result = client::call(&cli.socket, &request, Duration::from_secs(30)).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|_| Error::State)?
    );
    Ok(true)
}
