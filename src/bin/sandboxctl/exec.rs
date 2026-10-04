//! Exact-argv process control through the public daemon contract.
use super::super::Target;
use apollo_sandboxd::{
    api::client,
    error::{Error, Result},
};
use clap::{Args, Subcommand};
use sandboxd_protocol::{exec::*, *};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::OpenOptions, os::fd::OwnedFd, path::Path, time::Duration};

#[derive(Subcommand)]
pub enum ExecCommand {
    Start(Start),
    Attach {
        exec: ExecId,
        #[arg(long, default_value_t = 1)]
        from_sequence: u64,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        interactive: bool,
        #[arg(long)]
        pty: bool,
    },
    Wait {
        exec: ExecId,
    },
    Signal {
        exec: ExecId,
        signal: u8,
    },
    Cancel {
        exec: ExecId,
    },
    Stdin {
        exec: ExecId,
        data: String,
        #[arg(long)]
        eof: bool,
    },
    Resize {
        exec: ExecId,
        rows: u16,
        columns: u16,
    },
    List {
        #[arg(long)]
        after: Option<ExecId>,
        #[arg(long, default_value_t = 64)]
        limit: u16,
    },
}

#[derive(Args)]
pub struct Start {
    #[arg(long)]
    exec: ExecId,
    #[arg(long, default_value = "/")]
    cwd: String,
    #[arg(long, default_value_t = 0)]
    uid: u32,
    #[arg(long, default_value_t = 0)]
    gid: u32,
    #[arg(long, default_value_t = 3_600_000)]
    timeout_ms: u32,
    #[arg(long)]
    pty: bool,
    #[arg(long)]
    interactive: bool,
    #[arg(long)]
    detach: bool,
    #[arg(long, default_value_t = 24)]
    rows: u16,
    #[arg(long, default_value_t = 80)]
    columns: u16,
    #[arg(long="env", value_parser=parse_env)]
    environment: Vec<(String, String)>,
    #[arg(long, requires = "stderr_sink")]
    stdout_sink: Option<std::path::PathBuf>,
    #[arg(long, requires = "stdout_sink")]
    stderr_sink: Option<std::path::PathBuf>,
    /// Command arguments after -- are passed unchanged; no shell is implied.
    #[arg(last = true, required = true)]
    argv: Vec<String>,
}

fn parse_env(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or("environment must be KEY=VALUE")?;
    if key.is_empty() || key.contains('\0') || value.contains('\0') {
        return Err("invalid environment".into());
    }
    Ok((key.into(), value.into()))
}

pub(super) struct Calls<'a> {
    pub socket: &'a Path,
    target: Target,
    index: u64,
}
impl<'a> Calls<'a> {
    fn request(&self, command: GuestCommand) -> Result<Request> {
        command.validate().map_err(Error::Config)?;
        let sequence = self
            .target
            .operation_sequence
            .checked_add(self.index)
            .ok_or(Error::State)?;
        let operation = if self.index == 0 {
            OperationId::with_sequence(sequence, self.target.operation.as_str())
                .map_err(|_| Error::Config("invalid operation label or sequence"))?
        } else {
            let bytes = codec::encode_body(&("exec_cli", &self.target.operation, self.index))?;
            OperationId::with_sequence(
                sequence,
                format!("exec-{}", &hex::encode(Sha256::digest(bytes))[..24]),
            )
            .map_err(|_| Error::Config("invalid derived operation identity"))?
        };
        Ok(Request::Guest {
            operation,
            operation_sequence: sequence,
            fence: self.target.fence()?,
            command: Box::new(command),
        })
    }
    pub async fn call(&mut self, command: GuestCommand) -> Result<GuestReply> {
        self.call_sinks(command, Vec::new()).await
    }
    async fn call_sinks(
        &mut self,
        command: GuestCommand,
        sinks: Vec<OwnedFd>,
    ) -> Result<GuestReply> {
        let request = self.request(command)?;
        let response = if sinks.is_empty() {
            client::call(self.socket, &request, Duration::from_secs(30)).await?
        } else {
            client::call_with_sinks(self.socket, &request, sinks, Duration::from_secs(30)).await?
        };
        self.index = self.index.checked_add(1).ok_or(Error::State)?;
        match response {
            Response::Guest(reply) => Ok(reply),
            _ => Err(Error::State),
        }
    }
}

pub async fn run(socket: &Path, target: Target, command: ExecCommand) -> Result<bool> {
    let mut calls = Calls {
        socket,
        target,
        index: 0,
    };
    let request = match command {
        ExecCommand::Start(start) => {
            let environment: BTreeMap<_, _> = start.environment.into_iter().collect();
            let interactive = start.interactive || start.pty;
            let spec = ExecutionSpec {
                id: start.exec.clone(),
                argv: start.argv,
                use_image_defaults: false,
                cwd: start.cwd,
                uid: start.uid,
                gid: start.gid,
                environment,
                secret_environment: BTreeMap::new(),
                pty: start.pty.then_some(TerminalSize {
                    rows: start.rows,
                    columns: start.columns,
                }),
                stdin: if interactive {
                    StdinMode::Stream
                } else {
                    StdinMode::Closed
                },
                timeout_ms: start.timeout_ms,
                detached: start.detach,
                output_policy: if start.stdout_sink.is_some() {
                    OutputPolicy::Required
                } else {
                    OutputPolicy::Disabled
                },
            };
            let mut sinks = Vec::new();
            for path in [start.stdout_sink, start.stderr_sink].into_iter().flatten() {
                // Only the CLI opens these caller-local paths; the daemon receives owned FDs.
                let file = OpenOptions::new().write(true).open(path)?;
                sinks.push(file.into());
            }
            let reply = calls
                .call_sinks(
                    GuestCommand::ExecStart {
                        spec: Box::new(spec),
                    },
                    sinks,
                )
                .await?;
            if !matches!(reply, GuestReply::Acknowledged) {
                return Err(Error::State);
            }
            if start.detach {
                println!("{}", start.exec);
                return Ok(true);
            }
            return super::exec_attach::follow(
                &mut calls,
                start.exec,
                1,
                false,
                interactive,
                start.pty,
            )
            .await;
        }
        ExecCommand::Attach {
            exec,
            from_sequence,
            once,
            interactive,
            pty,
        } => {
            return super::exec_attach::follow(
                &mut calls,
                exec,
                from_sequence,
                once,
                interactive || pty,
                pty,
            )
            .await;
        }
        ExecCommand::Wait { exec } => GuestCommand::ExecWait { exec },
        ExecCommand::Signal { exec, signal } => GuestCommand::ExecSignal { exec, signal },
        ExecCommand::Cancel { exec } => GuestCommand::ExecCancel { exec },
        ExecCommand::Stdin { exec, data, eof } => GuestCommand::ExecStdin {
            exec,
            data: data.into_bytes(),
            eof,
        },
        ExecCommand::Resize {
            exec,
            rows,
            columns,
        } => GuestCommand::ExecResizePty {
            exec,
            size: TerminalSize { rows, columns },
        },
        ExecCommand::List { after, limit } => GuestCommand::ExecList { after, limit },
    };
    let reply = calls.call(request).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&reply).map_err(|_| Error::State)?
    );
    Ok(
        !matches!(reply, GuestReply::ExecExit { exit_code: Some(code), .. } if code != 0)
            && !matches!(
                reply,
                GuestReply::ExecExit {
                    signal: Some(_),
                    ..
                }
            ),
    )
}
