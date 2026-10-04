use super::super::Target;
use apollo_sandboxd::{
    api::client,
    error::{Error, Result},
};
use clap::Subcommand;
use sandboxd_protocol::{GuestCommand, GuestReply, Request, Response, files::FileRequest};
use std::{
    io::{Cursor, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Subcommand)]
pub enum FileCommand {
    Stat {
        path: String,
        #[arg(long)]
        no_follow: bool,
    },
    Ls {
        path: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 256)]
        limit: u16,
    },
    Read {
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    Write {
        path: String,
        data: String,
    },
    Upload {
        source: PathBuf,
        path: String,
    },
    Download {
        path: String,
        destination: PathBuf,
    },
    Mkdir {
        path: String,
        #[arg(long, default_value_t = 493)]
        mode: u32,
        #[arg(long)]
        parents: bool,
    },
    Remove {
        path: String,
        #[arg(long)]
        recursive: bool,
    },
    Rename {
        source: String,
        destination: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Chown {
        path: String,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target: String,
        path: String,
    },
    Readlink {
        path: String,
    },
}

pub async fn call(
    socket: &Path,
    target: &Target,
    operation: sandboxd_protocol::OperationId,
    operation_sequence: u64,
    request: FileRequest,
) -> Result<GuestReply> {
    request.validate().map_err(Error::Config)?;
    match client::call(
        socket,
        &Request::Guest {
            operation: sandboxd_protocol::OperationId::with_sequence(
                operation_sequence,
                operation.as_str(),
            )
            .map_err(|_| Error::Config("operation ID/sequence is invalid"))?,
            operation_sequence,
            fence: target.fence()?,
            command: Box::new(GuestCommand::File { request }),
        },
        Duration::from_secs(30),
    )
    .await?
    {
        Response::Guest(reply @ GuestReply::File { .. }) => Ok(reply),
        _ => Err(Error::State),
    }
}

pub async fn run(socket: &Path, target: Target, command: FileCommand) -> Result<bool> {
    use FileCommand::*;
    let request = match command {
        Read { path, offset } => {
            let mut output = std::io::stdout().lock();
            super::transfer::download(socket, &target, &path, offset, &mut output).await?;
            output.flush()?;
            return Ok(true);
        }
        Write { path, data } => {
            super::transfer::upload(socket, &target, &path, &mut Cursor::new(data.into_bytes()))
                .await?;
            return Ok(true);
        }
        Upload { source, path } => {
            let mut input = std::fs::File::open(source)?;
            super::transfer::upload(socket, &target, &path, &mut input).await?;
            return Ok(true);
        }
        Download { path, destination } => {
            super::transfer::download_atomic(socket, &target, &path, &destination).await?;
            return Ok(true);
        }
        Stat { path, no_follow } => FileRequest::Stat {
            path,
            follow_symlink: !no_follow,
        },
        Ls {
            path,
            cursor,
            limit,
        } => FileRequest::List {
            path,
            cursor,
            limit,
        },
        Mkdir {
            path,
            mode,
            parents,
        } => FileRequest::Mkdir {
            path,
            mode,
            parents,
        },
        Remove { path, recursive } => FileRequest::Remove { path, recursive },
        Rename {
            source,
            destination,
        } => FileRequest::Rename {
            source,
            destination,
        },
        Chmod { path, mode } => FileRequest::Chmod { path, mode },
        Chown { path, uid, gid } => FileRequest::Chown { path, uid, gid },
        Symlink { target, path } => FileRequest::Symlink { target, path },
        Readlink { path } => FileRequest::Readlink { path },
    };
    let reply = call(
        socket,
        &target,
        target.operation.clone(),
        target.operation_sequence,
        request,
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&reply).map_err(|_| Error::State)?
    );
    Ok(true)
}
