mod exec;
#[cfg(target_os = "linux")]
mod exec_cgroup;
#[cfg(target_os = "linux")]
mod exec_isolation;
mod exec_status;
mod files;
mod filesystem_export;
mod freeze;
mod fsync;
mod network;
mod protocol;
mod supervisor;
mod volumes;

fn main() -> Result<(), supervisor::Error> {
    #[cfg(target_os = "linux")]
    if exec_isolation::dispatch() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    exec_isolation::close_bootstrap_descriptors(std::env::args_os())
        .map_err(supervisor::Error::Config)?;
    supervisor::run(supervisor::Config::from_args(std::env::args_os())?)
}
