mod exec;
mod exec_status;
mod files;
mod freeze;
mod fsync;
mod network;
mod protocol;
mod supervisor;
mod volumes;

fn main() -> Result<(), supervisor::Error> {
    supervisor::run(supervisor::Config::from_args(std::env::args_os())?)
}
