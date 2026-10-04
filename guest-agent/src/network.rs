use guest_protocol::GuestNetworkConfig;
use std::{
    fs::File,
    os::fd::AsRawFd,
    process::Command,
    time::{Duration, Instant},
};

/// Configure the already-created guest interface. This runs inside the guest
/// supervisor after authenticated boot; it never creates or joins host
/// namespaces and never consumes a caller-provided host path.
pub fn configure(config: &GuestNetworkConfig, tool: Option<&File>) -> Result<(), String> {
    config.validate().map_err(str::to_owned)?;
    let tool = tool.ok_or("trusted guest network tool unavailable")?;
    run(
        tool,
        [
            "link",
            "set",
            "dev",
            &config.interface,
            "address",
            &config.mac,
        ],
    )?;
    let mtu = config.mtu.to_string();
    run(tool, ["link", "set", "dev", &config.interface, "mtu", &mtu])?;
    run(tool, ["link", "set", "dev", &config.interface, "up"])?;
    for address in &config.addresses {
        let value = format!("{}/{}", address.address, address.prefix);
        run(tool, ["addr", "replace", &value, "dev", &config.interface])?;
    }
    for gateway in &config.gateways {
        run(
            tool,
            [
                "route",
                "replace",
                "default",
                "via",
                gateway,
                "dev",
                &config.interface,
            ],
        )?;
    }
    if !config.dns_servers.is_empty() {
        let mut contents = String::new();
        for dns in &config.dns_servers {
            contents.push_str("nameserver ");
            contents.push_str(dns);
            contents.push('\n');
        }
        std::fs::write("/etc/resolv.conf", contents)
            .map_err(|e| format!("write DNS configuration: {e}"))?;
    }
    Ok(())
}

fn run<const N: usize>(tool: &File, args: [&str; N]) -> Result<(), String> {
    let path = format!("/proc/self/fd/{}", tool.as_raw_fd());
    let mut child = Command::new(path)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("run guest network tool: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("wait for guest network tool: {e}"))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err("guest network configuration rejected".into())
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("guest network configuration timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
