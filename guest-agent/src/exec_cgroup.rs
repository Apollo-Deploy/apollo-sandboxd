//! Per-execution cgroup-v2 process accounting and cleanup.

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub(crate) const EXECUTIONS: &str = "/sys/fs/cgroup/apollo/executions";

#[cfg(target_os = "linux")]
fn write_control(path: &std::path::Path, value: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .map_err(|e| format!("write cgroup control {}: {e}", path.display()))
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct ExecCgroup {
    path: Arc<PathBuf>,
}

#[cfg(target_os = "linux")]
impl ExecCgroup {
    pub(crate) fn create(exec: &str, customer_limit: u32) -> Result<Self, String> {
        let path = PathBuf::from(EXECUTIONS).join(format!("exec-{exec}"));
        fs::create_dir(&path).map_err(|e| format!("create execution cgroup: {e}"))?;
        let admitted = customer_limit
            .checked_add(2)
            .ok_or_else(|| "execution process limit overflow".to_owned())?;
        if let Err(error) = write_control(&path.join("pids.max"), &admitted.to_string()) {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self {
            path: Arc::new(path),
        })
    }

    pub(crate) fn placement_file(&self) -> Result<File, String> {
        OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))
            .map_err(|e| format!("open execution cgroup placement: {e}"))
    }

    pub(crate) fn contains(&self, pid: u32) -> Result<bool, String> {
        let members = fs::read_to_string(self.path.join("cgroup.procs"))
            .map_err(|e| format!("verify execution cgroup placement: {e}"))?;
        Ok(members
            .lines()
            .any(|member| member.parse::<u32>().ok() == Some(pid)))
    }

    pub(crate) fn kill_and_remove(&self) -> Result<(), String> {
        write_control(&self.path.join("cgroup.kill"), "1")?;
        let events_path = self.path.join("cgroup.events");
        for _ in 0..500 {
            let events = fs::read_to_string(&events_path)
                .map_err(|e| format!("read execution cgroup events: {e}"))?;
            if events.lines().any(|line| line == "populated 0") {
                return fs::remove_dir(&*self.path)
                    .map_err(|e| format!("remove execution cgroup: {e}"));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err("execution cgroup remained populated after kill".into())
    }

    pub(crate) fn kill(&self) -> Result<(), String> {
        write_control(&self.path.join("cgroup.kill"), "1")
    }
}

#[cfg(target_os = "linux")]
impl Drop for ExecCgroup {
    fn drop(&mut self) {
        if Arc::strong_count(&self.path) == 1 && self.path.exists() {
            let _ = self.kill_and_remove();
        }
    }
}
