use crate::exec::Manager;
use guest_protocol::{GuestHealth, GuestMetrics, GuestProcess, GuestTelemetryProvenance};
use nix::unistd::getpid;

impl Manager {
    pub fn health(&self) -> GuestHealth {
        GuestHealth {
            ready: true,
            pid: getpid().as_raw().max(0) as u32,
            running_execs: self.processes.len() as u32,
            control_channel: true,
        }
    }

    pub fn metrics(&self) -> GuestMetrics {
        GuestMetrics {
            running_execs: self.processes.len() as u32,
            completed_execs: self.completed.len() as u32,
            provenance: GuestTelemetryProvenance::GuestReported,
        }
    }

    pub fn process_list(&self) -> Vec<GuestProcess> {
        self.processes
            .iter()
            .map(|(exec, process)| GuestProcess {
                exec: exec.clone(),
                pid: process.pid,
                state: if process.alive.load(std::sync::atomic::Ordering::Acquire) {
                    "RUNNING".to_owned()
                } else {
                    "EXITING".to_owned()
                },
                detached: process.detached,
            })
            .collect()
    }
}
