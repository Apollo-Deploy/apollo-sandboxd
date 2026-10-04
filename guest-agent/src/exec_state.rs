use super::Manager;
use guest_protocol::GuestMessage;
use sandboxd_protocol::ExecId;

impl Manager {
    pub(crate) fn retire(&mut self, exec: &ExecId) -> Result<(), String> {
        if self.processes.contains_key(exec) {
            return Err("cannot retire a running exec".into());
        }
        self.completed
            .remove(exec)
            .map(|_| ())
            .ok_or_else(|| "completed exec receipt not found".into())
    }

    pub(crate) fn finish(&mut self, exec: &ExecId, result: &GuestMessage) {
        self.processes.remove(exec);
        // Completed receipts are retained for the lifetime of this guest
        // session so an operation/exec retry can never be mistaken for a new
        // process after bounded storage evicts its identity. New execs are
        // refused once this bounded receipt store reaches MAX_EXECUTIONS.
        self.completed.insert(exec.clone(), result.clone());
    }

    pub(crate) fn wait(&self, exec: &ExecId) -> GuestMessage {
        self.completed
            .get(exec)
            .cloned()
            .or_else(|| {
                self.processes
                    .contains_key(exec)
                    .then_some(GuestMessage::Ready)
            })
            .unwrap_or_else(|| GuestMessage::Error {
                code: "exec not found".into(),
            })
    }
}
