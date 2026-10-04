//! A control-connection freeze is always thawed on timeout or unwind.
use std::{
    fs::File,
    time::{Duration, Instant},
};

const MAX_FREEZE: Duration = Duration::from_secs(60);

pub struct FreezeGuard<'a> {
    state: Option<&'a File>,
    until: Option<Instant>,
}

impl<'a> FreezeGuard<'a> {
    pub fn new(state: Option<&'a File>) -> Self {
        Self { state, until: None }
    }

    pub fn frozen(&self) -> bool {
        self.until.is_some()
    }

    pub fn freeze(&mut self) -> Result<(), String> {
        if self.frozen() {
            return Err("filesystem already quiesced".into());
        }
        let state = self.state.ok_or("filesystem quiesce unavailable")?;
        crate::fsync::freeze_state(state)?;
        self.until = Some(Instant::now() + MAX_FREEZE);
        Ok(())
    }

    pub fn thaw(&mut self) -> Result<(), String> {
        if self.frozen() {
            crate::fsync::thaw_state(self.state.ok_or("filesystem unquiesce unavailable")?)?;
            self.until = None;
        }
        Ok(())
    }

    pub fn expire(&mut self) -> Result<(), String> {
        if self
            .until
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.thaw()?;
        }
        Ok(())
    }
}

impl Drop for FreezeGuard<'_> {
    fn drop(&mut self) {
        let _ = self.thaw();
    }
}
