use sandboxd_protocol::{SandboxGeneration, SandboxId, SessionGeneration, SessionId};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct BootNonce(pub [u8; 32]);
impl std::fmt::Debug for BootNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootNonce([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionIdentity {
    pub sandbox: SandboxId,
    pub sandbox_generation: SandboxGeneration,
    pub session: SessionId,
    pub session_generation: SessionGeneration,
    pub boot_nonce: BootNonce,
    pub vsock_cid: u32,
    pub protocol_version: u16,
}
impl SessionIdentity {
    pub fn validate_rebind(&self, next: &Self) -> Result<(), &'static str> {
        let old_nonce = self.boot_nonce.0;
        let new_nonce = next.boot_nonce.0;
        if self.protocol_version != crate::GUEST_PROTOCOL_VERSION
            || next.protocol_version != crate::GUEST_PROTOCOL_VERSION
            || self.sandbox != next.sandbox
            || self.sandbox_generation != next.sandbox_generation
            || self.session == next.session
            || next.session_generation.get() <= self.session_generation.get()
            || self.vsock_cid != next.vsock_cid
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || old_nonce == [0; 32]
            || new_nonce == [0; 32]
            || bool::from(self.boot_nonce.0.ct_eq(&next.boot_nonce.0))
        {
            return Err("guest session rebind identity rejected");
        }
        Ok(())
    }

    pub fn authenticate(&self, received: &Self) -> Result<(), &'static str> {
        // Evaluate nonce comparison even for wrong public identities.
        let nonce_matches = bool::from(self.boot_nonce.0.ct_eq(&received.boot_nonce.0));
        if self.protocol_version != crate::GUEST_PROTOCOL_VERSION
            || received.protocol_version != crate::GUEST_PROTOCOL_VERSION
            || self.sandbox != received.sandbox
            || self.sandbox_generation != received.sandbox_generation
            || self.session != received.session
            || self.session_generation != received.session_generation
            || self.vsock_cid != received.vsock_cid
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || self.boot_nonce.0 == [0; 32]
            || !nonce_matches
        {
            return Err("guest session authentication failed");
        }
        Ok(())
    }
}
