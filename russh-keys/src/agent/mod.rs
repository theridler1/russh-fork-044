/// Write clients for SSH agents.
pub mod client;
mod msg;
/// Write servers for SSH agents.
pub mod server;

/// Largest agent frame (the length announced by the 4-byte header) that the
/// client or the server will allocate a buffer for. Larger frames are
/// rejected with [`crate::Error::AgentProtocolError`] before any allocation
/// (RUSTSEC-2026-0154 / CVE-2026-46673; upstream uses the same 256 KiB cap).
pub const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

/// Constraints on how keys can be used
#[derive(Debug, PartialEq, Eq)]
pub enum Constraint {
    /// The key shall disappear from the agent's memory after that many seconds.
    KeyLifetime { seconds: u32 },
    /// Signatures need to be confirmed by the agent (for instance using a dialog).
    Confirm,
    /// Custom constraints
    Extensions { name: Vec<u8>, details: Vec<u8> },
}
