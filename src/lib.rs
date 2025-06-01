mod circuit;
mod hash;
mod types;
mod leakyand;
mod leakydelta_ot;
mod ot_base;
mod cointossing;
pub mod states;

pub use circuit::*;
pub use states::*;

/// Errors occurring during the validation or the execution of the MPC protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A different message was expected from the other party at this point in the protocol.
    UnexpectedMessageType,
    /// The AND shares received did not match the number of gates.
    InsufficientAndShares,
    /// The garbled table share does not belong to an AND gate.
    UnexpectedGarbledTableShare,
    /// Not enough input bits were provided as user input.
    InsufficientInput,
    /// A AC checking error occured, due to an accidental or deliberate data corruption.
    MacError,
    /// The Leaky Authenticated AND Triples did not pass the equality check.
    LeakyAndNotEqual,
    /// The provided circuit contains invalid gate connections.
    InvalidCircuit,
    /// The provided circuit has too many gates to be processed.
    MaxCircuitSizeExceeded,
    /// The provided byte buffer could not be deserialized into an OT init message.
    OtInitDeserializationError,
    /// The provided byte buffer could not be deserialized into an OT block message.
    OtBlockDeserializationError,
    /// The provided byte buffer could not be deserialized into the expected type.
    BincodeError,
    /// The protocol has already ended, no further messages can be processed.
    ProtocolEnded,
    /// The protocol is still in progress and does not yet have any output.
    ProtocolStillInProgress,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedMessageType => f.write_str("Unexpected message kind"),
            Error::InsufficientAndShares => {
                f.write_str("Insufficient number of AND shares received from upstream")
            }
            Error::UnexpectedGarbledTableShare => {
                f.write_str("Received a table share for an unsupported gate")
            }
            Error::InsufficientInput => f.write_str("Not enough or too many input bits provided"),
            Error::MacError => f.write_str("At least 1 MAC check failed"),
            Error::LeakyAndNotEqual => {
                f.write_str("The equality check of the leaky AND step failed")
            }
            Error::InvalidCircuit => {
                f.write_str("The provided circuit is invalid and cannot be executed")
            }
            Error::MaxCircuitSizeExceeded => f.write_str(
                "The number of gates in the circuit exceed the maximum that can be processed",
            ),
            Error::OtInitDeserializationError => f.write_str(
                "The message buffer could not be deserialized into a proper OT init message",
            ),
            Error::OtBlockDeserializationError => f.write_str(
                "The message buffer could not be deserialized into a proper OT block message",
            ),
            Error::BincodeError => {
                f.write_str("The message could not be serialized to / deserialized from bincode")
            }
            Error::ProtocolEnded => {
                f.write_str("The protocol has already ended, no further messages can be processed.")
            }
            Error::ProtocolStillInProgress => {
                f.write_str("The protocol is still in progress and does not yet have any output.")
            }
        }
    }
}

impl From<bincode::Error> for Error {
    fn from(_: bincode::Error) -> Self {
        Self::BincodeError
    }
}
