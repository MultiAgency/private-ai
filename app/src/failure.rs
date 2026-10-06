//! Why a review stopped, as the fixed category its caller is told. A run's
//! output leaves the enclave, so it never carries an error's text, which could
//! name a repository or quote code: each error is marked with its kind where it
//! arises (the GitHub and NEAR AI adapters mark theirs), and only the kind is
//! read back.
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// No stored job has this id.
    UnknownJob,
    /// The model's attestation failed its checks, so no code was sent.
    Attestation,
    /// A GitHub call failed.
    GitHub,
    /// A NEAR AI call failed, or a reply's signature did not check out.
    Model,
    /// The model never submitted its review.
    NoSubmission,
    /// Runs were killed before they answered (out of memory, or out of time).
    RunCutOff,
    /// Sealed storage could not be read or written.
    Storage,
    /// The head commit is larger than a run can hold.
    TooLarge,
    /// Anything else.
    Internal,
}

impl Failure {
    /// The category in the run's output.
    pub fn category(self) -> &'static str {
        match self {
            Self::UnknownJob => "unknown job",
            Self::Attestation => "attestation",
            Self::GitHub => "github",
            Self::Model => "model",
            Self::NoSubmission => "no submission",
            Self::RunCutOff => "run cut off",
            Self::Storage => "storage",
            Self::TooLarge => "too large",
            Self::Internal => "internal",
        }
    }

    /// What the pull request's check run says.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Attestation => "Attestation failed, so no code was sent to the model.",
            Self::TooLarge => "The repository is too large to review within one run's memory. No code left the enclave.",
            _ => "The review stopped before it finished. No code left the enclave.",
        }
    }

    /// The kind an error was marked with, wherever in its chain.
    pub fn of(error: &anyhow::Error) -> Self {
        error.chain().find_map(|e| e.downcast_ref::<Self>()).copied().unwrap_or(Self::Internal)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.category())
    }
}

impl std::error::Error for Failure {}

/// Marks a result's error with the kind it is, unless it already has one: the
/// first mark, nearest the cause, is the truest. The kind replaces the error,
/// whose text is never shown anywhere.
pub trait Mark<T> {
    fn mark(self, kind: Failure) -> anyhow::Result<T>;
}

impl<T> Mark<T> for anyhow::Result<T> {
    fn mark(self, kind: Failure) -> anyhow::Result<T> {
        self.map_err(|e| if Failure::of(&e) == Failure::Internal { kind.into() } else { e })
    }
}
