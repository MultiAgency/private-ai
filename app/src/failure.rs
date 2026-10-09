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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Context};

    const ALL: [Failure; 9] = [
        Failure::UnknownJob,
        Failure::Attestation,
        Failure::GitHub,
        Failure::Model,
        Failure::NoSubmission,
        Failure::RunCutOff,
        Failure::Storage,
        Failure::TooLarge,
        Failure::Internal,
    ];

    #[test]
    fn each_kind_has_a_distinct_fixed_category_that_is_also_its_display() {
        let categories: Vec<&str> = ALL.iter().map(|f| f.category()).collect();
        let mut unique = categories.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ALL.len(), "{categories:?}");
        for failure in ALL {
            assert_eq!(failure.to_string(), failure.category());
        }
        assert_eq!(Failure::GitHub.category(), "github");
        assert_eq!(Failure::NoSubmission.category(), "no submission");
    }

    #[test]
    fn the_check_run_explains_attestation_and_size_and_says_code_stayed_in_the_enclave() {
        assert_eq!(Failure::Attestation.explanation(), "Attestation failed, so no code was sent to the model.");
        assert!(Failure::TooLarge.explanation().contains("too large"));
        for failure in ALL {
            assert!(failure.explanation().ends_with("left the enclave.") || failure == Failure::Attestation, "{failure}");
        }
        assert_eq!(Failure::Model.explanation(), Failure::Internal.explanation());
    }

    #[test]
    fn an_error_with_no_mark_is_internal() {
        assert_eq!(Failure::of(&anyhow!("boom")), Failure::Internal);
    }

    #[test]
    fn a_mark_is_found_anywhere_in_the_chain() {
        let wrapped: anyhow::Error = anyhow::Error::from(Failure::Storage).context("while saving").context("while finishing");
        assert_eq!(Failure::of(&wrapped), Failure::Storage);
        let result: anyhow::Result<()> = Err(anyhow::Error::from(Failure::Model)).context("turn 3");
        assert_eq!(Failure::of(&result.unwrap_err()), Failure::Model);
    }

    #[test]
    fn marking_replaces_the_text_of_an_unmarked_error_with_the_kind() {
        let marked = Err::<(), _>(anyhow!("403 for private/repo")).mark(Failure::GitHub).unwrap_err();
        assert_eq!(Failure::of(&marked), Failure::GitHub);
        assert_eq!(marked.to_string(), "github");
        assert!(!format!("{marked:?}").contains("private/repo"));
    }

    #[test]
    fn the_first_mark_nearest_the_cause_wins() {
        let inner = Err::<(), _>(anyhow!("cause")).mark(Failure::Attestation);
        let outer = inner.mark(Failure::GitHub).unwrap_err();
        assert_eq!(Failure::of(&outer), Failure::Attestation);
        assert_eq!(Failure::of(&Err::<(), _>(anyhow!("x")).mark(Failure::Internal).unwrap_err()), Failure::Internal);
    }

    #[test]
    fn marking_leaves_a_success_alone() {
        assert_eq!(Ok::<_, anyhow::Error>(7).mark(Failure::Model).unwrap(), 7);
    }
}
