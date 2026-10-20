# Contributing

Thanks for helping. Private Investigator is small and its claims are specific,
so a good change is small too: one thing, with a test that fails before it and
passes after it. For anything larger than a fix, [open an issue](https://github.com/MultiAgency/private-ai/issues)
first.

## Set up

You need Node 22.19 or later. Rust is only needed to change `app/`; the pinned
toolchain and the `wasm32-wasip2` target come from `rust-toolchain.toml`.
Docker is only needed to reproduce a hosted build.

```sh
npm ci
npm run check   # node --check on every script
npm test        # offline; no keys, no network
cargo test --locked   # the hosted App's Rust core (app/)
```

CI runs the same: `npm run check && npm test`, then `cargo test --locked`, the
`wasm32-wasip2` build, and `app/verify-builds.sh`. Run what your change touches
before you push.

`npm test` is offline because it replays recorded evidence (a real attestation
report with its Intel collateral and NVIDIA's verdict, a real signed turn) and
a stand-in enclave. Keep new tests offline too, and keep API keys and tokens
out of the repository.

## Where things live

| Path | What it is |
| --- | --- |
| `review/` | The GitHub Action, and the review both paths run |
| `review/review.json` | The review as both reviewers run it: prompt, tools, limits. Change it there, never in code |
| `app/` | The hosted GitHub App, in Rust, built for OutLayer |
| `core/` | What every service shares (E2EE, attestation, receipts), in Node and the browser alike |
| `relay/` | The App's webhook relay |
| `site/` | The page, including the in-browser receipt checker |
| `eval/` | Quality measurements |

The Action and the App are two implementations of one review, so a behavior
change usually lands in both. `test/` and `app/tests/` check them against the
same cases; keep them agreeing.

## Changing the hosted App (`app/`)

A release is a build that anyone can reproduce from a commit. The files it is
built from are listed in `app/source.sh`: `app/src`, `app/Cargo.toml`,
`app/manifest.json`, the root `Cargo.toml` and `Cargo.lock`,
`rust-toolchain.toml`, `app/build.sh` and `review/review.json`. Changing any of
them changes the build.

- **Don't edit `app/builds.json` in a pull request.** It records each release's
  hash and commit, and the receipt checker trusts only recorded builds.
  `app/release.sh` adds an entry when a maintainer releases; it is not
  something to do by hand.
- Tests under `app/tests/` are not part of the build, so adding one never
  changes a release.
- Builds are only reproducible in the pinned container (`app/build.sh`, needs
  Docker). The same source builds different bytes on different hosts, so a
  native build's hash will not match.
- A change to `review/review.json` reaches the Action immediately and the App
  at its next release. Say so in the pull request.

## Adding an eval case

`eval/` measures the review on pull requests whose bugs are known. A case is a
JSON file in `eval/cases/` that pins:

- `repo`, `pull_request`, `base` and `head` commits (a public repository: cases
  hold findings and descriptions, so one from a private repository stays
  private);
- `description`, a file beside the case holding the pull request description
  *as it stood at that commit*, so a later edit can't hand the review the
  answer;
- `bugs`, the defects a review should raise, and optionally false positives it
  should not, each written as a yes/no question for the judge (see
  `eval/cases/near-agencies-94.json`).

`node eval/collect.mjs --repo owner/name` builds cases from 👍 and 👎 reactions
on the reviewer's own findings. It writes to the gitignored `eval/feedback/`;
move a case into `eval/cases/` only if its repository is public.

Run one with `NEARAI_API_KEY=… GITHUB_TOKEN=… node eval/run.mjs --case eval/cases/<case>.json --runs 4`.
Say in the pull request how many runs caught each bug. The README's quality
claims change only after a case is measured.

## Pull requests

- One change per pull request. Say what it fixes, what could break, and how you
  verified it, with the test that fails before the change.
- Run `npm run check`, `npm test`, and `cargo test --locked` if you touched
  `app/` or `review/review.json`.
- Match the surrounding code: its naming, its comment density, no new
  dependencies unless they are the point of the change. Dependencies are pinned
  to exact versions.
- Security reports: please don't open a public issue for a way around a check
  in `core/` or the receipt verifier. Contact the maintainers first.
