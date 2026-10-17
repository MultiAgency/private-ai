# Eval

`npm run eval` measures the reviewer on pull requests whose bugs are known. See
[How good it is](../README.md#how-good-it-is) for what the numbers say; this
page is for adding a case.

## A case

A case is a pair of files in [`cases/`](cases/):

- `<name>.json` pins the pull request and lists what a review should find.
- `<name>.md` is the pull request's description as it stood at the pinned
  commit. The review reads it, so keep it as it was, not as it ended up.

| Field | Meaning |
|---|---|
| `name` | A label for reports, e.g. `repo#94 at 34e6db3: volunteer tasks`. |
| `repo`, `pull_request` | Where the pull request lives (`owner/name`, number). |
| `base`, `head` | The full commit hashes the review runs between. |
| `description` | The `.md` file above, relative to the JSON. |
| `source` | Where the bugs came from (who found them, which commits fixed them). |
| `bugs` | One entry per known bug: a short key, and a yes/no question about a review's text. |

Each bug's question is put to the same attested model, which answers `YES` or
`NO` about a review's text (see [`judge.mjs`](judge.mjs)). Write it so that
*claiming the defect* is `YES` and *describing the code, or calling it fine*
is `NO`, as the existing cases do.

## Adding one

1. Pick a pull request whose bugs were found by someone other than this
   reviewer, so the case is not tuned to it. Pin `base` and `head`.
2. Save the description as it was at `head`, and write the questions.
3. Run it: `node eval/run.mjs --case eval/cases/<name>.json --runs 4`.
   It needs `NEARAI_API_KEY`, and `GITHUB_TOKEN` if the repository is private.
   Nothing is posted.
4. Check the grader before trusting it: the questions should answer `YES` on a
   review that raises the bug and `NO` on one that misses it.

`--runner rust` scores the hosted App on the same case; the build it needs is
described at the top of [`run.mjs`](run.mjs).

A case on a private repository can be measured but not shared. A public case is
more useful to others, because anyone can rerun it.
