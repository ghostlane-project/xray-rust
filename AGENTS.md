# This fork: ghostlane-project/xray-rust

This repository is Ghostlane's fork of `aimalygin/xray-rust`. In this fork,
write to `ghostlane-project/xray-rust` only: topic branches `gl/*`, and the
`ghostlane` branch the Ghostlane app pins, which moves by merges and
fast-forwards alone (never a rebase or a force push). Never push to `main`,
which mirrors upstream, and open no pull request or issue on
`aimalygin/xray-rust` without a new explicit instruction from the user.
The upstream scope below is kept as upstream wrote it, for upstream's own
checkouts.

# Repository write scope

Write access is restricted to these repositories:

- `aimalygin/xray-rust` (`/Users/antonmalygin/xray-rust` and its worktrees).
- `aimalygin/xray-rust-mobile` (`/Users/antonmalygin/xray-rust-mobile` and its worktrees).
- `aimalygin/xray-rust-kmp` (`/Users/antonmalygin/xray-rust-kmp` and its worktrees).

Reading other repositories is allowed when relevant to the task, including
inspecting code, searching, comparing implementations, and fetching reference
material.

Keep repository modifications and GitHub write operations within the three
repositories above. This includes source edits, commits, pushes, branch/tag
changes, pull-request or issue changes, workflow dispatches, and releases.
Writing to another repository requires a new explicit instruction from the user.

Before a write operation, verify the target repository. Use an explicit
repository path or `--repo` argument where available; broader account access
does not authorize writes to other repositories.
