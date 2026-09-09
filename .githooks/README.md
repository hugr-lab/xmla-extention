# Hooks

Four hooks, two owners, and two traps worth knowing about.

| hook | owner | what it does |
|---|---|---|
| `pre-commit` | this repo | the leak gate — constitution I, blocks a commit whose **staged** content carries an identifying token |
| `post-commit` | roborev | queues the commit for automated review |
| `post-rewrite` | roborev | remaps reviews after a rebase or amend |
| `pre-push` | roborev | flushes pending review batches before a push |

Point git at them with the **relative** path:

    git config core.hooksPath .githooks

## What the roborev hooks send

They are tracked, so a clone gets them — which makes automated review a property
of the repository rather than of one machine, and that deserves stating outright
rather than being discovered.

`roborev post-commit` hands the commit to a local daemon, which runs an AI agent
over the diff. That agent is a CLI tool on your machine, but it calls a model
API, so **commit content leaves the machine**. The leak gate runs *before* the
commit and roborev runs *after* it, so the gate is what stands between a token
and that transmission — which is a further reason the gate is not optional and
not to be bypassed with `--no-verify`.

If you would rather not run them, delete the three roborev hooks from your
checkout or point `core.hooksPath` somewhere that has only `pre-commit`. Nothing
in the build or CI depends on them.

## Trap 1: `roborev init` disables the leak gate in worktrees

`roborev init` sets `core.hooksPath` to an **absolute** path — the main
checkout's `.githooks` — rather than the relative `.githooks`. In a **git
worktree** that means the hooks git runs are the *main checkout's*, not the ones
in the worktree you are editing.

The consequence is silent and one-directional. The main checkout had only
roborev's three hooks, so running `roborev init` **turned the leak gate off for
every worktree** and nothing said so. Commits kept succeeding, which is exactly
what a disabled gate looks like.

**The remedy, not just the diagnosis:** re-run this in each worktree after any
`roborev init`:

    git config core.hooksPath .githooks

An absolute path stays wrong even once a `pre-commit` exists at the far end,
because the gate then disappears again whenever the main checkout is on a branch
or commit that predates it — a bisect, a detached checkout, an old feature
branch.

Check what is actually in force:

    git config --get core.hooksPath

The check that matters is not "is the file present" but "does a commit carrying
a token actually get blocked". Test it in both directions, which is what
`test/hooks/test_leak_gate.sh` does.

## Trap 2: the local hook is not the enforcement point

`.github/workflows/ci.yml` runs the gate over `git ls-files` — every tracked
file, not a diff — and that is the real backstop. The local hook is fast
feedback. A token that reached a commit while the hook was misconfigured is
still caught there, on the next push.
