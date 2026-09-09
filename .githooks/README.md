# Hooks

Four hooks, two owners, and one trap worth knowing about.

| hook | owner | what it does |
|---|---|---|
| `pre-commit` | this repo | the leak gate — constitution I, blocks a commit whose staged content carries an identifying token |
| `post-commit` | roborev | queues the commit for automated review |
| `post-rewrite` | roborev | remaps reviews after a rebase or amend |
| `pre-push` | roborev | flushes pending review batches before a push |

They are tracked so a fresh clone gets all four. Point git at them with:

    git config core.hooksPath .githooks

## The trap

`roborev init` sets `core.hooksPath` to an **absolute** path — the main checkout's
`.githooks` — rather than the relative `.githooks`. In a **git worktree** that means the
hooks git runs are the *main checkout's*, not the ones in the worktree you are editing.

The consequence is silent and one-directional: the main checkout had only roborev's three
hooks, so running `roborev init` **turned the leak gate off for every worktree** and nothing
said so. Commits kept succeeding, which is exactly what a disabled gate looks like.

If you edit `.githooks/pre-commit` here and the behaviour does not change, that is why. Check:

    git config --get core.hooksPath

and make sure a `pre-commit` exists at whatever path it names. The check that matters is not
"is the file present" but "does a commit carrying a token actually get blocked" — test it in
both directions, the way the gate's own tests do.
