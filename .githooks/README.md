# Git hooks

Repo-tracked hooks, so everyone runs the same ones. They are **not** active on a
fresh clone until you opt in once (git ignores `core.hooksPath` from a clone by
design — a repo shouldn't be able to run code on your machine automatically):

```sh
make setup        # or, without make:  bash scripts/setup.sh
```

which sets:

```sh
git config core.hooksPath .githooks
```

## Hooks

- **pre-commit** — runs [`scripts/sync-dev-notes.sh`](../scripts/sync-dev-notes.sh),
  which mirrors the developer working notes into [`docs/dev-notes/`](../docs/dev-notes)
  (redacting credentials, converting wikilinks) and re-stages them. Idempotent and
  a no-op if the source notes directory isn't present, so it's safe for anyone.
