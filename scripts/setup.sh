#!/usr/bin/env bash
# One-time developer setup for this clone. Idempotent — safe to re-run.
#
# Enables the repo-tracked git hooks (git ignores a clone's core.hooksPath by
# design, so each clone must opt in once). Run via `make setup`, or directly:
#     bash scripts/setup.sh
set -e
cd "$(git rev-parse --show-toplevel)"

git config core.hooksPath .githooks
echo "Enabled repo-tracked git hooks (core.hooksPath = $(git config --get core.hooksPath))."
echo "Hooks now active: $(ls .githooks | grep -v '\.md$' | tr '\n' ' ')"
echo "Setup complete."
