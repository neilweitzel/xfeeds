#!/usr/bin/env bash
# Environment setup script for Jules (paste into the task's environment setup box,
# or point Jules at this file). Also works locally.
#
# Jules VMs ship Python 3.12 and an older uv. xfeeds targets Python 3.13
# (docs/DECISIONS.md ADR-001), so we install it explicitly rather than
# downgrading the project to match the VM.

set -euo pipefail

echo "==> Installing a current uv"
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv --version

echo "==> Installing Python 3.13"
uv python install 3.13

echo "==> Syncing dependencies"
if [ -f pyproject.toml ]; then
  uv sync --all-extras --dev
else
  echo "No pyproject.toml yet (expected on the scaffolding task) - skipping sync"
fi

echo "==> Verifying toolchain"
uv run python --version || true
uv run ruff --version   || true
uv run mypy --version   || true
uv run pytest --version || true

echo "==> Setup complete"
