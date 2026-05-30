#!/usr/bin/env sh
# Minimal source installer: builds and installs depaudit via cargo.
set -eu

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust from https://rustup.rs first." >&2
    exit 1
fi

echo "Installing depaudit from source..."
cargo install --path crates/depaudit-cli
echo "Done. Run 'depaudit --help' to get started."
