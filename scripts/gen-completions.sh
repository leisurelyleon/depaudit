#!/usr/bin/env sh
# Generate shell completions into packaging/completions/.
# Requires the binary to support a hidden `completions <shell>` subcommand,
# which is a planned enhancement (see README roadmap).
set -eu

OUT_DIR="packaging/completions"
mkdir -p "$OUT_DIR"
echo "Completion generation is a planned enhancement; directory prepared at $OUT_DIR."
