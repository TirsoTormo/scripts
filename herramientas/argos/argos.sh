#!/usr/bin/env bash
# ARGOS v1 — Network Intelligence & Packet Factory
#
# Usage:
#   ./argos.sh              Opens interactive menu
#   ./argos.sh --scan       Direct CLI command
#   ./argos.sh --help       Show help

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR"

if command -v uv &> /dev/null; then
    uv run python -m argos "$@"
else
    python3 -m argos "$@"
fi
