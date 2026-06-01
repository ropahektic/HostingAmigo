#!/bin/bash
cd "$(dirname "$0")/.."
export PYTHONPATH=src
exec python3 scripts/replay_wire_winner.py "$@"
