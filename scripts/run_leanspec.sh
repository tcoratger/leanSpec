#!/bin/bash
# Run leanspec node for manual testing
#
# Usage: ./scripts/run_leanspec.sh <REAM_PEER_ID>
#
# Run this after run_ream.sh and pass the peer ID from ream's output

set -e

if [ -z "$1" ]; then
    echo "Usage: ./scripts/run_leanspec.sh <REAM_PEER_ID>"
    echo ""
    echo "Example:"
    echo "  ./scripts/run_leanspec.sh 16Uiu2HAmKNGTVBbei6r5KSgc5KSFqukQDoGnSif5aGmf3i8HLKEz"
    exit 1
fi

PEER_ID="$1"
BOOTNODE="/ip4/127.0.0.1/udp/9000/quic-v1/p2p/$PEER_ID"

pkill -f "python -m lean_spec" 2>/dev/null || true
sleep 1

if [ ! -f /tmp/leanspec_genesis.json ]; then
    echo "ERROR: Genesis file not found at /tmp/leanspec_genesis.json"
    echo "Run ./scripts/run_ream.sh first"
    exit 1
fi

echo "Connecting to: $BOOTNODE"
echo ""

uv run python -m lean_spec \
    --genesis /tmp/leanspec_genesis.json \
    --bootnode "$BOOTNODE" \
    -v
