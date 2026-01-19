#!/bin/bash
# Run ream lean node for manual testing
#
# Usage: ./scripts/run_ream.sh
#
# This starts ream and prints the multiaddr to use with run_leanspec.sh

set -e

REAM_DIR="/Users/tcoratger/Documents/ethereum/ream"

pkill -f "ream lean_node" 2>/dev/null || true
sleep 1

GENESIS_TIME=$(($(date +%s) + 60))

cat > /tmp/ream_config.yaml << EOF
GENESIS_TIME: $GENESIS_TIME
NUM_VALIDATORS: 3
GENESIS_VALIDATORS:
- 0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65ec589c858b9c7980b276ebe550056b23f0bdc3b5a
- 0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e377237595d9a27887421b5233d09a50832db2f303d
- 0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a31105bd9a69afd2690ffd737d22ec6e3b31d47a642f
EOF

cat > /tmp/leanspec_genesis.json << EOF
{"GENESIS_TIME": $GENESIS_TIME, "GENESIS_VALIDATORS": [
"0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65ec589c858b9c7980b276ebe550056b23f0bdc3b5a",
"0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e377237595d9a27887421b5233d09a50832db2f303d",
"0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a31105bd9a69afd2690ffd737d22ec6e3b31d47a642f"]}
EOF

echo "Genesis time: $GENESIS_TIME (in 60 seconds)"
echo "Genesis config: /tmp/leanspec_genesis.json"
echo ""
echo "Once ream shows its peer ID, run in another terminal:"
echo "  ./scripts/run_leanspec.sh <PEER_ID>"
echo ""

cd "$REAM_DIR"
cargo run --release --no-default-features --features devnet2 -- lean_node \
    --network /tmp/ream_config.yaml \
    --validator-registry-path ./bin/ream/assets/lean/validators.yaml \
    --bootnodes none \
    --node-id ream_0 \
    --socket-port 9000
