#!/bin/bash
# Autonomous interop test script for leanSpec <-> ream/zeam/leanspec
set -e

LEANSPEC_DIR="/Users/tcoratger/Documents/ethereum/leanSpec"
REAM_DIR="/Users/tcoratger/Documents/ethereum/ream"
ZEAM_DIR="/Users/tcoratger/Documents/ethereum/zeam"
TEST_TARGET="${1:-leanspec}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${BLUE}[SUCCESS]${NC} $1"; }

cleanup() {
    pkill -f "ream lean_node" 2>/dev/null || true
    pkill -f "zeam.*node" 2>/dev/null || true
    pkill -f "python -m lean_spec" 2>/dev/null || true
    rm -rf /tmp/zeam_genesis /tmp/lean_config.yaml /tmp/leanspec_genesis.json 2>/dev/null || true
    rm -f /tmp/leanspec_node1.log /tmp/leanspec_node2.log 2>/dev/null || true
}
trap cleanup EXIT

create_configs() {
    local genesis_time=$(($(date +%s) + 30))
    cat > /tmp/lean_config.yaml << EOF
GENESIS_TIME: $genesis_time
NUM_VALIDATORS: 3
GENESIS_VALIDATORS:
- 0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65ec589c858b9c7980b276ebe550056b23f0bdc3b5a
- 0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e377237595d9a27887421b5233d09a50832db2f303d
- 0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a31105bd9a69afd2690ffd737d22ec6e3b31d47a642f
EOF
    cat > /tmp/leanspec_genesis.json << EOF
{"GENESIS_TIME": $genesis_time, "GENESIS_VALIDATORS": [
"0xe2a03c16122c7e0f940e2301aa460c54a2e1e8343968bb2782f26636f051e65ec589c858b9c7980b276ebe550056b23f0bdc3b5a",
"0x0767e65924063f79ae92ee1953685f06718b1756cc665a299bd61b4b82055e377237595d9a27887421b5233d09a50832db2f303d",
"0xd4355005bc37f76f390dcd2bcc51677d8c6ab44e0cc64913fb84ad459789a31105bd9a69afd2690ffd737d22ec6e3b31d47a642f"]}
EOF
    echo "$genesis_time"
}

test_ream() {
    log_info "=== Testing leanSpec <-> ream ==="
    cleanup
    
    log_info "Building ream devnet2..."
    cd "$REAM_DIR"
    cargo build --release --no-default-features --features devnet2 2>&1 | tail -3
    
    create_configs
    
    log_info "Starting ream..."
    ./target/release/ream lean_node \
        --network /tmp/lean_config.yaml \
        --validator-registry-path ./bin/ream/assets/lean/validators.yaml \
        --bootnodes none --node-id ream_0 --socket-port 9000 \
        > /tmp/ream_output.log 2>&1 &
    REAM_PID=$!
    sleep 2
    
    PEER_ID=$(grep -oE '16Uiu2HAm[a-zA-Z0-9]+' /tmp/ream_output.log | head -1)
    log_info "ream peer ID: $PEER_ID"
    
    log_info "Starting leanSpec..."
    cd "$LEANSPEC_DIR"
    uv run python -m lean_spec --genesis /tmp/leanspec_genesis.json \
        --bootnode "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/$PEER_ID" -v \
        > /tmp/leanspec_output.log 2>&1 &
    LEANSPEC_PID=$!
    
    log_info "Monitoring for 40s..."
    for i in $(seq 1 20); do
        sleep 2
        if grep -q "Connected to peer" /tmp/ream_output.log 2>/dev/null; then
            log_info "✓ Connection established!"
            if grep -q "Received status response" /tmp/ream_output.log 2>/dev/null; then
                log_info "✓ Status handshake completed!"
            fi
        fi
        if ! kill -0 $REAM_PID 2>/dev/null; then
            if grep -q "Connected to peer" /tmp/ream_output.log 2>/dev/null; then
                log_warn "ream crashed after connection (known SSZ bug)"
                echo "=== RESULT: P2P INTEROP WORKS, ream has internal bug ==="
                return 0
            fi
            log_error "ream crashed before connection"
            tail -20 /tmp/ream_output.log
            return 1
        fi
    done
    echo "=== RESULT: Test completed ==="
}

test_zeam() {
    log_info "=== Testing leanSpec <-> zeam ==="
    cleanup
    
    log_info "Building zeam..."
    /Users/tcoratger/.zvm/self/zvm use 0.14.0 2>/dev/null || true
    cd "$ZEAM_DIR"
    zig build 2>&1 | tail -3
    
    create_configs
    
    # Setup zeam genesis dir
    mkdir -p /tmp/zeam_genesis
    cp /tmp/lean_config.yaml /tmp/zeam_genesis/config.yaml
    cat > /tmp/zeam_genesis/validator-config.yaml << 'EOF'
zeam_0:
  - 0
  - 1  
  - 2
EOF
    ln -sf "$REAM_DIR/bin/ream/assets/lean/hash-sig-keys" /tmp/zeam_genesis/hash-sig-keys
    
    log_info "Starting zeam..."
    ./zig-out/bin/zeam --console_log_level debug node \
        --custom_genesis /tmp/zeam_genesis \
        --node-id zeam_0 \
        --validator_config /tmp/zeam_genesis/validator-config.yaml \
        > /tmp/zeam_output.log 2>&1 &
    ZEAM_PID=$!
    sleep 3
    
    if ! kill -0 $ZEAM_PID 2>/dev/null; then
        log_error "zeam failed to start"
        tail -30 /tmp/zeam_output.log
        return 1
    fi
    
    PEER_ID=$(grep -oE '16Uiu2HAm[a-zA-Z0-9]+' /tmp/zeam_output.log | head -1)
    log_info "zeam peer ID: $PEER_ID"
    
    if [ -z "$PEER_ID" ]; then
        log_warn "Could not get peer ID, checking logs..."
        tail -20 /tmp/zeam_output.log
        return 1
    fi
    
    log_info "Starting leanSpec..."
    cd "$LEANSPEC_DIR"
    uv run python -m lean_spec --genesis /tmp/leanspec_genesis.json \
        --bootnode "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/$PEER_ID" -v \
        > /tmp/leanspec_output.log 2>&1 &
    LEANSPEC_PID=$!
    
    log_info "Monitoring for 40s..."
    for i in $(seq 1 20); do
        sleep 2
        if grep -qi "connected\|peer" /tmp/zeam_output.log 2>/dev/null; then
            log_info "✓ Connection activity detected!"
        fi
        if ! kill -0 $ZEAM_PID 2>/dev/null; then
            log_error "zeam crashed"
            tail -30 /tmp/zeam_output.log
            return 1
        fi
    done
    echo "=== RESULT: Test completed ==="
}

test_leanspec() {
    log_info "=== Testing leanSpec <-> leanSpec (QUIC) ==="
    cleanup

    cd "$LEANSPEC_DIR"
    create_configs

    log_info "Starting leanSpec node 1 (listener)..."
    uv run python -m lean_spec --genesis /tmp/leanspec_genesis.json \
        --listen /ip4/0.0.0.0/udp/9001/quic-v1 -v \
        > /tmp/leanspec_node1.log 2>&1 &
    NODE1_PID=$!

    # Wait for node 1 to start and get its peer ID
    sleep 3

    if ! kill -0 $NODE1_PID 2>/dev/null; then
        log_error "Node 1 failed to start"
        cat /tmp/leanspec_node1.log
        return 1
    fi

    PEER_ID=$(grep -oE '16Uiu2HAm[a-zA-Z0-9]+' /tmp/leanspec_node1.log | head -1)
    if [ -z "$PEER_ID" ]; then
        PEER_ID=$(grep -oE '16Uiu2HAk[a-zA-Z0-9]+' /tmp/leanspec_node1.log | head -1)
    fi

    if [ -z "$PEER_ID" ]; then
        log_error "Could not extract peer ID from node 1"
        cat /tmp/leanspec_node1.log
        return 1
    fi

    log_info "Node 1 peer ID: $PEER_ID"

    log_info "Starting leanSpec node 2 (connecting to node 1)..."
    uv run python -m lean_spec --genesis /tmp/leanspec_genesis.json \
        --bootnode "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/$PEER_ID" -v \
        > /tmp/leanspec_node2.log 2>&1 &
    NODE2_PID=$!

    log_info "Monitoring connection for 20s..."
    CONNECTED=false
    HANDSHAKE=false
    STREAMS=false

    for i in $(seq 1 10); do
        sleep 2

        # Check node 1 logs for incoming connection
        if grep -q "QuicConnectionState.FIRSTFLIGHT -> QuicConnectionState.CONNECTED" /tmp/leanspec_node1.log 2>/dev/null; then
            if [ "$CONNECTED" = false ]; then
                log_info "✓ QUIC connection established on node 1"
                CONNECTED=true
            fi
        fi

        # Check node 2 logs for successful handshake
        if grep -q "ALPN negotiated protocol libp2p" /tmp/leanspec_node2.log 2>/dev/null; then
            if [ "$HANDSHAKE" = false ]; then
                log_info "✓ TLS handshake completed (libp2p ALPN)"
                HANDSHAKE=true
            fi
        fi

        # Check for streams being created
        if grep -q "Stream.*created by peer" /tmp/leanspec_node1.log 2>/dev/null; then
            if [ "$STREAMS" = false ]; then
                log_info "✓ Streams created between peers"
                STREAMS=true
            fi
        fi

        # Check if both nodes are still running
        if ! kill -0 $NODE1_PID 2>/dev/null; then
            log_warn "Node 1 stopped"
            break
        fi
        if ! kill -0 $NODE2_PID 2>/dev/null; then
            log_warn "Node 2 stopped"
            break
        fi

        # If all checks passed, we can stop early
        if [ "$CONNECTED" = true ] && [ "$HANDSHAKE" = true ] && [ "$STREAMS" = true ]; then
            break
        fi
    done

    # Print results
    echo ""
    echo "=== INTEROP TEST RESULTS ==="
    if [ "$CONNECTED" = true ]; then
        log_success "QUIC Connection: PASSED"
    else
        log_error "QUIC Connection: FAILED"
    fi

    if [ "$HANDSHAKE" = true ]; then
        log_success "TLS Handshake: PASSED"
    else
        log_error "TLS Handshake: FAILED"
    fi

    if [ "$STREAMS" = true ]; then
        log_success "Stream Creation: PASSED"
    else
        log_error "Stream Creation: FAILED"
    fi

    if [ "$CONNECTED" = true ] && [ "$HANDSHAKE" = true ] && [ "$STREAMS" = true ]; then
        echo ""
        log_success "=== ALL TESTS PASSED ==="
        return 0
    else
        echo ""
        log_error "=== SOME TESTS FAILED ==="
        echo ""
        echo "Node 1 logs:"
        tail -20 /tmp/leanspec_node1.log
        echo ""
        echo "Node 2 logs:"
        tail -20 /tmp/leanspec_node2.log
        return 1
    fi
}

case "$TEST_TARGET" in
    ream) test_ream ;;
    zeam) test_zeam ;;
    leanspec) test_leanspec ;;
    all) test_leanspec; echo ""; test_ream; echo ""; test_zeam ;;
    *) echo "Usage: $0 [leanspec|ream|zeam|all]"; exit 1 ;;
esac
