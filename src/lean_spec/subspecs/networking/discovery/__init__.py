"""
Discovery v5 Protocol Specification

Node Discovery Protocol v5.1 for finding peers in Ethereum networks.

The module provides:
- Wire protocol encoding/decoding
- Cryptographic primitives (AES-CTR/GCM, secp256k1 ECDH)
- Session and handshake management
- UDP transport layer
- High-level discovery service

References:
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md
"""
