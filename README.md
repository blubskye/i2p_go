# i2p_go

A full I2P router implementation in pure Go with NTCP2 and SSU2 transports.

## Features

### Core Router
- **NTCP2 Transport** - TCP-based transport with Noise_XK handshake
- **SSU2 Transport** - UDP-based transport with congestion control
- **Tunnel System** - Inbound, outbound, and transit tunnels
- **Network Database** - Kademlia DHT with floodfill support
- **Garlic Routing** - ECIES-X25519-AEAD-Ratchet encryption
- **Streaming Protocol** - TCP-like reliable streams over I2P

### Client APIs
- **SAMv3** - Simple Anonymous Messaging protocol for applications

### Services
- **HTTP Proxy** - Browse .i2p sites (default: 127.0.0.1:4444)
- **SOCKS Proxy** - SOCKS4/4a/5 proxy support (default: 127.0.0.1:4447)
- **IRC Server** - Full-featured IRC server for I2P
- **Eepsite Server** - Host your own I2P website
- **Jump Service** - Address resolution and registration
- **Address Book** - Hostname to destination mapping

## Project Structure

```
i2p_go/
├── cmd/
│   └── i2p-router/          # Router daemon CLI
├── pkg/
│   ├── crypto/              # Cryptographic primitives
│   │   ├── aes.go           # AES-256 ECB/CBC
│   │   ├── chacha20.go      # ChaCha20-Poly1305 AEAD
│   │   ├── eddsa.go         # Ed25519 signatures
│   │   ├── elgamal.go       # ElGamal-2048
│   │   ├── x25519.go        # X25519 key exchange
│   │   ├── noise.go         # Noise_XK protocol
│   │   └── elligator.go     # Elligator2 encoding
│   ├── data/                # Core data structures
│   │   ├── router_info.go   # RouterInfo
│   │   ├── lease_set.go     # LeaseSet v1/v2
│   │   ├── destination.go   # I2P Destination
│   │   └── identity_ex.go   # Extended Identity
│   ├── i2np/                # I2NP protocol messages
│   ├── transport/
│   │   ├── ntcp2/           # NTCP2 transport
│   │   └── ssu2/            # SSU2 transport
│   ├── tunnel/              # Tunnel management
│   ├── netdb/               # Network database
│   ├── garlic/              # Garlic routing
│   ├── streaming/           # TCP-like streaming
│   ├── router/              # Router core
│   ├── sam/                 # SAMv3 API
│   ├── addressbook/         # Address book system
│   └── services/
│       ├── proxy/           # HTTP and SOCKS proxies
│       ├── irc/             # IRC server
│       ├── eepsite/         # Eepsite HTTP server
│       └── jump/            # Jump service
└── internal/
    └── util/                # Internal utilities
```

## Building

```bash
go build ./...
```

## Running

```bash
# Start the router
./i2p-router -config config.toml

# Or with defaults
./i2p-router
```

## Configuration

Default ports:
- NTCP2: 9001
- SSU2: 9002
- HTTP Proxy: 4444
- SOCKS Proxy: 4447
- SAM: 7656

## Dependencies

- `golang.org/x/crypto` - ChaCha20, X25519, Ed25519, HKDF
- `github.com/dchest/siphash` - SipHash for NTCP2 frames

## Cryptography

Custom implementations:
- ElGamal-2048 using `math/big`
- Elligator2 for X25519 point encoding
- I2P-specific Base64 alphabet

## License

MIT License

## Contributing

Contributions welcome! Please submit pull requests to the GitHub repository.
