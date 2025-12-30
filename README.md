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
│   ├── debug/               # Debug/trace system
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
# Clone the repository
git clone https://github.com/blubskye/i2p_go.git
cd i2p_go

# Build the router binary
go build -o i2p-router ./cmd/i2p-router
```

## Running

```bash
# Start the router with defaults
./i2p-router

# With debug logging
./i2p-router -log debug

# With custom addresses
./i2p-router -ntcp2 0.0.0.0:9001 -ssu2 0.0.0.0:9002

# Enable floodfill mode
./i2p-router -floodfill

# Custom data directory
./i2p-router -data /path/to/data

# Show all options
./i2p-router -help
```

Press `Ctrl+C` to stop the router.

### Router Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-data` | `~/.i2p-go` | Data directory |
| `-ntcp2` | `0.0.0.0:9001` | NTCP2 listen address |
| `-ssu2` | `0.0.0.0:9001` | SSU2 listen address |
| `-floodfill` | `false` | Enable floodfill mode |
| `-bw-in` | `256` | Inbound bandwidth limit (KB/s) |
| `-bw-out` | `256` | Outbound bandwidth limit (KB/s) |

## Configuration

Default ports:
- NTCP2: 9001
- SSU2: 9002
- HTTP Proxy: 4444
- SOCKS Proxy: 4447
- SAM: 7656

## Debugging & Tracing

The router includes a comprehensive debug/trace system that can be toggled on and off.

### Log Levels

```bash
./i2p-router -log trace    # Maximum verbosity (all messages)
./i2p-router -log debug    # Debug messages and above
./i2p-router -log info     # Normal operation (default)
./i2p-router -log warn     # Warnings and errors only
./i2p-router -log error    # Errors only
./i2p-router -log off      # Disable logging
```

### Subsystem Filtering

Filter logs to specific components:

```bash
# Only show NTCP2 and tunnel logs
./i2p-router -log debug -log-subsystems ntcp2,tunnel

# Available subsystems:
# router, ntcp2, ssu2, tunnel, netdb, garlic, stream, sam, proxy, irc, eepsite, crypto
```

### File Logging

```bash
# Write logs to file
./i2p-router -log debug -log-file router.log
```

### Stack Traces

```bash
# Enable stack traces for debug/trace messages
./i2p-router -log debug -log-stack
```

### Other Options

```bash
# Disable colored output
./i2p-router -log debug -no-color

# Show periodic statistics
./i2p-router -stats -stats-interval 30
```

### All Debug Flags

| Flag | Description |
|------|-------------|
| `-log` | Log level: off, error, warn, info, debug, trace |
| `-log-file` | Write logs to file instead of stderr |
| `-log-subsystems` | Comma-separated list of subsystems to trace |
| `-log-stack` | Show stack traces for debug/trace messages |
| `-no-color` | Disable colored log output |
| `-stats` | Show periodic router statistics |
| `-stats-interval` | Statistics display interval in seconds (default: 30) |

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
