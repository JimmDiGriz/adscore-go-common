# Adscore Go Common — Context Guide

## Project Overview

This is a Go library (`github.com/JimmDiGriz/adscore-go-common`) that provides utilities for parsing and decrypting [Adscore](https://adscore.com) traffic signatures. It supports V4 (hashing/signing) and V5 (encrypted payload) signature algorithms.

**Main purpose:** Server-side integration with Adscore service for traffic verification and metadata extraction.

## Architecture

### Package Structure

| Package | Description |
|---------|-------------|
| `signature` | V4 and V5 signature parsing, verification, decryption |
| `judge` | Result scoring system (Clean, Potentially unwanted, Proxy, Bot) |
| `crypt` | Symmetric (AES-CBC/GCM) and asymmetric (ECDSA) crypto operations |
| `formatter` | Base64 encoding/decoding variants |
| `adscoreStruct` | Payload structure decoding (JSON, RFC3986) |
| `adscoreErrors` | Custom error types (VersionError, ParseError, VerifyError) |
| `utils` | Binary unpacking, PEM/Base64 key parsing |

### Key Components

**Signature V4** (`signature/signatureV4.go`):
- Uses IP address + User Agent for verification
- Supports HASH_SHA256 (HMAC) and SIGN_SHA256 (ECDSA)
- Result derived from verification, not from payload

**Signature V5** (`signature/signatureV5.go`):
- Decrypts payload containing metadata (zone_id, result, ipv4/ipv6, user_agent, etc.)
- Verification is separate from decryption
- Supports multiple serialization formats (JSON, RFC3986)

**Judge** (`judge/judge.go`):
- Results: 0=Clean, 3=Potentially unwanted, 6=Proxy, 9=Bot

## Building and Running

**Requirements:** Go >= 1.22.5

```bash
# Install dependencies
go mod tidy

# Build
go build ./...

# Run tests (if any exist)
go test ./...
```

## Development Conventions

### Code Style

- **Receiver names:** `self` preferred over single letters (e.g., `s *Signature5`)
- **Function calls with 4+ parameters:** Split across multiple lines with trailing commas
- **Comments:** Minimal, avoid duplicating function names in comments
- **Export rules:** By default unexported; export only what's necessary

### Error Handling

Custom error types in `adscoreErrors`:
- `VersionError` — unsupported/invalid signature version
- `ParseError` — malformed signature data
- `VerifyError` — verification failed (IP/UA mismatch)

### Testing Practices

- Tests should cover parsing, verification, and decryption logic
- Use table-driven tests for multiple signature variants

## Usage Examples

### V4 Signature

```go
obj, err := adscoreSignature.CreateSignatureV4FromRequest(signature, ipAddresses, userAgent, cryptKey)
if err != nil {
    // Handle VersionError, ParseError, VerifyError
}
result := obj.Result
```

### V5 Signature

```go
obj, err := adscoreSignature.CreateSignatureV5FromRequest(signature, ipAddresses, userAgent, cryptKey)
if err != nil {
    // Handle VersionError, ParseError, VerifyError
}
result := obj.Result
// Access metadata: obj.Payload["ipv4.ip"], obj.Payload["b.ua"], etc.
```

### Get Zone ID (V5 only)

```go
zoneId, err := adscoreSignature.GetZoneId(signature, "BASE64_VARIANT_URLSAFE_NO_PADDING")
```

## Supported V5 Algorithms

| Algorithm | Encryption | Serialization |
|-----------|------------|---------------|
| v5_0200H | OpenSSL CBC | HTTP query |
| v5_0201H | OpenSSL GCM | HTTP query |
| v5_0200J | OpenSSL CBC | JSON |
| v5_0201J | OpenSSL GCM | JSON |

**Not supported:** sodium secretbox, igbinary, msgpack, PHP serialize variants.

## Key Implementation Details

1. **Binary unpacking:** Custom `utils.Unpack()` mimics PHP's `unpack()` for parsing binary headers
2. **Key formats:** V4 expects base64-encoded keys; V5 expects raw binary keys
3. **Base64 variants:** Supports URL-safe with/without padding, standard with/without padding
4. **Payload structure:** V5 header = `version (1 byte) + length (2 bytes) + zone_id (8 bytes)`
