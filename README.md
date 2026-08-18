# ecdsa-google-sheets

Google Apps Script ECDSA library for secp256k1 curve with local CSPRNG and RFC 6979 deterministic nonces.

## Usage

### Generate Keys
```javascript
const keys = easyMake();
const privateKeyPem = keys[0];
const publicKeyPem = keys[1];
```

### Sign a Message
```javascript
const message = "Hello, world!";
const signature = easySign(message, privateKeyPem);
```

### Verify a Signature
```javascript
const isValid = easyVerify(message, signature, publicKeyPem);
console.log(isValid); // true or false
```

## Test Coverage

Run all tests:
```javascript
runAllTests(); // Executes 7 tests
```

Run specific suites:
```javascript
runAllPhase1Tests();  // CSPRNG validation (4 tests)
runAllPhase2Tests();  // RFC 6979 validation (3 tests)
```

Tests:
1. 100 unique random numbers in valid range
2. Uniform distribution of random numbers
3. Private key generation with CSPRNG
4. Backward compatibility
5. RFC 6979 determinism (same input = same signature)
6. Different messages produce different signatures
7. Signature verification works

## Architecture

```
sign(message, privateKey)
  ├─ hash(message) → SHA-256
  ├─ Integer.secureRandomNonce(privateKey.secret, hash)
  │  └─ KDF-based deterministic nonce
  └─ return Signature(r, s)

verify(message, signature, publicKey)
  ├─ Recover point from signature
  ├─ Compare with expected point
  └─ return true/false
```

## Security Considerations

1. **Private Key Storage** — Keep PEM strings secure (treat as secrets)
2. **Message Integrity** — Verify message hasn't been modified before checking signature
3. **Nonce Determinism** — RFC 6979 eliminates nonce-reuse attacks
4. **Local Entropy** — All randomness is generated locally (no network exposure)

## License

See LICENSE file.
