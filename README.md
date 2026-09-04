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
runAllTests(); // Executes 10 tests
```

Run specific suites:
```javascript
runAllPhase1Tests();  // CSPRNG validation (4 tests)
runAllPhase2Tests();  // RFC 6979 validation (3 tests)
runAllPhase3Tests();  // Negative / security cases (3 tests)
```

Tests:
1. 100 unique random numbers in valid range
2. Uniform distribution of random numbers
3. Private key generation with CSPRNG
4. Backward compatibility
5. RFC 6979 determinism (same input = same signature)
6. Different messages produce different signatures
7. Signature verification works
8. verify rejects out-of-range r and s
9. verify rejects malformed signatures without throwing
10. verify rejects forged point-at-infinity signatures

## Architecture

```
sign(message, privateKey)
  ├─ hash(message) → SHA-256
  ├─ Integer.secureRandomNonce(privateKey.secret, hash)
  │  └─ KDF-based deterministic nonce
  └─ return Signature(r, s)

verify(message, signature, publicKey)
  ├─ reject if r or s not in [1, N)
  ├─ compute u1*G + u2*Q  (u1 = h*s⁻¹, u2 = r*s⁻¹ mod N)
  ├─ reject if the sum is the point at infinity
  └─ return (u1*G + u2*Q).x mod N == r
```

## Security Considerations

1. **Private Key Storage** — Keep PEM strings secure (treat as secrets)
2. **Message Integrity** — Verify message hasn't been modified before checking signature
3. **Nonce Determinism** — RFC 6979 eliminates nonce-reuse attacks
4. **Local Entropy** — All randomness is generated locally (no network exposure)

## License

See LICENSE file.
