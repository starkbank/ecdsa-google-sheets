let Integer = {};

Integer.modulo = function(x, n) {
    let mod = x % BigInt(n);

    if (mod < BigInt(0)) {
        mod = mod + BigInt(n);
    }

    return mod;
}


Integer.secureRandomNumber = function() {
    const N = Curve.secp256k1.N;

    while (true) {
        const entropy = Utilities.getUuid() +
                       Utilities.getUuid() +
                       Utilities.getUuid() +
                       Date.now().toString();

        const hashBytes = Utilities.computeDigest(
            Utilities.DigestAlgorithm.SHA_256,
            entropy
        );

        const randNum = Integer._bytesToBigInt(hashBytes);

        if (randNum >= BigInt(1) && randNum < N) {
            return randNum;
        }
    }
};

Integer._bytesToBigInt = function(bytes) {
    let result = BigInt(0);
    for (let i = 0; i < bytes.length; i++) {
        result = (result << BigInt(8)) | BigInt(bytes[i] & 0xFF);
    }
    return result;
};

// Apps Script Byte[] parameters are Java signed bytes (-128..127); normalize
// unsigned 0..255 values (and re-normalize already-signed HMAC output) before
// handing them to computeHmacSignature.
Integer._toSignedBytes = function(bytes) {
    return bytes.map(function(byte) {
        return ((byte & 0xFF) ^ 0x80) - 0x80;
    });
};

Integer._hmacSha256 = function(key, value) {
    const signature = Utilities.computeHmacSignature(
        Utilities.MacAlgorithm.HMAC_SHA_256,
        Integer._toSignedBytes(value),
        Integer._toSignedBytes(key)
    );

    return Array.from(signature);
};

Integer._hexStringToBytes = function(hexString) {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return bytes;
};

// RFC 6979 deterministic nonce generator. Yields successive candidates in
// [1, N) so the caller can request a fresh k when a candidate produces a
// degenerate signature (r == 0 or s == 0). N and the octet length come from
// the key's curve rather than being fixed to secp256k1.
Integer.secureRandomNonce = function* (privateKeySecret, messageHashHex, curve) {
    const N = curve.N;
    const byteLength = curve.length();

    const x = Integer._bigIntToBytes(privateKeySecret, byteLength);
    const h1Number = Integer._bytesToBigInt(Integer._hexStringToBytes(messageHashHex));
    const h1 = Integer._bigIntToBytes(Integer.modulo(h1Number, N), byteLength);

    let K = new Array(byteLength).fill(0x00);
    let V = new Array(byteLength).fill(0x01);

    K = Integer._hmacSha256(K, Integer._bytesConcat(V, [0x00], x, h1));
    V = Integer._hmacSha256(K, V);
    K = Integer._hmacSha256(K, Integer._bytesConcat(V, [0x01], x, h1));
    V = Integer._hmacSha256(K, V);

    while (true) {
        V = Integer._hmacSha256(K, V);

        const nonce = Integer._bytesToBigInt(V);
        if (nonce >= BigInt(1) && nonce < N) {
            yield nonce;
        }

        K = Integer._hmacSha256(K, Integer._bytesConcat(V, [0x00]));
        V = Integer._hmacSha256(K, V);
    }
};

Integer._bigIntToBytes = function(num, length) {
    const bytes = [];
    for (let i = length - 1; i >= 0; i--) {
        bytes.push(Number((num >> BigInt(i * 8)) & BigInt(0xFF)));
    }
    return bytes;
};

Integer._bytesConcat = function(...arrays) {
    return [].concat(...arrays);
};