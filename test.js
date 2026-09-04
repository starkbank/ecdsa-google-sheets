// Original test - backward compatibility
function test() {
  let keys = easyMake();
  let privateKeyPem = keys[0];
  let publicKeyPem = keys[1];

  let message = "mas que bela batata!";
  let nessage = "mas que belas batatas!";
  let signature = easySign(message, privateKeyPem);

  let right = easyVerify(message, signature, publicKeyPem);
  let wrong = easyVerify(nessage, signature, publicKeyPem);

  console.log("right: " + right);
  console.log("wrong: " + wrong);

  if (wrong || !right) {
    throw new Error(`backward-compat sign/verify failed (right=${right}, wrong=${wrong})`)
  }
}

// PHASE 1 TESTS: CSPRNG Local Implementation

function testPhase1_UniqueRandomNumbers() {
  const N = Curve.secp256k1.N;
  const numbers = new Set();
  const count = 100;
  for (let i = 0; i < count; i++) {
    const num = Integer.secureRandomNumber();
    if (num <= BigInt(0) || num >= N) {
      throw new Error(`Random number out of range: ${num}`);
    }
    numbers.add(num.toString());
  }
  if (numbers.size !== count) {
    throw new Error(`Expected ${count} unique numbers, got ${numbers.size}`);
  }
  console.log("✅ Test 1.4.1 PASSED");
}

function testPhase1_UniformDistribution() {
  const N = Curve.secp256k1.N;
  const buckets = 10;
  const samplesPerBucket = 100;
  const counts = Array(buckets).fill(0);
  const bucketSize = N / BigInt(buckets);
  for (let i = 0; i < samplesPerBucket * buckets; i++) {
    const num = Integer.secureRandomNumber();
    const rawIndex = Number(num / bucketSize);
    if (rawIndex < 0) {
      throw new Error(`Random number out of range: ${num}`);
    }
    // N is not divisible by buckets, so the top few values land at rawIndex ==
    // buckets; fold them into the last bucket instead of silently dropping them.
    counts[Math.min(rawIndex, buckets - 1)]++;
  }
  const expectedCount = samplesPerBucket;
  for (let i = 0; i < buckets; i++) {
    const variance = Math.abs(counts[i] - expectedCount) / expectedCount;
    if (variance > 0.5) {
      throw new Error(`Bucket ${i} variance too high: ${(variance * 100).toFixed(1)}%`);
    }
  }
  console.log("✅ Test 1.4.2 PASSED");
}

function testPhase1_PrivateKeyGeneration() {
  const keys = easyMake();
  const privateKeyPem = keys[0];
  const publicKeyPem = keys[1];
  if (!privateKeyPem || !publicKeyPem) {
    throw new Error("Failed to generate keys");
  }
  const message = "test message for phase 1";
  const signature = easySign(message, privateKeyPem);
  const verified = easyVerify(message, signature, publicKeyPem);
  if (!verified) {
    throw new Error("Signature verification failed");
  }
  console.log("✅ Test 1.4.3 PASSED");
}

function testPhase1_BackwardCompatibility() {
  try {
    test();
    console.log("✅ Test 1.4.4 PASSED");
  } catch (e) {
    throw new Error(`Backward compatibility broken: ${e.message}`);
  }
}

function runAllPhase1Tests() {
  console.log("PHASE 1 TESTS:");
  try {
    testPhase1_UniqueRandomNumbers();
    testPhase1_UniformDistribution();
    testPhase1_PrivateKeyGeneration();
    testPhase1_BackwardCompatibility();
    console.log("✅ ALL PHASE 1 TESTS PASSED (4/4)");
    return true;
  } catch (e) {
    console.log("❌ PHASE 1 TEST FAILED: " + e.message);
    throw e;
  }
}

function testPhase2_RFC6979Determinism() {
  const keys = easyMake();
  const privateKeyPem = keys[0];
  const message = "deterministic test message";
  const signature1 = easySign(message, privateKeyPem);
  const signature2 = easySign(message, privateKeyPem);
  if (signature1 !== signature2) {
    throw new Error("Signatures differ for same input");
  }
  console.log("✅ Test 2.3.1 PASSED");
}

function testPhase2_DifferentMessages() {
  const keys = easyMake();
  const privateKeyPem = keys[0];
  const message1 = "message number 1";
  const message2 = "message number 2";
  const signature1 = easySign(message1, privateKeyPem);
  const signature2 = easySign(message2, privateKeyPem);
  if (signature1 === signature2) {
    throw new Error("Different messages produced same signature");
  }
  console.log("✅ Test 2.3.2 PASSED");
}

function testPhase2_VerificationWorks() {
  const keys = easyMake();
  const privateKeyPem = keys[0];
  const publicKeyPem = keys[1];
  const message = "verification test for rfc 6979";
  const signature = easySign(message, privateKeyPem);
  const verified = easyVerify(message, signature, publicKeyPem);
  if (!verified) {
    throw new Error("Signature verification failed");
  }
  const signature2 = easySign(message, privateKeyPem);
  const verified2 = easyVerify(message, signature2, publicKeyPem);
  if (!verified2) {
    throw new Error("Second signature verification failed");
  }
  if (signature !== signature2) {
    throw new Error("Signatures differ for same input");
  }
  console.log("✅ Test 2.3.3 PASSED");
}

function runAllPhase2Tests() {
  console.log("PHASE 2 TESTS:");
  try {
    testPhase2_RFC6979Determinism();
    testPhase2_DifferentMessages();
    testPhase2_VerificationWorks();
    console.log("✅ ALL PHASE 2 TESTS PASSED (3/3)");
    return true;
  } catch (e) {
    console.log("❌ PHASE 2 TEST FAILED: " + e.message);
    throw e;
  }
}

// PHASE 3 TESTS: verify() must reject bad input, not accept or throw on it

function testPhase3_RejectsOutOfRangeRS() {
  const keys = easyMake();
  const publicKey = PublicKey.fromPem(keys[1]);
  const N = Curve.secp256k1.N;
  const message = "range check message";
  const good = sign(message, PrivateKey.fromPem(keys[0]));
  const badValues = [BigInt(0), N];
  for (let i = 0; i < badValues.length; i++) {
    if (verify(message, new Signature(badValues[i], good.s), publicKey)) {
      throw new Error(`verify accepted out-of-range r=${badValues[i]}`);
    }
    if (verify(message, new Signature(good.r, badValues[i]), publicKey)) {
      throw new Error(`verify accepted out-of-range s=${badValues[i]}`);
    }
  }
  console.log("✅ Test 3.1 PASSED");
}

function testPhase3_RejectsMalformedSignature() {
  const keys = easyMake();
  const message = "malformed signature message";
  const malformed = ["", "not-base64!!!", "AAAA", Utilities.base64Encode([0x02, 0x01, 0x01])];
  for (let i = 0; i < malformed.length; i++) {
    let result;
    try {
      result = easyVerify(message, malformed[i], keys[1]);
    } catch (e) {
      throw new Error(`easyVerify threw instead of returning false: ${e.message}`);
    }
    if (result !== false) {
      throw new Error(`easyVerify did not reject malformed input: ${malformed[i]}`);
    }
  }
  console.log("✅ Test 3.2 PASSED");
}

function testPhase3_RejectsForgedInfinity() {
  const keys = easyMake();
  const privateKey = PrivateKey.fromPem(keys[0]);
  const publicKey = PublicKey.fromPem(keys[1]);
  const N = publicKey.curve.N;
  const message = "forged infinity message";
  // With s = 1 and r = -h * d^-1 mod N, verify computes u1 = -u2, so
  // u1 + u2 is the point at infinity. verify() must return false, not throw.
  const h = BinaryAscii.numberFromHex(hash(message));
  const r = Integer.modulo(-h * EcdsaMath.inv(privateKey.secret, N), N);
  const s = BigInt(1);
  if (r < BigInt(1) || r >= N) {
    throw new Error("could not craft an in-range forged r");
  }
  let result;
  try {
    result = verify(message, new Signature(r, s), publicKey);
  } catch (e) {
    throw new Error(`verify threw on forged point-at-infinity signature: ${e.message}`);
  }
  if (result !== false) {
    throw new Error("verify accepted a forged point-at-infinity signature");
  }
  console.log("✅ Test 3.3 PASSED");
}

function runAllPhase3Tests() {
  console.log("PHASE 3 TESTS:");
  try {
    testPhase3_RejectsOutOfRangeRS();
    testPhase3_RejectsMalformedSignature();
    testPhase3_RejectsForgedInfinity();
    console.log("✅ ALL PHASE 3 TESTS PASSED (3/3)");
    return true;
  } catch (e) {
    console.log("❌ PHASE 3 TEST FAILED: " + e.message);
    throw e;
  }
}

function runAllTests() {
  console.log("RUNNING ALL TESTS:");
  try {
    runAllPhase1Tests();
    runAllPhase2Tests();
    runAllPhase3Tests();
    console.log("✅ ALL TESTS PASSED (10/10)");
    return true;
  } catch (e) {
    console.log("❌ TESTS FAILED: " + e.message);
    throw e;
  }
}
