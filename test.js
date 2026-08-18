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
    console.log(privateKeyPem)
    console.log(publicKeyPem)
    console.log(signature)
    throw new Error("bad")
  }
}

// PHASE 1 TESTS: CSPRNG Local Implementation

function testPhase1_UniqueRandomNumbers() {
  const N = Integer._secp256k1_N;
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
  const N = Integer._secp256k1_N;
  const buckets = 10;
  const samplesPerBucket = 100;
  const counts = Array(buckets).fill(0);
  const bucketSize = N / BigInt(buckets);
  for (let i = 0; i < samplesPerBucket * buckets; i++) {
    const num = Integer.secureRandomNumber();
    const bucketIndex = Number(num / bucketSize);
    if (bucketIndex >= 0 && bucketIndex < buckets) {
      counts[bucketIndex]++;
    }
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

function runAllTests() {
  console.log("RUNNING ALL TESTS:");
  try {
    runAllPhase1Tests();
    runAllPhase2Tests();
    console.log("✅ ALL TESTS PASSED (7/7)");
    return true;
  } catch (e) {
    console.log("❌ TESTS FAILED: " + e.message);
    throw e;
  }
}
