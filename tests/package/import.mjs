import assert from 'node:assert/strict';
import { randomFillSync } from 'node:crypto';

const jose = await import('@josesuite/node');

for (const name of [
  'getCapabilityReport',
  'signCompact',
  'verifyCompact',
  'encryptCompact',
  'decryptCompact',
  'decryptJson',
  'importKeyBytes',
]) {
  assert.equal(typeof jose[name], 'function', `${name} is not exported from the built package`);
}

assert.equal(jose.getCapabilityReport().specificationVersion, '1.0.11');

const secret = Buffer.alloc(32, 7).toString('base64url');
const rawJwk = new TextEncoder().encode(JSON.stringify({ kty: 'oct', k: secret }));
const signing = jose.importKeyBytes(rawJwk, { algorithm: 'HS256', operation: 'sign' });
const verifying = jose.importKeyBytes(rawJwk, { algorithm: 'HS256', operation: 'verify' });
assert.equal(signing.ok, true);
assert.equal(verifying.ok, true);
const created = await jose.signCompact(new TextEncoder().encode('package boundary'), {
  policy: jose.AlgorithmPolicy.create('jws', ['HS256'], 'create'),
  key: signing.key,
  limits: jose.LIMITS_V1,
});
assert.equal(created.ok, true);
const verified = await jose.verifyCompact(created.token, {
  policy: jose.AlgorithmPolicy.create('jws', ['HS256'], 'receive'),
  key: verifying.key,
  principalId: 'package-test',
  limits: jose.LIMITS_V1,
});
assert.equal(verified.ok, true);

const wrapping = jose.importKeyBytes(rawJwk, {
  algorithm: 'A256KW',
  operation: 'wrapKey',
  contentAlgorithms: ['A128GCM'],
});
const unwrapping = jose.importKeyBytes(rawJwk, {
  algorithm: 'A256KW',
  operation: 'unwrapKey',
  contentAlgorithms: ['A128GCM'],
});
assert.equal(wrapping.ok, true);
assert.equal(unwrapping.ok, true);
const encrypted = await jose.encryptJson(new TextEncoder().encode('package JWE boundary'), {
  keyPolicy: jose.AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'create'),
  contentPolicy: jose.AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'create'),
  contentAlgorithm: 'A128GCM',
  recipients: [{ key: wrapping.key }],
  random: { randomBytes: (length) => ({ ok: true, value: randomFillSync(new Uint8Array(length)) }) },
  nonceAllocator: {
    reserve: async () => ({ ok: true, reservation: { nonce: randomFillSync(new Uint8Array(12)) } }),
  },
  limits: jose.LIMITS_V1,
});
assert.equal(encrypted.ok, true, JSON.stringify(encrypted));
const decrypted = await jose.decryptJson(new TextEncoder().encode(encrypted.value), {
  keyPolicy: jose.AlgorithmPolicy.create('jwe_alg', ['A256KW'], 'receive'),
  contentPolicy: jose.AlgorithmPolicy.create('jwe_enc', ['A128GCM'], 'receive'),
  recipients: [{ principalId: 'package-test', key: unwrapping.key }],
  principalId: 'package-test',
  limits: jose.LIMITS_V1,
});
assert.equal(decrypted.ok, true, JSON.stringify(decrypted));
assert.equal(new TextDecoder().decode(decrypted.plaintext), 'package JWE boundary');

assert.equal(
  jose.importKeyBytes(new TextEncoder().encode('{"kty":"oct","k":"a","k":"b"}'), {
    algorithm: 'HS256',
    operation: 'verify',
  }).ok,
  false,
);

await assert.rejects(
  import('@josesuite/node/internal/json/parse'),
  (error) => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
);
