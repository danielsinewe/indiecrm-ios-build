import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { seal, open, symmetricKey } from './envelope.mjs';
const bytes = Buffer.from('private source and encrypted build diagnostics');
const context = { sourceSha: 'a'.repeat(40), build: '18', kind: 'ios-build-input' };
test('symmetric transfer authenticates complete context, ciphertext and plaintext identity', () => {
  const key = randomBytes(32), data = seal(bytes, context, { key });
  assert.ok(!data.includes(bytes));
  assert.deepEqual(open(data, { key, expectedContext: context }).bytes, bytes);
  assert.deepEqual(open(data, { key, expectedContext: {kind:context.kind,build:context.build,sourceSha:context.sourceSha} }).bytes, bytes);
  assert.throws(() => open(data, { key: randomBytes(32) }), /authentication failed/);
  assert.throws(() => open(data, { key, expectedContext: { ...context, build: '19' } }), /authentication failed/);
  for (const offset of [0, 12, data.length - 20, data.length - 1]) {
    const altered = Buffer.from(data); altered[offset] ^= 1;
    assert.throws(() => open(altered, { key }), /authentication failed/);
  }
});
test('output decrypts only for the private cloud recipient and differs each time', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const data = seal(bytes, context, { publicKey });
  assert.deepEqual(open(data, { privateKey, expectedContext: context }).bytes, bytes);
  assert.notDeepEqual(seal(bytes, context, { publicKey }), data);
  assert.throws(() => open(data, { key: randomBytes(32) }), /authentication failed/);
  const wrong = generateKeyPairSync('rsa', { modulusLength: 3072 });
  assert.throws(() => open(data, { privateKey: wrong.privateKey }), /authentication failed/);
});
test('invalid key and recipient selection fail without retaining private input', () => {
  assert.throws(() => symmetricKey('private-invalid'), /Invalid input encryption key/);
  assert.throws(() => seal(bytes, context, {}), /one encryption recipient/);
  assert.equal(symmetricKey(randomBytes(32).toString('base64')).length, 32);
});
