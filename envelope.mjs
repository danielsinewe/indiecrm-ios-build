import { createCipheriv, createDecipheriv, createHash, publicEncrypt, privateDecrypt, randomBytes, constants } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const MAGIC = Buffer.from('ICCLOUD1\n');
const MAX = 512 * 1024 * 1024;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function requireValue(value, message) { if (!value) throw new Error(message); }
export function symmetricKey(value) {
  requireValue(typeof value === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(value), 'Invalid input encryption key.');
  const key = Buffer.from(value, 'base64');
  requireValue(key.length === 32, 'Invalid input encryption key.');
  return key;
}
export function seal(bytes, context, { key, publicKey } = {}) {
  requireValue(Buffer.isBuffer(bytes) && bytes.length <= MAX, 'Payload exceeds the transfer limit.');
  requireValue(Boolean(key) !== Boolean(publicKey), 'Select one encryption recipient.');
  const actualKey = key ? Buffer.from(key) : randomBytes(32);
  requireValue(actualKey.length === 32, 'Invalid encryption key.');
  const iv = randomBytes(12);
  const header = { version: 1, algorithm: publicKey ? 'RSA-OAEP-256+A256GCM' : 'A256GCM',
    context, iv: iv.toString('base64'), plaintextSha256: hash(bytes), plaintextSize: bytes.length };
  if (publicKey) header.wrappedKey = publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, actualKey).toString('base64');
  const aad = Buffer.from(JSON.stringify(header));
  requireValue(aad.length <= 16384, 'Transfer header exceeds limit.');
  const cipher = createCipheriv('aes-256-gcm', actualKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  const size = Buffer.alloc(4); size.writeUInt32BE(aad.length);
  actualKey.fill(0);
  return Buffer.concat([MAGIC, size, aad, ciphertext, cipher.getAuthTag()]);
}
export function open(envelope, { key, privateKey, expectedContext } = {}) {
  try {
    requireValue(envelope.length > MAGIC.length + 20 && envelope.length <= MAX + 32768 && envelope.subarray(0, MAGIC.length).equals(MAGIC), 'Invalid envelope.');
    const length = envelope.readUInt32BE(MAGIC.length);
    requireValue(length > 0 && length <= 16384 && envelope.length >= MAGIC.length + 4 + length + 16, 'Invalid header.');
    const start = MAGIC.length + 4;
    const aad = envelope.subarray(start, start + length);
    const header = JSON.parse(aad);
    requireValue(header.version === 1 && header.plaintextSize >= 0 && header.plaintextSize <= MAX, 'Invalid envelope identity.');
    if (expectedContext) requireValue(isDeepStrictEqual(header.context, expectedContext), 'Context mismatch.');
    let actualKey;
    if (header.algorithm === 'A256GCM') { requireValue(key && !privateKey, 'Wrong recipient.'); actualKey = Buffer.from(key); }
    else if (header.algorithm === 'RSA-OAEP-256+A256GCM') {
      requireValue(privateKey && !key, 'Wrong recipient.');
      actualKey = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(header.wrappedKey, 'base64'));
    } else throw new Error('Unknown encryption algorithm.');
    requireValue(actualKey.length === 32, 'Wrong key size.');
    const iv = Buffer.from(header.iv, 'base64'); requireValue(iv.length === 12, 'Invalid IV.');
    const decipher = createDecipheriv('aes-256-gcm', actualKey, iv);
    decipher.setAAD(aad); decipher.setAuthTag(envelope.subarray(-16));
    const bytes = Buffer.concat([decipher.update(envelope.subarray(start + length, -16)), decipher.final()]);
    actualKey.fill(0);
    requireValue(bytes.length === header.plaintextSize && hash(bytes) === header.plaintextSha256, 'Invalid plaintext.');
    return { bytes, header };
  } catch { throw new Error('Encrypted transfer authentication failed.'); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [mode, input, output, contextPath, keyPath] = process.argv.slice(2);
    if (mode === 'open-input') {
      const expectedContext = JSON.parse(await readFile(contextPath, 'utf8'));
      const result = open(await readFile(input), { key: symmetricKey(process.env.IC_INPUT_KEY), expectedContext });
      await writeFile(output, result.bytes, { mode: 0o600, flag: 'wx' });
    } else if (mode === 'seal-output') {
      const context = JSON.parse(await readFile(contextPath, 'utf8'));
      const result = seal(await readFile(input), context, { publicKey: await readFile(keyPath, 'utf8') });
      await writeFile(output, result, { mode: 0o600, flag: 'wx' });
    } else throw new Error('Invalid transfer command.');
    console.log('Authenticated encrypted transfer complete.');
  } catch { console.error('Encrypted transfer failed; no plaintext was published.'); process.exitCode = 1; }
}
