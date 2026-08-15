'use strict';

const crypto = require('crypto');

// NIST P-256
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = -3n;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function inv(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

function double(pt) {
  if (pt === null) return null;
  const [x, y] = pt;
  if (y === 0n) return null;
  const l = mod((3n * x * x + A) * inv(2n * y, P), P);
  const nx = mod(l * l - 2n * x, P);
  return [nx, mod(l * (x - nx) - y, P)];
}

function add(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2) return mod(y1 + y2, P) === 0n ? null : double(p1);
  const l = mod((y2 - y1) * inv(x2 - x1, P), P);
  const nx = mod(l * l - x1 - x2, P);
  return [nx, mod(l * (x1 - nx) - y1, P)];
}

function mul(k, pt) {
  let acc = null;
  let cur = pt;
  let n = mod(k, N);
  while (n > 0n) {
    if (n & 1n) acc = add(acc, cur);
    cur = double(cur);
    n >>= 1n;
  }
  return acc;
}

const G = [GX, GY];

function hashToInt(message) {
  const digest = crypto.createHash('sha256').update(message, 'utf8').digest('hex');
  return mod(BigInt('0x' + digest), N);
}

function hex64(value) {
  return value.toString(16).padStart(64, '0');
}

// ---------------------------------------------------------------------------
// 영수증 서명에 쓰는 일회용 값.
// 발행 일련번호마다 새로 뽑되, 상위 비트는 쓰지 않는다.
// ---------------------------------------------------------------------------
const NONCE_BITS = 248;
const NONCE_MASK = (1n << BigInt(NONCE_BITS)) - 1n;

function nonceFor(secret, label) {
  const mac = crypto.createHmac('sha256', secret)
    .update(String(label), 'utf8')
    .digest('hex');
  const k = (BigInt('0x' + mac) & NONCE_MASK) % N;
  return k === 0n ? 1n : k;
}

function sign(privateKey, nonceSecret, message, label) {
  const e = hashToInt(message);
  const k = nonceFor(nonceSecret, label);
  const R = mul(k, G);
  const r = mod(R[0], N);
  const s = mod(inv(k, N) * (e + r * privateKey), N);
  return { r: hex64(r), s: hex64(s) };
}

function verify(publicKey, message, r, s) {
  let ri;
  let si;
  try {
    ri = BigInt('0x' + r);
    si = BigInt('0x' + s);
  } catch (err) {
    return false;
  }
  if (ri <= 0n || ri >= N || si <= 0n || si >= N) return false;
  const e = hashToInt(message);
  const w = inv(si, N);
  const point = add(mul(mod(e * w, N), G), mul(mod(ri * w, N), publicKey));
  if (point === null) return false;
  return mod(point[0], N) === ri;
}

// 시드에서 결정적으로 키를 만든다.
// 컨테이너가 재시작돼도 같은 키가 나와야, 참가자가 이미 복구해 둔
// 개인키가 무효가 되지 않는다.
function keypairFromSeed(seed) {
  const mac = crypto.createHmac('sha256', seed)
    .update('murthehelp-issuer-key', 'utf8')
    .digest('hex');
  let d = mod(BigInt('0x' + mac), N);
  if (d === 0n) d = 1n;
  return { d, Q: mul(d, G) };
}

function nonceSecretFromSeed(seed) {
  return crypto.createHmac('sha256', seed)
    .update('murthehelp-nonce-secret', 'utf8')
    .digest();
}

function keypair() {
  let d;
  do {
    d = mod(BigInt('0x' + crypto.randomBytes(32).toString('hex')), N);
  } while (d === 0n);
  return { d, Q: mul(d, G) };
}

module.exports = { sign, verify, keypair, keypairFromSeed, nonceSecretFromSeed, hex64, N, G, mul, mod, inv };