// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function registerUnit(key) {
  return Q.register({ key, robotClass: 'industrial', make: 'Quantova Robotics', model: 'QR 200', serial: 'QR 2026 0001', autonomyLevel: 'supervised', massGrams: 120000, makerLabel: 'Quantova Robotics' });
}

test('a registered unit is a well formed signed record of the manufacturer', () => {
  const maker = freshKey();
  const unit = registerUnit(maker);
  assert.strictEqual(unit.format, 'qrobot/1');
  assert.strictEqual(unit.type, 'register');
  assert.strictEqual(unit.algorithm, 'ML-DSA-65');
  assert.strictEqual(unit.signer.id, Q.keyId(maker));
  assert.strictEqual(unit.statement.makerKeyId, Q.keyId(maker));
  assert.match(unit.statement.robotId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(unit.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(unit.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the conformity, commission and transfer records chain to the same unit', () => {
  const maker = freshKey();
  const assessor = freshKey();
  const operator = freshKey();
  const buyer = freshKey();
  const unit = registerUnit(maker);
  const conf = Q.conformity({ key: assessor, register: unit, standard: 'ISO 10218-1 2025' });
  const live = Q.commission({ key: operator, record: unit, site: 'Plant 7 Line 3' });
  const moved = Q.transfer({ key: operator, record: live, to: Q.keyId(buyer), toLabel: 'Acme Automation Ltd' });
  assert.strictEqual(conf.statement.robotId, unit.statement.robotId);
  assert.strictEqual(conf.statement.registerRef, Q.recordRef(unit));
  assert.strictEqual(live.statement.priorRef, Q.recordRef(unit));
  assert.strictEqual(moved.statement.robotId, unit.statement.robotId);
  assert.strictEqual(moved.statement.fromKeyId, Q.keyId(operator));
  assert.strictEqual(moved.statement.toKeyId, Q.keyId(buyer));
  assert.strictEqual(moved.statement.priorRef, Q.recordRef(live));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const base = { key, robotClass: 'industrial', make: 'A', model: 'B', serial: 'A1', autonomyLevel: 'supervised', massGrams: 1 };
  assert.throws(() => Q.register(Object.assign({}, base, { robotClass: 'spaceship' })), /robotClass must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { autonomyLevel: 'sentient' })), /autonomyLevel must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { massGrams: 1.5 })), /massGrams must be a whole number/);
  assert.throws(() => Q.register(Object.assign({}, base, { massGrams: 100000000001 })), /massGrams is larger than/);
  assert.throws(() => Q.register(Object.assign({}, base, { serial: '' })), /serial is 1 to/);
  assert.throws(() => Q.register(Object.assign({}, base, { make: '' })), /make cannot be empty/);
  assert.throws(() => Q.register(Object.assign({}, base, { unknownField: 1 })), /is not an option of register/);
});

test('a transfer refuses a recipient equal to the sender', () => {
  const holder = freshKey();
  const unit = registerUnit(holder);
  assert.throws(() => Q.transfer({ key: holder, record: unit, to: Q.keyId(holder) }), /the receiving key must differ/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => registerUnit(new Uint8Array(16)), /32 byte Uint8Array seed/);
  assert.throws(() => registerUnit(new Uint8Array(32)), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const maker = freshKey();
  const unit = registerUnit(maker);
  const ok = await Q.verify(unit, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'register');
  assert.strictEqual(ok.robotId, unit.statement.robotId);
  const wrongType = await Q.verify(unit, { type: 'conformity', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(unit, { type: 'register', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const maker = freshKey();
  const unit = registerUnit(maker);
  const forged = JSON.parse(JSON.stringify(unit));
  forged.statement.massGrams = forged.statement.massGrams + 1;
  const r = await Q.verify(forged, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a record to the record before it', async () => {
  const maker = freshKey();
  const operator = freshKey();
  const unit = registerUnit(maker);
  const live = Q.commission({ key: operator, record: unit, site: 'Plant 7 Line 3' });
  const good = await Q.verify(live, { type: 'commission', network: 'testnet', requireAnchor: false, strict: false, prior: unit });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherUnit = registerUnit(maker);
  const bad = await Q.verify(live, { type: 'commission', network: 'testnet', requireAnchor: false, strict: false, prior: otherUnit });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('unitRef is deterministic for the same secret and serial and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.unitRef(secret, 'QR 2026 0001');
  const b = Q.unitRef(secret, 'QR 2026 0001');
  const c = Q.unitRef(secret, 'QR 2026 0002');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the robotics line', () => {
  assert.strictEqual(Q.KIND, 1401);
  assert.strictEqual(Q.FORMAT, 'qrobot/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'conformity', 'commission', 'transfer', 'retire']);
  assert.deepStrictEqual([...Q.CLASSES], ['industrial', 'mobile', 'humanoid', 'surgical', 'agricultural', 'logistics', 'service', 'inspection']);
});
