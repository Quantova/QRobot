// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qrobot/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = 1401;
const TYPES = Object.freeze(['register', 'conformity', 'commission', 'transfer', 'retire']);
const CLASSES = Object.freeze(['industrial', 'mobile', 'humanoid', 'surgical', 'agricultural', 'logistics', 'service', 'inspection']);
const AUTONOMY = Object.freeze(['teleoperated', 'assisted', 'supervised', 'conditional', 'high', 'full']);
const KEY_DOMAIN = Buffer.from('quantova/qrobot/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qrobot/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qrobot/anchor/1', 'ascii');
const UNIT_DOMAIN = Buffer.from('quantova/qrobot/unit/1', 'ascii');
const MAGIC = Buffer.from('QROB', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 200;
const NOTE_MAX = 1000;
const SERIAL_MAX = 120;
const MAX_MASS_G = 100000000000;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const SERIAL = /^[A-Za-z0-9][A-Za-z0-9 ./-]{0,119}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

const FIELDS = Object.freeze({
  register: ['robotId', 'robotClass', 'make', 'model', 'serial', 'autonomyLevel', 'massGrams', 'makerKeyId', 'makerLabel', 'registeredAt', 'note'],
  conformity: ['robotId', 'registerRef', 'standard', 'assessmentId', 'assessorKeyId', 'assessorLabel', 'assessedAt', 'note'],
  commission: ['robotId', 'priorRef', 'operatorKeyId', 'operatorLabel', 'site', 'commissionedAt', 'note'],
  transfer: ['robotId', 'priorRef', 'fromKeyId', 'toKeyId', 'toLabel', 'transferredAt', 'note'],
  retire: ['robotId', 'priorRef', 'holderKeyId', 'reason', 'retiredAt', 'note'],
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QROBOT_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QROBOT_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function unitRefOf(secret, serial) {
  if (!((ArrayBuffer.isView(secret) && secret instanceof Uint8Array)) || secret.length !== 32) reject('the unit secret is a 32 byte Uint8Array held by the maker');
  if (new Set(secret).size < 13) reject('a unit secret made of too few different byte values is refused, draw it from a secure random source');
  if (typeof serial !== 'string' || serial.length === 0 || serial.length > SERIAL_MAX) reject('the unit serial is 1 to ' + SERIAL_MAX + ' characters');
  if (!SERIAL.test(serial)) reject('the unit serial holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit');
  return sha3(UNIT_DOMAIN, Buffer.from([0]), Buffer.from(secret), Buffer.from(serial, 'utf8')).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' cannot be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function refProblem(value, what) {
  if (typeof value !== 'string' || !HEX32.test(value)) return what + ' must be 64 lowercase hex characters';
  return null;
}

function enumProblem(value, allowed, what) {
  if (typeof value !== 'string' || !allowed.includes(value)) return what + ' must be one of ' + allowed.join(', ');
  return null;
}

function intProblem(value, max, what) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) return what + ' must be a whole number of at least 1';
  if (value > max) return what + ' is larger than ' + max;
  return null;
}

function serialProblem(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > SERIAL_MAX) return 'serial is 1 to ' + SERIAL_MAX + ' characters';
  if (!SERIAL.test(value)) return 'serial holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit';
  return null;
}

function statementProblem(type, st) {
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  const fields = FIELDS[type];
  if (Object.keys(st).sort().join(',') !== fields.slice().sort().join(',')) return 'a ' + type + ' statement holds exactly ' + fields.join(', ');
  const checks = [];
  checks.push(pattern(st.robotId, HEX16, 'robotId', '32 lowercase hex characters'));
  checks.push(textProblem(st.note, NOTE_MAX, 'note', false));
  if (type === 'register') {
    checks.push(enumProblem(st.robotClass, CLASSES, 'robotClass'));
    checks.push(textProblem(st.make, LABEL_MAX, 'make', true));
    checks.push(textProblem(st.model, LABEL_MAX, 'model', true));
    checks.push(serialProblem(st.serial));
    checks.push(enumProblem(st.autonomyLevel, AUTONOMY, 'autonomyLevel'));
    checks.push(intProblem(st.massGrams, MAX_MASS_G, 'massGrams'));
    checks.push(pattern(st.makerKeyId, HEX32, 'makerKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.makerLabel, LABEL_MAX, 'makerLabel', false));
    checks.push(timeProblem(st.registeredAt, 'registeredAt'));
  } else if (type === 'conformity') {
    checks.push(refProblem(st.registerRef, 'registerRef'));
    checks.push(textProblem(st.standard, LABEL_MAX, 'standard', true));
    checks.push(pattern(st.assessmentId, HEX16, 'assessmentId', '32 lowercase hex characters'));
    checks.push(pattern(st.assessorKeyId, HEX32, 'assessorKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.assessorLabel, LABEL_MAX, 'assessorLabel', false));
    checks.push(timeProblem(st.assessedAt, 'assessedAt'));
  } else if (type === 'commission') {
    checks.push(refProblem(st.priorRef, 'priorRef'));
    checks.push(pattern(st.operatorKeyId, HEX32, 'operatorKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.operatorLabel, LABEL_MAX, 'operatorLabel', false));
    checks.push(textProblem(st.site, LABEL_MAX, 'site', true));
    checks.push(timeProblem(st.commissionedAt, 'commissionedAt'));
  } else if (type === 'transfer') {
    checks.push(refProblem(st.priorRef, 'priorRef'));
    checks.push(pattern(st.fromKeyId, HEX32, 'fromKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.toKeyId, HEX32, 'toKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.toLabel, LABEL_MAX, 'toLabel', false));
    checks.push(timeProblem(st.transferredAt, 'transferredAt'));
    if (!checks.some(Boolean) && st.fromKeyId === st.toKeyId) checks.push('the receiving key must differ from the sending key');
  } else {
    checks.push(refProblem(st.priorRef, 'priorRef'));
    checks.push(pattern(st.holderKeyId, HEX32, 'holderKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.reason, LABEL_MAX, 'reason', true));
    checks.push(timeProblem(st.retiredAt, 'retiredAt'));
  }
  return checks.find(Boolean) || null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type), hex(st.robotId)];
  if (type === 'register') {
    parts.push(ascii(st.robotClass), utf8(st.make), utf8(st.model), utf8(st.serial), ascii(st.autonomyLevel), u64(st.massGrams), hex(st.makerKeyId), utf8(st.makerLabel), ascii(st.registeredAt));
  } else if (type === 'conformity') {
    parts.push(hex(st.registerRef), utf8(st.standard), hex(st.assessmentId), hex(st.assessorKeyId), utf8(st.assessorLabel), ascii(st.assessedAt));
  } else if (type === 'commission') {
    parts.push(hex(st.priorRef), hex(st.operatorKeyId), utf8(st.operatorLabel), utf8(st.site), ascii(st.commissionedAt));
  } else if (type === 'transfer') {
    parts.push(hex(st.priorRef), hex(st.fromKeyId), hex(st.toKeyId), utf8(st.toLabel), ascii(st.transferredAt));
  } else {
    parts.push(hex(st.priorRef), hex(st.holderKeyId), utf8(st.reason), ascii(st.retiredAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(envelope.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof envelope.signer.id !== 'string' || !HEX32.test(envelope.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  let statement;
  try {
    statement = plainCopy(envelope.statement);
  } catch (e) {
    fail('the statement is not plain data');
  }
  const problem = statementProblem(envelope.type, statement);
  if (problem) fail(problem);
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { type: envelope.type, signerId: envelope.signer.id, publicKey, statement, signature, anchor };
}

function encoded(parsed) {
  return payload(parsed.type, parsed.statement);
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature);
}

module.exports = {
  FORMAT, ALGORITHM, KIND, TYPES, FIELDS, CLASSES, AUTONOMY, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX, SERIAL_MAX, MAX_MASS_G,
  sha3, keyIdOf, unitRefOf, textProblem, timeProblem, statementProblem, payload, encoded, parse, refOf, anchorDigest, reject, plainCopy,
};
