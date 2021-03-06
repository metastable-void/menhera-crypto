/* vim: set ts=2 sw=2 et ai : */
/*
  menhera-crypto
  Copyright (C) 2021 Menhera.org developers.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  @license Apache-2.0
*/

const webcrypto = globalThis.crypto && crypto.getRandomValues && crypto.subtle && crypto;
const nodecrypto = webcrypto ? null : require('crypto');
const { sidh } = require('sidh');
const { sphincs } = require('sphincs');

const curve25519 = require('curve25519-js');
const ed = require('@noble/ed25519');

exports.utils = {};
const compareUint8Array = (buffer1, buffer2) => {
  if (buffer1.length != buffer2.length || buffer1.byteLength != buffer2.byteLength) {
    return false;
  }
  let result = true;
  for (let i = 0; i < buffer1.length; i++) {
    result = result && buffer1[i] == buffer2[i];
  }
  return result;
}
exports.utils.compareUint8Array = compareUint8Array;

const getRandomValues = (byteLength) => {
  const buffer = new Uint8Array(0 | byteLength);
  if (webcrypto) {
    webcrypto.getRandomValues(buffer);
  } else {
    nodecrypto.randomFillSync(buffer);
  }
  return buffer;
};
exports.utils.getRandomValues = getRandomValues;

exports.AesGcm = {};
/**
 * Encrypts data with AES-256-GCM.
 * @param {Uint8Array} rawKey 32-byte (256-bit) key.
 * @param {Uint8Array} iv 12-byte IV.
 * @param {Uint8Array} data Data to encrypt.
 * @returns {Promise<Uint8Array>} Ciphertext.
 */
exports.AesGcm.encrypt = async (rawKey, iv, data) => {
  if (!(rawKey instanceof Uint8Array)) {
    throw new TypeError('rawKey must be of Uint8Array type.');
  }
  if (!(iv instanceof Uint8Array)) {
    throw new TypeError('iv must be of Uint8Array type.');
  }
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('data must be of Uint8Array type.');
  }
  if (rawKey.length != 32) {
    throw new TypeError('Invalid key length (!= 32)');
  }
  if (iv.length != 12) {
    throw new TypeError('Invalid iv length (!= 12)');
  }
  if (webcrypto) {
    // Web browsers
    const key = await webcrypto.subtle.importKey('raw', rawKey, {
      name: 'AES-GCM',
    }, false, [
      'encrypt',
      'decrypt',
    ]);
    const cipherBuffer = await webcrypto.subtle.encrypt({
      name: 'AES-GCM',
      iv,
    }, key, data);
    return new Uint8Array(cipherBuffer);
  } else {
    // Node.JS
    const cipher = nodecrypto.createCipheriv('aes-256-gcm', rawKey, iv);
    const buffer1 = cipher.update(data);
    const buffer2 = cipher.final();
    const buffer3 = cipher.getAuthTag();
    const buffer = Buffer.concat([buffer1, buffer2, buffer3]);
    return new Uint8Array(buffer.buffer);
  }
};

/**
 * Decrypts data with AES-256-GCM.
 * @param {Uint8Array} rawKey 32-byte (256-bit) key.
 * @param {Uint8Array} iv 12-byte IV.
 * @param {Uint8Array} ciphertext Ciphertext to decrypt.
 * @returns {Promise<Uint8Array>} Decrypted data.
 */
exports.AesGcm.decrypt = async (rawKey, iv, ciphertext) => {
  if (!(rawKey instanceof Uint8Array)) {
    throw new TypeError('rawKey must be of Uint8Array type.');
  }
  if (!(iv instanceof Uint8Array)) {
    throw new TypeError('iv must be of Uint8Array type.');
  }
  if (!(ciphertext instanceof Uint8Array)) {
    throw new TypeError('data must be of Uint8Array type.');
  }
  if (rawKey.length != 32) {
    throw new TypeError('Invalid key length (!= 32)');
  }
  if (iv.length != 12) {
    throw new TypeError('Invalid iv length (!= 12)');
  }
  if (ciphertext.length < 16) {
    throw new TypeError('Invalid ciphertext length (< 16)');
  }
  if (webcrypto) {
    // Web browsers
    const key = await webcrypto.subtle.importKey('raw', rawKey, {
      name: 'AES-GCM',
    }, false, [
      'encrypt',
      'decrypt',
    ]);
    const dataBuffer = await webcrypto.subtle.decrypt({
      name: 'AES-GCM',
      iv,
    }, key, ciphertext);
    return new Uint8Array(dataBuffer);
  } else {
    // Node.JS
    const decipher = nodecrypto.createDecipheriv('aes-256-gcm', rawKey, iv);
    decipher.setAuthTag(ciphertext.slice(-16));
    const buffer = Buffer.concat([decipher.update(ciphertext.slice(0, -16)), decipher.final()]);
    return new Uint8Array(buffer.buffer);
  }
};

exports.Sha256 = {};
/**
 * Computes SHA-256 digest of message.
 * @param {Uint8Array} data Message to digest.
 * @returns {Promise<Uint8Array>} SHA-256 digest of the message.
 */
exports.Sha256.hash = async (data) => {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('data must be of Uint8Array type');
  }
  if (webcrypto) {
    // Web browsers
    const buffer = await webcrypto.subtle.digest('SHA-256', data);
    return new Uint8Array(buffer);
  } else {
    // Node.JS
    const hash = nodecrypto.createHash('sha256');
    hash.update(data);
    const buffer = hash.digest();
    return new Uint8Array(buffer.buffer);
  }
};

/**
 * Computes HMAC-SHA-256 signature of message.
 * @param {Uint8Array} data Message to sign.
 * @param {Uint8Array} rawKey Common key used for signature.
 * @returns {Promise<Uint8Array>} HMAC-SHA-256 signature of the message.
 */
exports.Sha256.hmac = async (data, rawKey) => {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('data must be of Uint8Array type');
  }
  if (!(rawKey instanceof Uint8Array)) {
    throw new TypeError('rawKey must be of Uint8Array type');
  }
  if (webcrypto) {
    // Web browsers
    const key = await webcrypto.subtle.importKey('raw', rawKey, {
      name: 'HMAC',
      hash: {
        name: 'SHA-256',
      },
    }, false, [
      'sign',
      'verify',
    ]);
    const buffer = await webcrypto.subtle.sign('HMAC', key, data);
    return new Uint8Array(buffer);
  } else {
    // Node.JS
    const hmac = nodecrypto.createHmac('sha256', rawKey);
    hmac.update(data);
    const buffer = hmac.digest();
    return new Uint8Array(buffer.buffer);
  }
};

exports.Sike = {};
/**
 * Generates a SIKE key pair.
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
exports.Sike.generateKeyPair = async () => {
  const {privateKey, publicKey} = await sidh.keyPair();
  return {privateKey, publicKey};
};

/**
 * Computes the shared secret for the given keys.
 * @param {Uint8Array} privateKey 
 * @param {Uint8Array} publicKey 
 * @returns {Promise<Uint8Array>}
 */
exports.Sike.computeSharedSecret = async (privateKey, publicKey) => {
  return await sidh.secret(publicKey, privateKey);
};

exports.Sphincs = {};
/**
 * Generates a SPHINCS key pair.
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
exports.Sphincs.generateKeyPair = async () => {
  const {privateKey, publicKey} = await sphincs.keyPair();
  return {privateKey, publicKey};
};

/**
 * Signs a message with the given secret key.
 * @param {Uint8Array} privateKey 
 * @param {Uint8Array} message 
 * @returns {Promise<Uint8Array>} signature
 */
exports.Sphincs.sign = async (privateKey, message) => {
  const signature = await sphincs.signDetached(message, privateKey);
  return signature;
};

/**
 * Verifies a signature against a message with the given public key.
 * @param {Uint8Array} publicKey 
 * @param {Uint8Array} message 
 * @param {Uint8Array} signature 
 * @returns {Promise<boolean>} result
 */
exports.Sphincs.verify = async (publicKey, message, signature) => {
  return await sphincs.verifyDetached(signature, message, publicKey);
};

exports.Curve25519 = {};
/**
 * Generates a Curve25519 key pair.
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
exports.Curve25519.generateKeyPair = async () => {
  const seed = getRandomValues(32);
  const {private, public} = curve25519.generateKeyPair(seed);
  return {privateKey: private, publicKey: public};
};

/**
 * Computes a Curve25519 shared secret from the given keys.
 * @param {Uint8Array} privateKey 
 * @param {Uint8Array} publicKey 
 * @returns {Promise<Uint8Array>}
 */
exports.Curve25519.computeSharedSecret = async (privateKey, publicKey) => {
  return curve25519.sharedKey(privateKey, publicKey);
};

exports.Ed25519 = {};
/**
 * Generates an Ed25519 key pair.
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array}>}
 */
exports.Ed25519.generateKeyPair = async () => {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKey(privateKey);
  return {privateKey, publicKey};
};

/**
 * Signs a message with a Ed25519 private key.
 * @param {Uinr8Array} privateKey 
 * @param {Uint8Array} message 
 * @returns {Promise<Uint8Array>}
 */
exports.Ed25519.sign = async (privateKey, message) => {
  return await ed.sign(message, privateKey);
};

/**
 * Verifies a signature against a message with the given public key.
 * @param {Uint8Array} publicKey 
 * @param {Uint8Array} message 
 * @param {Uint8Array} signature 
 * @returns {Promise<boolean>}
 */
exports.Ed25519.verify = async (publicKey, message, signature) => {
  return await ed.verify(signature, message, publicKey);
};
