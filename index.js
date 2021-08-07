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

/**
 * Encrypts data with AES-256-GCM.
 * @param {Uint8Array} rawKey 32-byte (256-bit) key.
 * @param {Uint8Array} iv 12-byte IV.
 * @param {Uint8Array} data Data to encrypt.
 * @returns {Promise<Uint8Array>} Ciphertext.
 */
exports.encryptAesGcm = async (rawKey, iv, data) => {
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
    const buffer = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
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
exports.decryptAesGcm = async (rawKey, iv, ciphertext) => {
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
    const dataBuffer = await webcrypto.subtle.encrypt({
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

/**
 * Computes SHA-256 digest of message.
 * @param {Uint8Array} data Message to digest.
 * @returns {Promise<Uint8Array>} SHA-256 digest of the message.
 */
exports.sha256 = async (data) => {
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
exports.sha256Hmac = async (data, rawKey) => {
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
