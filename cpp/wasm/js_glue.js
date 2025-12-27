/**
 * JavaScript glue code for Turnkey Client WASM
 *
 * Provides implementations for imported functions:
 * - js_fetch: HTTP requests using fetch API
 * - js_sign_message: ECDSA P-256 signature generation
 * - js_sha256: SHA-256 hashing
 */

// Crypto utilities using Web Crypto API
const crypto = globalThis.crypto || require('crypto').webcrypto;

/**
 * SHA-256 hash function
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} - 32-byte hash
 */
async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * ECDSA P-256 signature generation
 * @param {string} message - Message to sign
 * @param {string} privateKeyHex - Private key as hex string
 * @returns {Promise<string>} - Signature as hex string
 */
async function signMessage(message, privateKeyHex) {
  // Convert hex private key to bytes
  const privateKeyBytes = hexToBytes(privateKeyHex);

  // Import private key
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // Sign message
  const messageBytes = new TextEncoder().encode(message);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    messageBytes
  );

  return bytesToHex(new Uint8Array(signature));
}

/**
 * Hex encoding/decoding utilities
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * HTTP fetch wrapper
 * @param {string} method - HTTP method
 * @param {string} url - Request URL
 * @param {Object} headers - Request headers
 * @param {string} body - Request body
 * @returns {Promise<{status: number, body: string}>}
 */
async function httpFetch(method, url, headers, body) {
  const response = await fetch(url, {
    method,
    headers,
    body: body || undefined
  });

  const responseBody = await response.text();

  return {
    status: response.status,
    body: responseBody
  };
}

/**
 * Create WASM import object with all required functions
 */
function createImportObject(memory) {
  return {
    env: {
      memory,

      /**
       * js_fetch implementation
       */
      js_fetch: (
        methodPtr, urlPtr, headersJsonPtr, bodyPtr, bodyLen,
        outResponseBodyPtr, outResponseLenPtr, outStatusCodePtr,
        outErrorPtr, outErrorLenPtr
      ) => {
        try {
          // Read strings from WASM memory
          const method = readCString(memory, methodPtr);
          const url = readCString(memory, urlPtr);
          const headersJson = readCString(memory, headersJsonPtr);
          const headers = JSON.parse(headersJson);
          const body = bodyLen > 0 ? readBytes(memory, bodyPtr, bodyLen) : null;

          // Perform fetch (async, but we need sync behavior)
          // Note: Real implementation would use asyncify or similar
          httpFetch(method, url, headers, body).then(result => {
            // Write response to WASM memory
            writeString(memory, outResponseBodyPtr, result.body);
            writeInt32(memory, outResponseLenPtr, result.body.length);
            writeInt32(memory, outStatusCodePtr, result.status);
            return 0;
          }).catch(err => {
            writeString(memory, outErrorPtr, err.message);
            writeInt32(memory, outErrorLenPtr, err.message.length);
            return 1;
          });
        } catch (err) {
          writeString(memory, outErrorPtr, err.message);
          writeInt32(memory, outErrorLenPtr, err.message.length);
          return 1;
        }
      },

      /**
       * js_sign_message implementation
       */
      js_sign_message: (
        messagePtr, messageLen, privateKeyPtr, keyLen,
        outSignaturePtr, outSigLenPtr
      ) => {
        try {
          const message = readBytes(memory, messagePtr, messageLen);
          const privateKey = readCString(memory, privateKeyPtr);

          signMessage(new TextDecoder().decode(message), privateKey).then(signature => {
            writeString(memory, outSignaturePtr, signature);
            writeInt32(memory, outSigLenPtr, signature.length);
          });
        } catch (err) {
          writeInt32(memory, outSigLenPtr, -1);
        }
      },

      /**
       * js_sha256 implementation
       */
      js_sha256: (dataPtr, dataLen, outHashPtr) => {
        try {
          const data = readBytes(memory, dataPtr, dataLen);

          sha256(data).then(hash => {
            writeBytes(memory, outHashPtr, hash);
          });
        } catch (err) {
          // Fill with zeros on error
          const view = new Uint8Array(memory.buffer);
          for (let i = 0; i < 32; i++) {
            view[outHashPtr + i] = 0;
          }
        }
      }
    }
  };
}

/**
 * Memory access helpers
 */
function readCString(memory, ptr) {
  const view = new Uint8Array(memory.buffer);
  let end = ptr;
  while (view[end] !== 0) end++;
  return new TextDecoder().decode(view.slice(ptr, end));
}

function readBytes(memory, ptr, len) {
  const view = new Uint8Array(memory.buffer);
  return view.slice(ptr, ptr + len);
}

function writeString(memory, ptr, str) {
  const view = new Uint8Array(memory.buffer);
  const bytes = new TextEncoder().encode(str);
  view.set(bytes, ptr);
  view[ptr + bytes.length] = 0; // null terminator
}

function writeBytes(memory, ptr, bytes) {
  const view = new Uint8Array(memory.buffer);
  view.set(bytes, ptr);
}

function writeInt32(memory, ptr, value) {
  const view = new DataView(memory.buffer);
  view.setInt32(ptr, value, true); // little-endian
}

// Export for Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { createImportObject, sha256, signMessage, httpFetch };
}
