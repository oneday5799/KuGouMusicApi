const CryptoJS = require('crypto-js');
const forge = require('node-forge');
const { randomString } = require('./util');
const publicRasKey = `-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIAG7QOELSYoIJvTFJhMpe1s/gbjDJX51HBNnEl5HXqTW6lQ7LC8jr9fWZTwusknp+sVGzwd40MwP6U5yDE27M/X1+UR4tvOGOqp94TJtQ1EPnWGWXngpeIW5GxoQGao1rmYWAu6oi1z9XkChrsUdC6DJE5E221wf/4WLFxwAtRQIDAQAB\n-----END PUBLIC KEY-----`;
const publicLiteRasKey = `-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDECi0Np2UR87scwrvTr72L6oO01rBbbBPriSDFPxr3Z5syug0O24QyQO8bg27+0+4kBzTBTBOZ/WWU0WryL1JSXRTXLgFVxtzIY41Pe7lPOgsfTCn5kZcvKhYKJesKnnJDNr5/abvTGf+rHG3YRwsCHcQ08/q6ifSioBszvb3QiwIDAQAB\n-----END PUBLIC KEY-----`;

const rsaKeyCache = new Map();

function encodeUtf8(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }

  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'utf8'));
  }

  const codePoints = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = ((code - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
        i++;
      }
    }
    codePoints.push(code);
  }

  const bytes = [];
  for (const code of codePoints) {
    if (code <= 0x7f) {
      bytes.push(code);
    } else if (code <= 0x7ff) {
      bytes.push(
        0xc0 | (code >> 6),
        0x80 | (code & 0x3f),
      );
    } else if (code <= 0xffff) {
      bytes.push(
        0xe0 | (code >> 12),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }

  return new Uint8Array(bytes);
}

function decodeUtf8(uint8) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder().decode(uint8);
  }

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(uint8).toString('utf8');
  }

  let out = '';
  let i = 0;
  while (i < uint8.length) {
    const byte1 = uint8[i++];
    if (byte1 < 0x80) {
      out += String.fromCharCode(byte1);
      continue;
    }
    if (byte1 < 0xe0) {
      const byte2 = uint8[i++] & 0x3f;
      const codePoint = ((byte1 & 0x1f) << 6) | byte2;
      out += String.fromCharCode(codePoint);
      continue;
    }
    if (byte1 < 0xf0) {
      const byte2 = uint8[i++] & 0x3f;
      const byte3 = uint8[i++] & 0x3f;
      const codePoint = ((byte1 & 0x0f) << 12) | (byte2 << 6) | byte3;
      out += String.fromCharCode(codePoint);
      continue;
    }

    const byte2 = uint8[i++] & 0x3f;
    const byte3 = uint8[i++] & 0x3f;
    const byte4 = uint8[i++] & 0x3f;
    let codePoint = ((byte1 & 0x07) << 18) | (byte2 << 12) | (byte3 << 6) | byte4;
    codePoint -= 0x10000;
    out += String.fromCharCode(
      (codePoint >> 10) + 0xd800,
      (codePoint & 0x3ff) + 0xdc00,
    );
  }

  return out;
}

function normalizeBuffer(data) {
  if (data instanceof Uint8Array) return data;
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return encodeUtf8(str);
}

function wordArrayFromBuffer(uint8) {
  const words = [];
  for (let i = 0; i < uint8.length; i += 4) {
    words.push(
      ((uint8[i] || 0) << 24) | ((uint8[i + 1] || 0) << 16) |
      ((uint8[i + 2] || 0) << 8) | (uint8[i + 3] || 0)
    );
  }
  return CryptoJS.lib.WordArray.create(words, uint8.length);
}

function wordArrayToBuffer(wordArray) {
  const { words, sigBytes } = wordArray;
  const uint8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    uint8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return uint8;
}

function uint8ArrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function utf8WordArray(input) {
  return typeof input === 'string' ? CryptoJS.enc.Utf8.parse(input) : wordArrayFromBuffer(input);
}

function getForgePublicKey(pem) {
  if (!rsaKeyCache.has(pem)) {
    rsaKeyCache.set(pem, forge.pki.publicKeyFromPem(pem));
  }
  return rsaKeyCache.get(pem);
}

function bufferToBinaryString(buffer) {
  let out = '';
  for (let i = 0; i < buffer.length; i++) out += String.fromCharCode(buffer[i]);
  return out;
}

function rsaRawEncrypt(buffer, publicKey) {
  const keyLength = Math.ceil(publicKey.n.bitLength() / 8);
  const message = new forge.jsbn.BigInteger(uint8ArrayToHex(buffer), 16);
  const encrypted = message.modPow(publicKey.e, publicKey.n);
  return encrypted.toString(16).padStart(keyLength * 2, '0');
}

/**
 * @typedef {{str: string, key: string}} AesEncrypt
 */

/**
 * MD5 加密
 * @param {BufferLike} data
 * @returns {string}
 */
function cryptoMd5(data) {
  const buffer = typeof data === 'object' ? JSON.stringify(data) : data;
  return CryptoJS.MD5(buffer).toString(CryptoJS.enc.Hex);
}

/**
 * Sha1 加密
 * @param {BufferLike} data
 * @returns { string }
 */
function cryptoSha1(data) {
  const buffer = typeof data === 'object' ? JSON.stringify(data) : data;
  return CryptoJS.SHA1(buffer).toString(CryptoJS.enc.Hex);
}

/**
 * AES 加密
 * @param {BufferLike} data 需要加密的数据
 * @param {{ key?:string, iv?: string } | undefined} opt
 * @returns {AesEncrypt | string}
 */
function cryptoAesEncrypt(data, opt) {
  if (typeof data === 'object') data = JSON.stringify(data);
  const buffer = normalizeBuffer(data);
  let key;
  let iv;
  let tempKey = '';

  if (opt?.key && opt?.iv) {
    key = opt.key;
    iv = opt.iv;
  } else {
    tempKey = opt?.key || randomString(16).toLowerCase();
    key = cryptoMd5(tempKey).substring(0, 32);
    iv = key.substring(key.length - 16);
  }

  const encrypted = CryptoJS.AES.encrypt(wordArrayFromBuffer(buffer), utf8WordArray(key), {
    iv: utf8WordArray(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const hex = CryptoJS.enc.Hex.stringify(encrypted.ciphertext);
  if (opt?.key && opt?.key) return hex;
  return { str: hex, key: tempKey };
}

/**
 * AES 解密
 * @param {string} data
 * @param {string} key
 * @param {string?} iv
 * @returns {string | Record<string, string>}
 */
function cryptoAesDecrypt(data, key, iv) {
  if (!iv) key = cryptoMd5(key).substring(0, 32);
  iv = iv || key.substring(key.length - 16);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(data) });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, utf8WordArray(key), {
    iv: utf8WordArray(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const text = decodeUtf8(wordArrayToBuffer(decrypted));
  try {
    return JSON.parse(text);
  } catch (e) {
    return text;
  }
}

/**
 * RSA加密
 * @param {BufferLike} data
 * @param {string?} publicKey
 * @returns {string} hex
 */
function cryptoRSAEncrypt(data, publicKey) {
  const isLite = process.env.platform === 'lite';
  const buffer = normalizeBuffer(data);
  const pem = publicKey || (isLite ? publicLiteRasKey : publicRasKey);
  const key = getForgePublicKey(pem);
  const keyLength = Math.ceil(key.n.bitLength() / 8);

  if (buffer.length > keyLength) throw new Error('Data length exceeds key size');
  let padded = buffer;
  if (buffer.length < keyLength) {
    padded = new Uint8Array(keyLength);
    padded.set(buffer);
  }

  return rsaRawEncrypt(padded, key);
}

function rsaEncrypt2(data) {
  const isLite = process.env.platform === 'lite';
  const buffer = normalizeBuffer(data);
  const key = getForgePublicKey(isLite ? publicLiteRasKey : publicRasKey);
  const encrypted = key.encrypt(bufferToBinaryString(buffer), 'RSAES-PKCS1-V1_5');
  return forge.util.bytesToHex(encrypted);
}

// 概念版 H5 页面脚本（kg-rsa）内嵌的 RSA 公钥模数（1024-bit，hex），
// 与 APP 端 publicRasKey / publicLiteRasKey 均不同，仅用于 H5 mobileCallProtocol 端点族的 p 字段
const h5ConceptRsaModulusHex =
  'B1B1EC76A1BBDBF0D18E8CD9A87E53FA3881E2F004C67C9DDA2CA677DBEFA3D61' +
  'DF8463FE12D84FF4B4699E02C9D41CAB917F5A8FB9E35580C4BDF97763A0420A4' +
  '76295D763EE10174E6F9EBF7DF8A77BA5B20CDA4EE705DEF5BBA3C88567B9656E' +
  '52C9CD5CD95CA735FF2D25F762B133273EEEB7B4F3EA8B6DA29040F3B67CD';

/**
 * 概念版 H5 页面脚本（kg-rsa）的 RSA 加密，输出定长 256 位小写 hex
 *
 * 其 "PKCS1Padding" 是自定义块布局（非标准 PKCS#1 v1.5）：
 *   block[0..m-1]      = 明文字节反转
 *   block[m]           = 0x00
 *   block[m+1..125]    = 随机非零字节
 *   block[126]         = 0x02
 *   block[127]         = 0x00
 * 之后把块按小端装配成整数做 raw RSA（m^e mod n）。
 * 实测服务端对标准 PKCS#1 v1.5 与此自定义布局当前均接受，但为与客户端 H5 原实现
 * 逐字节一致（已做同随机序列对拍验证），按原布局实现。
 * @param {BufferLike} data
 * @returns {string} hex
 */
function cryptoH5RsaEncryptHex(data) {
  const buffer = normalizeBuffer(data);
  if (buffer.length > 117) throw new Error('Data length exceeds RSA-1024 block (117 bytes)');
  const block = new Uint8Array(128);
  for (let i = 0; i < buffer.length; i++) block[buffer.length - 1 - i] = buffer[i];
  for (let i = buffer.length; i < 128; i++) {
    let byte = 0;
    while (byte === 0) byte = (Math.random() * 256) | 0;
    block[i] = byte;
  }
  block[buffer.length] = 0x00;
  block[126] = 0x02;
  block[127] = 0x00;
  const n = new forge.jsbn.BigInteger(h5ConceptRsaModulusHex, 16);
  const e = new forge.jsbn.BigInteger('10001', 16);
  // 小端装配：整数的大端 hex 即字节序反转
  const message = new forge.jsbn.BigInteger(uint8ArrayToHex(block.reverse()), 16);
  return message.modPow(e, n).toString(16).padStart(256, '0');
}

function playlistAesEncrypt(data) {
  const useData = typeof data === 'object' ? JSON.stringify(data) : data;
  const key = randomString(6).toLowerCase();
  const encryptKey = cryptoMd5(key).substring(0, 16);
  const iv = cryptoMd5(key).substring(16, 32);

  const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(useData), utf8WordArray(encryptKey), {
    iv: utf8WordArray(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  return { key, str: CryptoJS.enc.Base64.stringify(encrypted.ciphertext) };
}

function playlistAesDecrypt(data) {
  const encryptKey = cryptoMd5(data.key).substring(0, 16);
  const iv = cryptoMd5(data.key).substring(16, 32);

  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(data.str) });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, utf8WordArray(encryptKey), {
    iv: utf8WordArray(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const text = decodeUtf8(wordArrayToBuffer(decrypted));
  try {
    return JSON.parse(text);
  } catch (e) {
    return text;
  }
}

module.exports = {
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  rsaEncrypt2,
  cryptoSha1,
  playlistAesEncrypt,
  playlistAesDecrypt,
  cryptoH5RsaEncryptHex,
  publicLiteRasKey,
  publicRasKey,
  wordArrayFromBuffer,
};
