var Crypto = require('/cryptojs').Crypto;

/**
 * 获取aes加密的密钥
 * @param {String} key sdk的appkey
 */
function getAESKey(key) {
  var md5Str = Crypto.MD5(key + "20171219008");
  return md5Str.substring(0, 16);
}

/**
 * base 64位 编码
 * @param {byte[]} content aes加密后得到的byte数组
 */
function base64Encoder(content) {
  var result = Crypto.util.bytesToBase64(content);
  return result;
}

/**
 * base 64位 解码
 * @param {String} content base64的编码
 */
function base64Decode(content) {
  var result = Crypto.util.base64ToBytes(content);
  return result;
}

/**
 * AES加密
 * @param {String} word 需要加密的字符串
 * @param {String} appkey sdk的appkey
 */
function AESEncrypt(word, appkey) {
  var aeskey = getAESKey(appkey);
  var mode = new Crypto.mode.CBC(Crypto.pad.pkcs7);
  var eb = Crypto.charenc.UTF8.stringToBytes(word);
  var kb = Crypto.charenc.UTF8.stringToBytes(aeskey); //KEY
  // var vb = Crypto.charenc.UTF8.stringToBytes(iv); //IV
  var vb = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
  var ub = Crypto.AES.encrypt(eb, kb, {
    iv: vb,
    mode: mode,
    asBytes: true
  });
  return ub;
}

/**
 * AES解密
 * @param {byte[]} word 加密的byte数组
 * @param {String} appkey sdk的appkey
 */
function AESDecrypt(word, appkey) {
  var aeskey = getAESKey(appkey);
  var mode = new Crypto.mode.CBC(Crypto.pad.pkcs7);
  var kb = Crypto.charenc.UTF8.stringToBytes(aeskey); //KEY
  var vb = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
  var ub = Crypto.AES.decrypt(word, kb, {
    asBytes: false,
    mode: mode,
    iv: vb
  });
  return ub;
}