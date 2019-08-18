var ThinNeo;
(function (ThinNeo) {
    var contract = (function () {
        function contract() {
            this.parameters = [{ "name": "parameter0", "type": "Signature" }];
            this.deployed = false;
        }
        return contract;
    } ());
    ThinNeo.contract = contract;
    var nep6account = (function () {
        function nep6account() {
        }
        nep6account.prototype.getPrivateKey = function (scrypt, password, callback) {
            var _this = this;
            var cb = function (i, r) {
                if (i == "finish") {
                    var bytes = r;
                    var pkey = ThinNeo.Helper.GetPublicKeyFromPrivateKey(bytes);
                    var address = ThinNeo.Helper.GetAddressFromPublicKey(pkey);
                    if (address == _this.address) {
                        callback(i, r);
                    }
                    else {
                        callback("error", "checkerror");
                    }
                }
                else {
                    callback(i, r);
                }
            };
            ThinNeo.Helper.GetPrivateKeyFromNep2(this.nep2key, password, scrypt.N, scrypt.r, scrypt.p, cb);
        };
        return nep6account;
    } ());
    ThinNeo.nep6account = nep6account;
    var nep6ScryptParameters = (function () {
        function nep6ScryptParameters() {
        }
        return nep6ScryptParameters;
    } ());
    ThinNeo.nep6ScryptParameters = nep6ScryptParameters;
    var nep6wallet = (function () {
        function nep6wallet() {
        }
        nep6wallet.prototype.fromJsonStr = function (jsonstr) {
            var json = JSON.parse(jsonstr);
            this.scrypt = new nep6ScryptParameters();
            this.scrypt.N = json.scrypt.n;
            this.scrypt.r = json.scrypt.r;
            this.scrypt.p = json.scrypt.p;
            this.accounts = [];
            for (var i = 0; i < json.accounts.length; i++) {
                var acc = json.accounts[i];
                var localacc = new nep6account();
                localacc.address = acc.address;
                localacc.nep2key = acc.key;
                localacc.contract = acc.contract;
                if (localacc.contract == null || localacc.contract.script == null) {
                    localacc.nep2key = null;
                }
                else {
                    var ss = localacc.contract.script.hexToBytes();
                    if (ss.length != 35 || ss[0] != 33 || ss[34] != 172) {
                        localacc.nep2key = null;
                    }
                }
                if (acc.key == undefined)
                    localacc.nep2key = null;
                this.accounts.push(localacc);
            }
        };
        nep6wallet.prototype.toJson = function () {
            var obj = {};
            obj["name"] = null;
            obj["version"] = "1.0";
            obj["scrypt"] = {
                "n": this.scrypt.N,
                "r": this.scrypt.r,
                "p": this.scrypt.p
            };
            var accounts = [];
            for (var i = 0; i < this.accounts.length; i++) {
                var acc = this.accounts[0];
                var jsonacc = {};
                jsonacc["address"] = acc.address;
                jsonacc["label"] = null;
                jsonacc["isDefault"] = false;
                jsonacc["lock"] = false;
                jsonacc["key"] = acc.nep2key;
                jsonacc["extra"] = null;
                jsonacc["contract"] = acc.contract;
                accounts.push(jsonacc);
            }
            obj["accounts"] = accounts;
            obj["extra"] = null;
            return obj;
        };
        return nep6wallet;
    } ());
    ThinNeo.nep6wallet = nep6wallet;
})(ThinNeo || (ThinNeo = {}));
var ThinNeo;
(function (ThinNeo) {
    var Base64 = (function () {
        function Base64() {
        }
        Base64.init = function () {
            if (Base64.binited)
                return;
            Base64.lookup = [];
            Base64.revLookup = [];
            for (var i = 0, len = Base64.code.length; i < len; ++i) {
                Base64.lookup[i] = Base64.code[i];
                Base64.revLookup[Base64.code.charCodeAt(i)] = i;
            }
            Base64.revLookup['-'.charCodeAt(0)] = 62;
            Base64.revLookup['_'.charCodeAt(0)] = 63;
            Base64.binited = true;
        };
        Base64.placeHoldersCount = function (b64) {
            var len = b64.length;
            if (len % 4 > 0) {
                throw new Error('Invalid string. Length must be a multiple of 4');
            }
            return b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0;
        };
        Base64.byteLength = function (b64) {
            return (b64.length * 3 / 4) - Base64.placeHoldersCount(b64);
        };
        Base64.toByteArray = function (b64) {
            Base64.init();
            var i, l, tmp, placeHolders, arr;
            var len = b64.length;
            placeHolders = Base64.placeHoldersCount(b64);
            arr = new Uint8Array((len * 3 / 4) - placeHolders);
            l = placeHolders > 0 ? len - 4 : len;
            var L = 0;
            for (i = 0; i < l; i += 4) {
                tmp = (Base64.revLookup[b64.charCodeAt(i)] << 18) | (Base64.revLookup[b64.charCodeAt(i + 1)] << 12) | (Base64.revLookup[b64.charCodeAt(i + 2)] << 6) | Base64.revLookup[b64.charCodeAt(i + 3)];
                arr[L++] = (tmp >> 16) & 0xFF;
                arr[L++] = (tmp >> 8) & 0xFF;
                arr[L++] = tmp & 0xFF;
            }
            if (placeHolders === 2) {
                tmp = (Base64.revLookup[b64.charCodeAt(i)] << 2) | (Base64.revLookup[b64.charCodeAt(i + 1)] >> 4);
                arr[L++] = tmp & 0xFF;
            }
            else if (placeHolders === 1) {
                tmp = (Base64.revLookup[b64.charCodeAt(i)] << 10) | (Base64.revLookup[b64.charCodeAt(i + 1)] << 4) | (Base64.revLookup[b64.charCodeAt(i + 2)] >> 2);
                arr[L++] = (tmp >> 8) & 0xFF;
                arr[L++] = tmp & 0xFF;
            }
            return arr;
        };
        Base64.tripletToBase64 = function (num) {
            return Base64.lookup[num >> 18 & 0x3F] + Base64.lookup[num >> 12 & 0x3F] + Base64.lookup[num >> 6 & 0x3F] + Base64.lookup[num & 0x3F];
        };
        Base64.encodeChunk = function (uint8, start, end) {
            var tmp;
            var output = [];
            for (var i = start; i < end; i += 3) {
                tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
                output.push(Base64.tripletToBase64(tmp));
            }
            return output.join('');
        };
        Base64.fromByteArray = function (uint8) {
            Base64.init();
            var tmp;
            var len = uint8.length;
            var extraBytes = len % 3;
            var output = '';
            var parts = [];
            var maxChunkLength = 16383;
            for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
                parts.push(Base64.encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)));
            }
            if (extraBytes === 1) {
                tmp = uint8[len - 1];
                output += Base64.lookup[tmp >> 2];
                output += Base64.lookup[(tmp << 4) & 0x3F];
                output += '==';
            }
            else if (extraBytes === 2) {
                tmp = (uint8[len - 2] << 8) + (uint8[len - 1]);
                output += Base64.lookup[tmp >> 10];
                output += Base64.lookup[(tmp >> 4) & 0x3F];
                output += Base64.lookup[(tmp << 2) & 0x3F];
                output += '=';
            }
            parts.push(output);
            return parts.join('');
        };
        Base64.lookup = [];
        Base64.revLookup = [];
        Base64.code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        Base64.binited = false;
        return Base64;
    } ());
    ThinNeo.Base64 = Base64;
})(ThinNeo || (ThinNeo = {}));
var ThinNeo;
(function (ThinNeo) {
    var scrypt_loaded = false;
    var Helper = (function () {
        function Helper() {
        }
        Helper.GetPrivateKeyFromWIF = function (wif) {
            if (wif == null)
                throw new Error("null wif");
            var data = Neo.Cryptography.Base58.decode(wif);
            if (data.length != 38 || data[0] != 0x80 || data[33] != 0x01)
                throw new Error("wif length or tag is error");
            var sum = data.subarray(data.length - 4, data.length);
            var realdata = data.subarray(0, data.length - 4);
            var _checksum = Neo.Cryptography.Sha256.computeHash(realdata);
            var checksum = new Uint8Array(Neo.Cryptography.Sha256.computeHash(_checksum));
            var sumcalc = checksum.subarray(0, 4);
            for (var i = 0; i < 4; i++) {
                if (sum[i] != sumcalc[i])
                    throw new Error("the sum is not match.");
            }
            var privateKey = data.subarray(1, 1 + 32);
            return privateKey;
        };
        Helper.GetWifFromPrivateKey = function (prikey) {
            var data = new Uint8Array(38);
            data[0] = 0x80;
            data[33] = 0x01;
            for (var i = 0; i < 32; i++) {
                data[i + 1] = prikey[i];
            }
            var realdata = data.subarray(0, data.length - 4);
            var _checksum = Neo.Cryptography.Sha256.computeHash(realdata);
            var checksum = new Uint8Array(Neo.Cryptography.Sha256.computeHash(_checksum));
            for (var i = 0; i < 4; i++) {
                data[34 + i] = checksum[i];
            }
            var wif = Neo.Cryptography.Base58.encode(data);
            return wif;
        };
        Helper.GetPublicKeyFromPrivateKey = function (privateKey) {
            var pkey = Neo.Cryptography.ECPoint.multiply(Neo.Cryptography.ECCurve.secp256r1.G, privateKey);
            return pkey.encodePoint(true);
        };
        Helper.Hash160 = function (data) {
            var hash1 = Neo.Cryptography.Sha256.computeHash(data);
            var hash2 = Neo.Cryptography.RIPEMD160.computeHash(hash1);
            return new Uint8Array(hash2);
        };
        Helper.GetAddressCheckScriptFromPublicKey = function (publicKey) {
            var script = new Uint8Array(publicKey.length + 2);
            script[0] = publicKey.length;
            for (var i = 0; i < publicKey.length; i++) {
                script[i + 1] = publicKey[i];
            }
            ;
            script[script.length - 1] = 172;
            return script;
        };
        Helper.GetPublicKeyScriptHashFromPublicKey = function (publicKey) {
            var script = Helper.GetAddressCheckScriptFromPublicKey(publicKey);
            var scripthash = Neo.Cryptography.Sha256.computeHash(script);
            scripthash = Neo.Cryptography.RIPEMD160.computeHash(scripthash);
            return new Uint8Array(scripthash);
        };
        Helper.GetScriptHashFromScript = function (script) {
            var scripthash = Neo.Cryptography.Sha256.computeHash(script);
            scripthash = Neo.Cryptography.RIPEMD160.computeHash(scripthash);
            return new Uint8Array(scripthash);
        };
        Helper.GetAddressFromScriptHash = function (scripthash) {
            var data = new Uint8Array(scripthash.length + 1);
            data[0] = 0x17;
            for (var i = 0; i < scripthash.length; i++) {
                data[i + 1] = scripthash[i];
            }
            var hash = Neo.Cryptography.Sha256.computeHash(data);
            hash = Neo.Cryptography.Sha256.computeHash(hash);
            var hashu8 = new Uint8Array(hash, 0, 4);
            var alldata = new Uint8Array(data.length + 4);
            for (var i = 0; i < data.length; i++) {
                alldata[i] = data[i];
            }
            for (var i = 0; i < 4; i++) {
                alldata[data.length + i] = hashu8[i];
            }
            return Neo.Cryptography.Base58.encode(alldata);
        };
        Helper.GetAddressFromPublicKey = function (publicKey) {
            var scripthash = Helper.GetPublicKeyScriptHashFromPublicKey(publicKey);
            return Helper.GetAddressFromScriptHash(scripthash);
        };
        Helper.GetPublicKeyScriptHash_FromAddress = function (address) {
            var array = Neo.Cryptography.Base58.decode(address);
            var salt = array.subarray(0, 1);
            var hash = array.subarray(1, 1 + 20);
            var check = array.subarray(21, 21 + 4);
            var checkdata = array.subarray(0, 21);
            var hashd = Neo.Cryptography.Sha256.computeHash(checkdata);
            hashd = Neo.Cryptography.Sha256.computeHash(hashd);
            var hashd = hashd.slice(0, 4);
            var checked = new Uint8Array(hashd);
            for (var i = 0; i < 4; i++) {
                if (checked[i] != check[i]) {
                    throw new Error("the sum is not match.");
                }
            }
            return hash.clone();
        };
        Helper.Sign = function (message, privateKey) {
            var PublicKey = Neo.Cryptography.ECPoint.multiply(Neo.Cryptography.ECCurve.secp256r1.G, privateKey);
            var pubkey = PublicKey.encodePoint(false).subarray(1, 64);
            var key = new Neo.Cryptography.ECDsaCryptoKey(PublicKey, privateKey);
            var ecdsa = new Neo.Cryptography.ECDsa(key);
            {
                return new Uint8Array(ecdsa.sign(message));
            }
        };
        Helper.VerifySignature = function (message, signature, pubkey) {
            var PublicKey = Neo.Cryptography.ECPoint.decodePoint(pubkey, Neo.Cryptography.ECCurve.secp256r1);
            var usepk = PublicKey.encodePoint(false).subarray(1, 64);
            var key = new Neo.Cryptography.ECDsaCryptoKey(PublicKey);
            var ecdsa = new Neo.Cryptography.ECDsa(key);
            {
                return ecdsa.verify(message, signature);
            }
        };
        Helper.String2Bytes = function (str) {
            var back = [];
            var byteSize = 0;
            for (var i = 0; i < str.length; i++) {
                var code = str.charCodeAt(i);
                if (0x00 <= code && code <= 0x7f) {
                    byteSize += 1;
                    back.push(code);
                }
                else if (0x80 <= code && code <= 0x7ff) {
                    byteSize += 2;
                    back.push((192 | (31 & (code >> 6))));
                    back.push((128 | (63 & code)));
                }
                else if ((0x800 <= code && code <= 0xd7ff)
                    || (0xe000 <= code && code <= 0xffff)) {
                    byteSize += 3;
                    back.push((224 | (15 & (code >> 12))));
                    back.push((128 | (63 & (code >> 6))));
                    back.push((128 | (63 & code)));
                }
            }
            var uarr = new Uint8Array(back.length);
            for (i = 0; i < back.length; i++) {
                uarr[i] = back[i] & 0xff;
            }
            return uarr;
        };
        Helper.Bytes2String = function (_arr) {
            var UTF = '';
            for (var i = 0; i < _arr.length; i++) {
                var one = _arr[i].toString(2), v = one.match(/^1+?(?=0)/);
                if (v && one.length == 8) {
                    var bytesLength = v[0].length;
                    var store = _arr[i].toString(2).slice(7 - bytesLength);
                    for (var st = 1; st < bytesLength; st++) {
                        store += _arr[st + i].toString(2).slice(2);
                    }
                    UTF += String.fromCharCode(parseInt(store, 2));
                    i += bytesLength - 1;
                }
                else {
                    UTF += String.fromCharCode(_arr[i]);
                }
            }
            return UTF;
        };
        Helper.Aes256Encrypt = function (src, key) {
            var srcs = CryptoJS.enc.Utf8.parse(src);
            var keys = CryptoJS.enc.Utf8.parse(key);
            var encryptedkey = CryptoJS.AES.encrypt(srcs, keys, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            });
            return encryptedkey.ciphertext.toString();
        };
        Helper.Aes256Encrypt_u8 = function (src, key) {
            var srcs = CryptoJS.enc.Utf8.parse("1234123412341234");
            srcs.sigBytes = src.length;
            srcs.words = new Array(src.length / 4);
            for (var i = 0; i < src.length / 4; i++) {
                srcs.words[i] = src[i * 4 + 3] + src[i * 4 + 2] * 256 + src[i * 4 + 1] * 256 * 256 + src[i * 4 + 0] * 256 * 256 * 256;
            }
            var keys = CryptoJS.enc.Utf8.parse("1234123412341234");
            keys.sigBytes = key.length;
            keys.words = new Array(key.length / 4);
            for (var i = 0; i < key.length / 4; i++) {
                keys.words[i] = key[i * 4 + 3] + key[i * 4 + 2] * 256 + key[i * 4 + 1] * 256 * 256 + key[i * 4 + 0] * 256 * 256 * 256;
            }
            var encryptedkey = CryptoJS.AES.encrypt(srcs, keys, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            });
            var str = encryptedkey.ciphertext.toString();
            return str.hexToBytes();
        };
        Helper.Aes256Decrypt_u8 = function (encryptedkey, key) {
            var keys = CryptoJS.enc.Utf8.parse("1234123412341234");
            keys.sigBytes = key.length;
            keys.words = new Array(key.length / 4);
            for (var i = 0; i < key.length / 4; i++) {
                keys.words[i] = key[i * 4 + 3] + key[i * 4 + 2] * 256 + key[i * 4 + 1] * 256 * 256 + key[i * 4 + 0] * 256 * 256 * 256;
            }
            var base64key = ThinNeo.Base64.fromByteArray(encryptedkey);
            var srcs = CryptoJS.AES.decrypt(base64key, keys, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.NoPadding
            });
            var str = srcs.toString();
            return str.hexToBytes();
        };
        Helper.GetNep2FromPrivateKey = function (prikey, passphrase, n, r, p, callback) {
            if (n === void 0) { n = 16384; }
            if (r === void 0) { r = 8; }
            if (p === void 0) { p = 8; }
            var pp = scrypt.getAvailableMod();
            scrypt.setResPath('SDK-BlockChain/neo/lib');
            var addresshash = null;
            var ready = function () {
                var param = {
                    N: n,
                    r: r,
                    P: p
                };
                var opt = {
                    maxPassLen: 32,
                    maxSaltLen: 32,
                    maxDkLen: 64,
                    maxThread: 4
                };
                try {
                    scrypt.config(param, opt);
                }
                catch (err) {
                    console.warn('config err: ', err);
                }
            };
            scrypt.onload = function () {
                console.log("scrypt.onload");
                scrypt_loaded = true;
                ready();
            };
            scrypt.onerror = function (err) {
                console.warn('scrypt err:', err);
                callback("error", err);
            };
            scrypt.oncomplete = function (dk) {
                console.log('done', scrypt.binToHex(dk));
                var u8dk = new Uint8Array(dk);
                var derivedhalf1 = u8dk.subarray(0, 32);
                var derivedhalf2 = u8dk.subarray(32, 64);
                var u8xor = new Uint8Array(32);
                for (var i = 0; i < 32; i++) {
                    u8xor[i] = prikey[i] ^ derivedhalf1[i];
                }
                var encryptedkey = Helper.Aes256Encrypt_u8(u8xor, derivedhalf2);
                var buffer = new Uint8Array(39);
                buffer[0] = 0x01;
                buffer[1] = 0x42;
                buffer[2] = 0xe0;
                for (var i = 3; i < 3 + 4; i++) {
                    buffer[i] = addresshash[i - 3];
                }
                for (var i = 7; i < 32 + 7; i++) {
                    buffer[i] = encryptedkey[i - 7];
                }
                var b1 = Neo.Cryptography.Sha256.computeHash(buffer);
                b1 = Neo.Cryptography.Sha256.computeHash(b1);
                var u8hash = new Uint8Array(b1);
                var outbuf = new Uint8Array(39 + 4);
                for (var i = 0; i < 39; i++) {
                    outbuf[i] = buffer[i];
                }
                for (var i = 39; i < 39 + 4; i++) {
                    outbuf[i] = u8hash[i - 39];
                }
                var base58str = Neo.Cryptography.Base58.encode(outbuf);
                callback("finish", base58str);
            };
            scrypt.onprogress = function (percent) {
                console.log('onprogress');
            };
            scrypt.onready = function () {
                var pubkey = Helper.GetPublicKeyFromPrivateKey(prikey);
                var script_hash = Helper.GetPublicKeyScriptHashFromPublicKey(pubkey);
                var address = Helper.GetAddressFromScriptHash(script_hash);
                var addrbin = scrypt.strToBin(address);
                var b1 = Neo.Cryptography.Sha256.computeHash(addrbin);
                b1 = Neo.Cryptography.Sha256.computeHash(b1);
                var b2 = new Uint8Array(b1);
                addresshash = b2.subarray(0, 4);
                var passbin = scrypt.strToBin(passphrase);
                scrypt.hash(passbin, addresshash, 64);
            };
            if (scrypt_loaded == false) {
                scrypt.load("asmjs");
            }
            else {
                ready();
            }
            return;
        };
        Helper.GetPrivateKeyFromNep2 = function (nep2, passphrase, n, r, p, callback) {
            if (n === void 0) { n = 16384; }
            if (r === void 0) { r = 8; }
            if (p === void 0) { p = 8; }
            var data = Neo.Cryptography.Base58.decode(nep2);
            if (data.length != 39 + 4) {
                callback("error", "data.length error");
                return;
            }
            if (data[0] != 0x01 || data[1] != 0x42 || data[2] != 0xe0) {
                callback("error", "dataheader error");
                return;
            }
            var hash = data.subarray(39, 39 + 4);
            var buffer = data.subarray(0, 39);
            var b1 = Neo.Cryptography.Sha256.computeHash(buffer);
            b1 = Neo.Cryptography.Sha256.computeHash(b1);
            var u8hash = new Uint8Array(b1);
            for (var i = 0; i < 4; i++) {
                if (u8hash[i] != hash[i]) {
                    callback("error", "data hash error");
                    return;
                }
            }
            var addresshash = buffer.subarray(3, 3 + 4);
            var encryptedkey = buffer.subarray(7, 7 + 32);
            var pp = scrypt.getAvailableMod();
            scrypt.setResPath('SDK-BlockChain/neo/lib');
            var ready = function () {
                var param = {
                    N: n,
                    r: r,
                    P: p
                };
                var opt = {
                    maxPassLen: 32,
                    maxSaltLen: 32,
                    maxDkLen: 64,
                    maxThread: 4
                };
                try {
                    scrypt.config(param, opt);
                }
                catch (err) {
                    console.warn('config err: ', err);
                }
            };
            scrypt.onload = function () {
                console.log("scrypt.onload");
                scrypt_loaded = true;
                ready();
            };
            scrypt.oncomplete = function (dk) {
                console.log('done', scrypt.binToHex(dk));
                var u8dk = new Uint8Array(dk);
                var derivedhalf1 = u8dk.subarray(0, 32);
                var derivedhalf2 = u8dk.subarray(32, 64);
                var u8xor = Helper.Aes256Decrypt_u8(encryptedkey, derivedhalf2);
                var prikey = new Uint8Array(u8xor.length);
                for (var i = 0; i < 32; i++) {
                    prikey[i] = u8xor[i] ^ derivedhalf1[i];
                }
                var pubkey = Helper.GetPublicKeyFromPrivateKey(prikey);
                var script_hash = Helper.GetPublicKeyScriptHashFromPublicKey(pubkey);
                var address = Helper.GetAddressFromScriptHash(script_hash);
                var addrbin = scrypt.strToBin(address);
                var b1 = Neo.Cryptography.Sha256.computeHash(addrbin);
                b1 = Neo.Cryptography.Sha256.computeHash(b1);
                var b2 = new Uint8Array(b1);
                var addresshashgot = b2.subarray(0, 4);
                for (var i = 0; i < 4; i++) {
                    if (addresshash[i] != b2[i]) {
                        callback("error", "nep2 hash not match.");
                        return;
                    }
                }
                callback("finish", prikey);
            };
            scrypt.onerror = function (err) {
                console.warn('scrypt err:', err);
                callback("error", err);
            };
            scrypt.onprogress = function (percent) {
                console.log('onprogress');
            };
            scrypt.onready = function () {
                var passbin = scrypt.strToBin(passphrase);
                scrypt.hash(passbin, addresshash, 64);
            };
            if (scrypt_loaded == false) {
                scrypt.load("asmjs");
            }
            else {
                ready();
            }
        };
        return Helper;
    } ());
    ThinNeo.Helper = Helper;
})(ThinNeo || (ThinNeo = {}));
var ThinNeo;
(function (ThinNeo) {
    var OpCode;
    (function (OpCode) {
        OpCode[OpCode["PUSH0"] = 0] = "PUSH0";
        OpCode[OpCode["PUSHF"] = 0] = "PUSHF";
        OpCode[OpCode["PUSHBYTES1"] = 1] = "PUSHBYTES1";
        OpCode[OpCode["PUSHBYTES75"] = 75] = "PUSHBYTES75";
        OpCode[OpCode["PUSHDATA1"] = 76] = "PUSHDATA1";
        OpCode[OpCode["PUSHDATA2"] = 77] = "PUSHDATA2";
        OpCode[OpCode["PUSHDATA4"] = 78] = "PUSHDATA4";
        OpCode[OpCode["PUSHM1"] = 79] = "PUSHM1";
        OpCode[OpCode["PUSH1"] = 81] = "PUSH1";
        OpCode[OpCode["PUSHT"] = 81] = "PUSHT";
        OpCode[OpCode["PUSH2"] = 82] = "PUSH2";
        OpCode[OpCode["PUSH3"] = 83] = "PUSH3";
        OpCode[OpCode["PUSH4"] = 84] = "PUSH4";
        OpCode[OpCode["PUSH5"] = 85] = "PUSH5";
        OpCode[OpCode["PUSH6"] = 86] = "PUSH6";
        OpCode[OpCode["PUSH7"] = 87] = "PUSH7";
        OpCode[OpCode["PUSH8"] = 88] = "PUSH8";
        OpCode[OpCode["PUSH9"] = 89] = "PUSH9";
        OpCode[OpCode["PUSH10"] = 90] = "PUSH10";
        OpCode[OpCode["PUSH11"] = 91] = "PUSH11";
        OpCode[OpCode["PUSH12"] = 92] = "PUSH12";
        OpCode[OpCode["PUSH13"] = 93] = "PUSH13";
        OpCode[OpCode["PUSH14"] = 94] = "PUSH14";
        OpCode[OpCode["PUSH15"] = 95] = "PUSH15";
        OpCode[OpCode["PUSH16"] = 96] = "PUSH16";
        OpCode[OpCode["NOP"] = 97] = "NOP";
        OpCode[OpCode["JMP"] = 98] = "JMP";
        OpCode[OpCode["JMPIF"] = 99] = "JMPIF";
        OpCode[OpCode["JMPIFNOT"] = 100] = "JMPIFNOT";
        OpCode[OpCode["CALL"] = 101] = "CALL";
        OpCode[OpCode["RET"] = 102] = "RET";
        OpCode[OpCode["APPCALL"] = 103] = "APPCALL";
        OpCode[OpCode["SYSCALL"] = 104] = "SYSCALL";
        OpCode[OpCode["TAILCALL"] = 105] = "TAILCALL";
        OpCode[OpCode["DUPFROMALTSTACK"] = 106] = "DUPFROMALTSTACK";
        OpCode[OpCode["TOALTSTACK"] = 107] = "TOALTSTACK";
        OpCode[OpCode["FROMALTSTACK"] = 108] = "FROMALTSTACK";
        OpCode[OpCode["XDROP"] = 109] = "XDROP";
        OpCode[OpCode["XSWAP"] = 114] = "XSWAP";
        OpCode[OpCode["XTUCK"] = 115] = "XTUCK";
        OpCode[OpCode["DEPTH"] = 116] = "DEPTH";
        OpCode[OpCode["DROP"] = 117] = "DROP";
        OpCode[OpCode["DUP"] = 118] = "DUP";
        OpCode[OpCode["NIP"] = 119] = "NIP";
        OpCode[OpCode["OVER"] = 120] = "OVER";
        OpCode[OpCode["PICK"] = 121] = "PICK";
        OpCode[OpCode["ROLL"] = 122] = "ROLL";
        OpCode[OpCode["ROT"] = 123] = "ROT";
        OpCode[OpCode["SWAP"] = 124] = "SWAP";
        OpCode[OpCode["TUCK"] = 125] = "TUCK";
        OpCode[OpCode["CAT"] = 126] = "CAT";
        OpCode[OpCode["SUBSTR"] = 127] = "SUBSTR";
        OpCode[OpCode["LEFT"] = 128] = "LEFT";
        OpCode[OpCode["RIGHT"] = 129] = "RIGHT";
        OpCode[OpCode["SIZE"] = 130] = "SIZE";
        OpCode[OpCode["INVERT"] = 131] = "INVERT";
        OpCode[OpCode["AND"] = 132] = "AND";
        OpCode[OpCode["OR"] = 133] = "OR";
        OpCode[OpCode["XOR"] = 134] = "XOR";
        OpCode[OpCode["EQUAL"] = 135] = "EQUAL";
        OpCode[OpCode["INC"] = 139] = "INC";
        OpCode[OpCode["DEC"] = 140] = "DEC";
        OpCode[OpCode["SIGN"] = 141] = "SIGN";
        OpCode[OpCode["NEGATE"] = 143] = "NEGATE";
        OpCode[OpCode["ABS"] = 144] = "ABS";
        OpCode[OpCode["NOT"] = 145] = "NOT";
        OpCode[OpCode["NZ"] = 146] = "NZ";
        OpCode[OpCode["ADD"] = 147] = "ADD";
        OpCode[OpCode["SUB"] = 148] = "SUB";
        OpCode[OpCode["MUL"] = 149] = "MUL";
        OpCode[OpCode["DIV"] = 150] = "DIV";
        OpCode[OpCode["MOD"] = 151] = "MOD";
        OpCode[OpCode["SHL"] = 152] = "SHL";
        OpCode[OpCode["SHR"] = 153] = "SHR";
        OpCode[OpCode["BOOLAND"] = 154] = "BOOLAND";
        OpCode[OpCode["BOOLOR"] = 155] = "BOOLOR";
        OpCode[OpCode["NUMEQUAL"] = 156] = "NUMEQUAL";
        OpCode[OpCode["NUMNOTEQUAL"] = 158] = "NUMNOTEQUAL";
        OpCode[OpCode["LT"] = 159] = "LT";
        OpCode[OpCode["GT"] = 160] = "GT";
        OpCode[OpCode["LTE"] = 161] = "LTE";
        OpCode[OpCode["GTE"] = 162] = "GTE";
        OpCode[OpCode["MIN"] = 163] = "MIN";
        OpCode[OpCode["MAX"] = 164] = "MAX";
        OpCode[OpCode["WITHIN"] = 165] = "WITHIN";
        OpCode[OpCode["SHA1"] = 167] = "SHA1";
        OpCode[OpCode["SHA256"] = 168] = "SHA256";
        OpCode[OpCode["HASH160"] = 169] = "HASH160";
        OpCode[OpCode["HASH256"] = 170] = "HASH256";
        OpCode[OpCode["CSHARPSTRHASH32"] = 171] = "CSHARPSTRHASH32";
        OpCode[OpCode["JAVAHASH32"] = 173] = "JAVAHASH32";
        OpCode[OpCode["CHECKSIG"] = 172] = "CHECKSIG";
        OpCode[OpCode["CHECKMULTISIG"] = 174] = "CHECKMULTISIG";
        OpCode[OpCode["ARRAYSIZE"] = 192] = "ARRAYSIZE";
        OpCode[OpCode["PACK"] = 193] = "PACK";
        OpCode[OpCode["UNPACK"] = 194] = "UNPACK";
        OpCode[OpCode["PICKITEM"] = 195] = "PICKITEM";
        OpCode[OpCode["SETITEM"] = 196] = "SETITEM";
        OpCode[OpCode["NEWARRAY"] = 197] = "NEWARRAY";
        OpCode[OpCode["NEWSTRUCT"] = 198] = "NEWSTRUCT";
        OpCode[OpCode["SWITCH"] = 208] = "SWITCH";
        OpCode[OpCode["THROW"] = 240] = "THROW";
        OpCode[OpCode["THROWIFNOT"] = 241] = "THROWIFNOT";
    })(OpCode = ThinNeo.OpCode || (ThinNeo.OpCode = {}));
})(ThinNeo || (ThinNeo = {}));
var ThinNeo;
(function (ThinNeo) {
    var ScriptBuilder = (function () {
        function ScriptBuilder() {
            this.Offset = 0;
            this.writer = [];
        }
        ScriptBuilder.prototype._WriteUint8 = function (num) {
            this.writer.push(num);
            this.Offset++;
        };
        ScriptBuilder.prototype._WriteUint16 = function (num) {
            var buf = new Uint8Array(2);
            var d = new DataView(buf.buffer, 0, 2);
            d.setUint16(0, num, true);
            this.writer.push(buf[0]);
            this.writer.push(buf[1]);
            this.Offset += 2;
        };
        ScriptBuilder.prototype._WriteUint32 = function (num) {
            var buf = new Uint8Array(4);
            var d = new DataView(buf.buffer, 0, 4);
            d.setUint32(0, num, true);
            this.writer.push(buf[0]);
            this.writer.push(buf[1]);
            this.writer.push(buf[2]);
            this.writer.push(buf[3]);
            this.Offset += 4;
        };
        ScriptBuilder.prototype._WriteUint8Array = function (nums) {
            for (var i = 0; i < nums.length; i++)
                this.writer.push(nums[i]);
            this.Offset += nums.length;
        };
        ScriptBuilder.prototype._ConvertInt16ToBytes = function (num) {
            var buf = new Uint8Array(2);
            var d = new DataView(buf.buffer, 0, 2);
            d.setInt16(0, num, true);
            return buf;
        };
        ScriptBuilder.prototype.Emit = function (op, arg) {
            if (arg === void 0) { arg = null; }
            this._WriteUint8(op);
            if (arg != null)
                this._WriteUint8Array(arg);
            return this;
        };
        ScriptBuilder.prototype.EmitAppCall = function (scriptHash, useTailCall) {
            if (useTailCall === void 0) { useTailCall = false; }
            if (scriptHash.length != 20)
                throw new Error("error scriptHash length");
            return this.Emit(useTailCall ? ThinNeo.OpCode.TAILCALL : ThinNeo.OpCode.APPCALL, scriptHash);
        };
        ScriptBuilder.prototype.EmitJump = function (op, offset) {
            if (op != ThinNeo.OpCode.JMP && op != ThinNeo.OpCode.JMPIF && op != ThinNeo.OpCode.JMPIFNOT && op != ThinNeo.OpCode.CALL)
                throw new Error("ArgumentException");
            return this.Emit(op, this._ConvertInt16ToBytes(offset));
        };
        ScriptBuilder.prototype.EmitPushNumber = function (number) {
            var i32 = number.toInt32();
            if (i32 == -1)
                return this.Emit(ThinNeo.OpCode.PUSHM1);
            if (i32 == 0)
                return this.Emit(ThinNeo.OpCode.PUSH0);
            if (i32 > 0 && i32 <= 16)
                return this.Emit(ThinNeo.OpCode.PUSH1 - 1 + i32);
            return this.EmitPushBytes(number.toUint8Array(true));
        };
        ScriptBuilder.prototype.EmitPushBool = function (data) {
            return this.Emit(data ? ThinNeo.OpCode.PUSHT : ThinNeo.OpCode.PUSHF);
        };
        ScriptBuilder.prototype.EmitPushBytes = function (data) {
            if (data == null)
                throw new Error("ArgumentNullException");
            if (data.length <= ThinNeo.OpCode.PUSHBYTES75) {
                this._WriteUint8(data.length);
                this._WriteUint8Array(data);
            }
            else if (data.length < 0x100) {
                this.Emit(ThinNeo.OpCode.PUSHDATA1);
                this._WriteUint8(data.length);
                this._WriteUint8Array(data);
            }
            else if (data.length < 0x10000) {
                this.Emit(ThinNeo.OpCode.PUSHDATA2);
                this._WriteUint16(data.length);
                this._WriteUint8Array(data);
            }
            else {
                this.Emit(ThinNeo.OpCode.PUSHDATA4);
                this._WriteUint32(data.length);
                this._WriteUint8Array(data);
            }
            return this;
        };
        ScriptBuilder.prototype.EmitPushString = function (data) {
            return this.EmitPushBytes(ThinNeo.Helper.String2Bytes(data));
        };
        ScriptBuilder.prototype.EmitSysCall = function (api) {
            if (api == null)
                throw new Error("ArgumentNullException");
            var api_bytes = ThinNeo.Helper.String2Bytes(api);
            if (api_bytes.length == 0 || api_bytes.length > 252)
                throw new Error("ArgumentException");
            var arg = new Uint8Array(api_bytes.length + 1);
            arg[0] = api_bytes.length;
            for (var i = 0; i < api_bytes.length; i++) {
                arg[i + 1] = api_bytes[i];
            }
            return this.Emit(ThinNeo.OpCode.SYSCALL, arg);
        };
        ScriptBuilder.prototype.ToArray = function () {
            var array = new Uint8Array(this.writer.length);
            for (var i = 0; i < this.writer.length; i++) {
                array[i] = this.writer[i];
            }
            return array;
        };
        ScriptBuilder.prototype.EmitParamJson = function (param) {
            if (typeof param === "number") {
                this.EmitPushNumber(new Neo.BigInteger(param));
            }
            else if (typeof param === "boolean") {
                this.EmitPushBool(param);
            }
            else if (typeof param === "object") {
                var list = param;
                for (var i = list.length - 1; i >= 0; i--) {
                    this.EmitParamJson(list[i]);
                }
                this.EmitPushNumber(new Neo.BigInteger(list.length));
                this.Emit(ThinNeo.OpCode.PACK);
            }
            else if (typeof param === "string") {
                var str = param;
                if (str[0] != '(')
                    throw new Error("must start with:(str) or (hex) or (hexrev) or (addr)or(int)");
                if (str.indexOf("(string)") == 0) {
                    this.EmitPushString(str.substr(8));
                }
                if (str.indexOf("(str)") == 0) {
                    this.EmitPushString(str.substr(5));
                }
                else if (str.indexOf("(bytes)") == 0) {
                    var hex = str.substr(7).hexToBytes();
                    this.EmitPushBytes(hex);
                }
                else if (str.indexOf("([])") == 0) {
                    var hex = str.substr(4).hexToBytes();
                    this.EmitPushBytes(hex);
                }
                else if (str.indexOf("(address)") == 0) {
                    var addr = (str.substr(9));
                    var hex = ThinNeo.Helper.GetPublicKeyScriptHash_FromAddress(addr);
                    this.EmitPushBytes(hex);
                }
                else if (str.indexOf("(addr)") == 0) {
                    var addr = (str.substr(6));
                    var hex = ThinNeo.Helper.GetPublicKeyScriptHash_FromAddress(addr);
                    this.EmitPushBytes(hex);
                }
                else if (str.indexOf("(integer)") == 0) {
                    var num = new Neo.BigInteger(str.substr(9));
                    this.EmitPushNumber(num);
                }
                else if (str.indexOf("(int)") == 0) {
                    var num = new Neo.BigInteger(str.substr(5));
                    this.EmitPushNumber(num);
                }
                else if (str.indexOf("(hexinteger)") == 0) {
                    var hex = str.substr(12).hexToBytes();
                    this.EmitPushBytes(hex.reverse());
                }
                else if (str.indexOf("(hexint)") == 0) {
                    var hex = str.substr(8).hexToBytes();
                    this.EmitPushBytes(hex.reverse());
                }
                else if (str.indexOf("(hex)") == 0) {
                    var hex = str.substr(5).hexToBytes();
                    this.EmitPushBytes(hex.reverse());
                }
                else if (str.indexOf("(int256)") == 0 || str.indexOf("(hex256)") == 0) {
                    var hex = str.substr(8).hexToBytes();
                    if (hex.length != 32)
                        throw new Error("not a int256");
                    this.EmitPushBytes(hex.reverse());
                }
                else if (str.indexOf("(int160)") == 0 || str.indexOf("(hex160)") == 0) {
                    var hex = str.substr(8).hexToBytes();
                    if (hex.length != 20)
                        throw new Error("not a int160");
                    this.EmitPushBytes(hex.reverse());
                }
                else
                    throw new Error("must start with:(str) or (hex) or (hexbig) or (addr) or(int)");
            }
            else {
                throw new Error("error type:" + typeof param);
            }
            return this;
        };
        return ScriptBuilder;
    } ());
    ThinNeo.ScriptBuilder = ScriptBuilder;
})(ThinNeo || (ThinNeo = {}));
var ThinNeo;
(function (ThinNeo) {
    var TransactionType;
    (function (TransactionType) {
        TransactionType[TransactionType["MinerTransaction"] = 0] = "MinerTransaction";
        TransactionType[TransactionType["IssueTransaction"] = 1] = "IssueTransaction";
        TransactionType[TransactionType["ClaimTransaction"] = 2] = "ClaimTransaction";
        TransactionType[TransactionType["EnrollmentTransaction"] = 32] = "EnrollmentTransaction";
        TransactionType[TransactionType["RegisterTransaction"] = 64] = "RegisterTransaction";
        TransactionType[TransactionType["ContractTransaction"] = 128] = "ContractTransaction";
        TransactionType[TransactionType["PublishTransaction"] = 208] = "PublishTransaction";
        TransactionType[TransactionType["InvocationTransaction"] = 209] = "InvocationTransaction";
    })(TransactionType = ThinNeo.TransactionType || (ThinNeo.TransactionType = {}));
    var TransactionAttributeUsage;
    (function (TransactionAttributeUsage) {
        TransactionAttributeUsage[TransactionAttributeUsage["ContractHash"] = 0] = "ContractHash";
        TransactionAttributeUsage[TransactionAttributeUsage["ECDH02"] = 2] = "ECDH02";
        TransactionAttributeUsage[TransactionAttributeUsage["ECDH03"] = 3] = "ECDH03";
        TransactionAttributeUsage[TransactionAttributeUsage["Script"] = 32] = "Script";
        TransactionAttributeUsage[TransactionAttributeUsage["Vote"] = 48] = "Vote";
        TransactionAttributeUsage[TransactionAttributeUsage["DescriptionUrl"] = 129] = "DescriptionUrl";
        TransactionAttributeUsage[TransactionAttributeUsage["Description"] = 144] = "Description";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash1"] = 161] = "Hash1";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash2"] = 162] = "Hash2";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash3"] = 163] = "Hash3";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash4"] = 164] = "Hash4";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash5"] = 165] = "Hash5";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash6"] = 166] = "Hash6";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash7"] = 167] = "Hash7";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash8"] = 168] = "Hash8";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash9"] = 169] = "Hash9";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash10"] = 170] = "Hash10";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash11"] = 171] = "Hash11";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash12"] = 172] = "Hash12";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash13"] = 173] = "Hash13";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash14"] = 174] = "Hash14";
        TransactionAttributeUsage[TransactionAttributeUsage["Hash15"] = 175] = "Hash15";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark"] = 240] = "Remark";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark1"] = 241] = "Remark1";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark2"] = 242] = "Remark2";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark3"] = 243] = "Remark3";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark4"] = 244] = "Remark4";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark5"] = 245] = "Remark5";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark6"] = 246] = "Remark6";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark7"] = 247] = "Remark7";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark8"] = 248] = "Remark8";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark9"] = 249] = "Remark9";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark10"] = 250] = "Remark10";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark11"] = 251] = "Remark11";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark12"] = 252] = "Remark12";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark13"] = 253] = "Remark13";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark14"] = 254] = "Remark14";
        TransactionAttributeUsage[TransactionAttributeUsage["Remark15"] = 255] = "Remark15";
    })(TransactionAttributeUsage = ThinNeo.TransactionAttributeUsage || (ThinNeo.TransactionAttributeUsage = {}));
    var Attribute = (function () {
        function Attribute() {
        }
        return Attribute;
    } ());
    ThinNeo.Attribute = Attribute;
    var TransactionOutput = (function () {
        function TransactionOutput() {
        }
        return TransactionOutput;
    } ());
    ThinNeo.TransactionOutput = TransactionOutput;
    var TransactionInput = (function () {
        function TransactionInput() {
        }
        return TransactionInput;
    } ());
    ThinNeo.TransactionInput = TransactionInput;
    var Witness = (function () {
        function Witness() {
        }
        Object.defineProperty(Witness.prototype, "Address", {
            get: function () {
                var hash = ThinNeo.Helper.GetScriptHashFromScript(this.VerificationScript);
                return ThinNeo.Helper.GetAddressFromScriptHash(hash);
            },
            enumerable: true,
            configurable: true
        });
        return Witness;
    } ());
    ThinNeo.Witness = Witness;
    var InvokeTransData = (function () {
        function InvokeTransData() {
        }
        InvokeTransData.prototype.Serialize = function (trans, writer) {
            writer.writeVarBytes(this.script.buffer);
            if (trans.version >= 1) {
                writer.writeUint64(this.gas.getData());
            }
        };
        InvokeTransData.prototype.Deserialize = function (trans, reader) {
            var buf = reader.readVarBytes(10000000);
            this.script = new Uint8Array(buf, 0, buf.byteLength);
            if (trans.version >= 1) {
                this.gas = new Neo.Fixed8(reader.readUint64());
            }
        };
        return InvokeTransData;
    } ());
    ThinNeo.InvokeTransData = InvokeTransData;
    var ClaimTransData = (function () {
        function ClaimTransData() {
        }
        ClaimTransData.prototype.Serialize = function (trans, writer) {
            writer.writeVarInt(this.claims.length);
            for (var i = 0; i < this.claims.length; i++) {
                writer.write(this.claims[i].hash, 0, 32);
                writer.writeUint16(this.claims[i].index);
            }
        };
        ClaimTransData.prototype.Deserialize = function (trans, reader) {
            var countClaims = reader.readVarInt();
            this.claims = [];
            for (var i = 0; i < countClaims; i++) {
                this.claims.push(new TransactionInput());
                var arr = reader.readBytes(32);
                this.claims[i].hash = new Uint8Array(arr, 0, arr.byteLength);
                this.claims[i].index = reader.readUint16();
            }
        };
        return ClaimTransData;
    } ());
    ThinNeo.ClaimTransData = ClaimTransData;
    var MinerTransData = (function () {
        function MinerTransData() {
        }
        MinerTransData.prototype.Serialize = function (trans, writer) {
            writer.writeUint32(this.nonce);
        };
        MinerTransData.prototype.Deserialize = function (trans, reader) {
            this.nonce = reader.readUint32();
        };
        return MinerTransData;
    } ());
    ThinNeo.MinerTransData = MinerTransData;
    var Transaction = (function () {
        function Transaction() {
        }
        Transaction.prototype.SerializeUnsigned = function (writer) {
            writer.writeByte(this.type);
            writer.writeByte(this.version);
            if (this.type == TransactionType.ContractTransaction ||
                this.type == TransactionType.IssueTransaction) {
            }
            else if (this.type == TransactionType.InvocationTransaction) {
                this.extdata.Serialize(this, writer);
            }
            else if (this.type == TransactionType.ClaimTransaction) {
                this.extdata.Serialize(this, writer);
            }
            else if (this.type == TransactionType.MinerTransaction) {
                this.extdata.Serialize(this, writer);
            }
            else {
                throw new Error("未编写针对这个交易类型的代码");
            }
            var countAttributes = this.attributes.length;
            writer.writeVarInt(countAttributes);
            for (var i = 0; i < countAttributes; i++) {
                var attributeData = this.attributes[i].data;
                var Usage = this.attributes[i].usage;
                writer.writeByte(Usage);
                if (Usage == TransactionAttributeUsage.ContractHash || Usage == TransactionAttributeUsage.Vote || (Usage >= TransactionAttributeUsage.Hash1 && Usage <= TransactionAttributeUsage.Hash15)) {
                    writer.write(attributeData.buffer, 0, 32);
                }
                else if (Usage == TransactionAttributeUsage.ECDH02 || Usage == TransactionAttributeUsage.ECDH03) {
                    writer.write(attributeData.buffer, 1, 32);
                }
                else if (Usage == TransactionAttributeUsage.Script) {
                    writer.write(attributeData.buffer, 0, 20);
                }
                else if (Usage == TransactionAttributeUsage.DescriptionUrl) {
                    var len = attributeData.length;
                    writer.writeByte(len);
                    writer.write(attributeData.buffer, 0, len);
                }
                else if (Usage == TransactionAttributeUsage.Description || Usage >= TransactionAttributeUsage.Remark) {
                    var len = attributeData.length;
                    writer.writeVarInt(len);
                    writer.write(attributeData.buffer, 0, len);
                }
                else
                    throw new Error();
            }
            var countInputs = this.inputs.length;
            writer.writeVarInt(countInputs);
            for (var i = 0; i < countInputs; i++) {
                writer.write(this.inputs[i].hash, 0, 32);
                writer.writeUint16(this.inputs[i].index);
            }
            var countOutputs = this.outputs.length;
            writer.writeVarInt(countOutputs);
            for (var i = 0; i < countOutputs; i++) {
                var item = this.outputs[i];
                writer.write(item.assetId.buffer, 0, 32);
                writer.writeUint64(item.value.getData());
                writer.write(item.toAddress.buffer, 0, 20);
            }
        };
        Transaction.prototype.Serialize = function (writer) {
            this.SerializeUnsigned(writer);
            var witnesscount = this.witnesses.length;
            writer.writeVarInt(witnesscount);
            for (var i = 0; i < witnesscount; i++) {
                var _witness = this.witnesses[i];
                writer.writeVarBytes(_witness.InvocationScript.buffer);
                writer.writeVarBytes(_witness.VerificationScript.buffer);
            }
        };
        Transaction.prototype.DeserializeUnsigned = function (ms) {
            this.type = ms.readByte();
            this.version = ms.readByte();
            if (this.type == TransactionType.ContractTransaction
                || this.type == TransactionType.IssueTransaction) {
                this.extdata = null;
            }
            else if (this.type == TransactionType.InvocationTransaction) {
                this.extdata = new InvokeTransData();
            }
            else if (this.type == TransactionType.ClaimTransaction) {
                this.extdata = new ClaimTransData();
            }
            else if (this.type == TransactionType.MinerTransaction) {
                this.extdata = new MinerTransData();
            }
            else {
                throw new Error("未编写针对这个交易类型的代码");
            }
            if (this.extdata != null) {
                this.extdata.Deserialize(this, ms);
            }
            var countAttributes = ms.readVarInt();
            this.attributes = [];
            for (var i = 0; i < countAttributes; i++) {
                var attributeData = null;
                var Usage = ms.readByte();
                if (Usage == TransactionAttributeUsage.ContractHash || Usage == TransactionAttributeUsage.Vote || (Usage >= TransactionAttributeUsage.Hash1 && Usage <= TransactionAttributeUsage.Hash15)) {
                    var arr = ms.readBytes(32);
                    attributeData = new Uint8Array(arr, 0, arr.byteLength);
                }
                else if (Usage == TransactionAttributeUsage.ECDH02 || Usage == TransactionAttributeUsage.ECDH03) {
                    var arr = ms.readBytes(32);
                    var data = new Uint8Array(arr, 0, arr.byteLength);
                    attributeData = new Uint8Array(33);
                    attributeData[0] = Usage;
                    for (var i = 0; i < 32; i++) {
                        attributeData[i + 1] = data[i];
                    }
                }
                else if (Usage == TransactionAttributeUsage.Script) {
                    var arr = ms.readBytes(20);
                    attributeData = new Uint8Array(arr, 0, arr.byteLength);
                }
                else if (Usage == TransactionAttributeUsage.DescriptionUrl) {
                    var len = ms.readByte();
                    var arr = ms.readBytes(len);
                    attributeData = new Uint8Array(arr, 0, arr.byteLength);
                }
                else if (Usage == TransactionAttributeUsage.Description || Usage >= TransactionAttributeUsage.Remark) {
                    var len = ms.readVarInt(65535);
                    var arr = ms.readBytes(len);
                    attributeData = new Uint8Array(arr, 0, arr.byteLength);
                }
                else
                    throw new Error();
                var attr = new Attribute();
                attr.usage = Usage;
                attr.data = attributeData;
                this.attributes.push(attr);
            }
            var countInputs = ms.readVarInt();
            this.inputs = [];
            for (var i = 0; i < countInputs; i++) {
                this.inputs.push(new TransactionInput());
                var arr = ms.readBytes(32);
                this.inputs[i].hash = new Uint8Array(arr, 0, arr.byteLength);
                this.inputs[i].index = ms.readUint16();
            }
            var countOutputs = ms.readVarInt();
            this.outputs = [];
            for (var i = 0; i < countOutputs; i++) {
                this.outputs.push(new TransactionOutput());
                var outp = this.outputs[i];
                var arr = ms.readBytes(32);
                var assetid = new Uint8Array(arr, 0, arr.byteLength);
                var value = new Neo.Fixed8(ms.readUint64());
                var arr = ms.readBytes(20);
                var scripthash = new Uint8Array(arr, 0, arr.byteLength);
                outp.assetId = assetid;
                outp.value = value;
                outp.toAddress = scripthash;
                this.outputs[i] = outp;
            }
        };
        Transaction.prototype.Deserialize = function (ms) {
            this.DeserializeUnsigned(ms);
            if (ms.canRead() > 0) {
                var witnesscount = ms.readVarInt();
                this.witnesses = [];
                for (var i = 0; i < witnesscount; i++) {
                    this.witnesses.push(new Witness());
                    this.witnesses[i].InvocationScript = new Uint8Array(ms.readVarBytes()).clone();
                    this.witnesses[i].VerificationScript = new Uint8Array(ms.readVarBytes()).clone();
                }
            }
        };
        Transaction.prototype.GetMessage = function () {
            var ms = new Neo.IO.MemoryStream();
            var writer = new Neo.IO.BinaryWriter(ms);
            this.SerializeUnsigned(writer);
            var arr = ms.toArray();
            var msg = new Uint8Array(arr, 0, arr.byteLength);
            return msg;
        };
        Transaction.prototype.GetRawData = function () {
            var ms = new Neo.IO.MemoryStream();
            var writer = new Neo.IO.BinaryWriter(ms);
            this.Serialize(writer);
            var arr = ms.toArray();
            var msg = new Uint8Array(arr, 0, arr.byteLength);
            return msg;
        };
        Transaction.prototype.AddWitness = function (signdata, pubkey, addrs) {
            {
                var msg = this.GetMessage();
                var bsign = ThinNeo.Helper.VerifySignature(msg, signdata, pubkey);
                if (bsign == false)
                    throw new Error("wrong sign");
                var addr = ThinNeo.Helper.GetAddressFromPublicKey(pubkey);
                if (addr != addrs)
                    throw new Error("wrong script");
            }
            var vscript = ThinNeo.Helper.GetAddressCheckScriptFromPublicKey(pubkey);
            var sb = new ThinNeo.ScriptBuilder();
            sb.EmitPushBytes(signdata);
            var iscript = sb.ToArray();
            this.AddWitnessScript(vscript, iscript);
        };
        Transaction.prototype.AddWitnessScript = function (vscript, iscript) {
            var scripthash = ThinNeo.Helper.GetScriptHashFromScript(vscript);
            if (this.witnesses == null)
                this.witnesses = [];
            var newwit = new Witness();
            newwit.VerificationScript = vscript;
            newwit.InvocationScript = iscript;
            for (var i = 0; i < this.witnesses.length; i++) {
                if (this.witnesses[i].Address == newwit.Address)
                    throw new Error("alread have this witness");
            }
            this.witnesses.push(newwit);
        };
        Transaction.prototype.GetHash = function () {
            var msg = this.GetMessage();
            var data = Neo.Cryptography.Sha256.computeHash(msg);
            data = Neo.Cryptography.Sha256.computeHash(data);
            return new Uint8Array(data, 0, data.byteLength);
        };
        return Transaction;
    } ());
    ThinNeo.Transaction = Transaction;
})(ThinNeo || (ThinNeo = {}));
var Neo;
(function (Neo) {
    var D = 100000000;
    var _max, _minus, _min, _one, _satoshi;
    var Fixed8 = (function () {
        function Fixed8(data) {
            this.data = data;
            if (data.bits[1] >= 0x80000000 && (data.bits[0] != 0xffffffff || data.bits[1] != 0xffffffff))
                throw new RangeError();
        }
        Object.defineProperty(Fixed8, "MaxValue", {
            get: function () { return _max || (_max = new Fixed8(new Neo.Uint64(0xffffffff, 0x7fffffff))); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Fixed8, "MinusOne", {
            get: function () { return _minus || (_minus = new Fixed8(new Neo.Uint64(0xffffffff, 0xffffffff))); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Fixed8, "MinValue", {
            get: function () { return _min || (_min = new Fixed8(Neo.Uint64.MinValue)); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Fixed8, "One", {
            get: function () { return _one || (_one = Fixed8.fromNumber(1)); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Fixed8, "Satoshi", {
            get: function () { return _satoshi || (_satoshi = new Fixed8(new Neo.Uint64(1))); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Fixed8, "Zero", {
            get: function () { return Fixed8.MinValue; },
            enumerable: true,
            configurable: true
        });
        Fixed8.prototype.add = function (other) {
            var result = this.data.add(other.data);
            if (result.compareTo(this.data) < 0)
                throw new Error();
            return new Fixed8(result);
        };
        Fixed8.prototype.compareTo = function (other) {
            return this.data.compareTo(other.data);
        };
        Fixed8.prototype.equals = function (other) {
            return this.data.equals(other.data);
        };
        Fixed8.fromNumber = function (value) {
            if (value < 0)
                throw new RangeError();
            value *= D;
            if (value >= 0x8000000000000000)
                throw new RangeError();
            var array = new Uint32Array((new Neo.BigInteger(value)).toUint8Array(true, 8).buffer);
            return new Fixed8(new Neo.Uint64(array[0], array[1]));
        };
        Fixed8.prototype.getData = function () {
            return this.data;
        };
        Fixed8.max = function (first) {
            var others = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                others[_i - 1] = arguments[_i];
            }
            for (var i = 0; i < others.length; i++)
                if (first.compareTo(others[i]) < 0)
                    first = others[i];
            return first;
        };
        Fixed8.min = function (first) {
            var others = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                others[_i - 1] = arguments[_i];
            }
            for (var i = 0; i < others.length; i++)
                if (first.compareTo(others[i]) > 0)
                    first = others[i];
            return first;
        };
        Fixed8.parse = function (str) {
            var dot = str.indexOf('.');
            var digits = dot >= 0 ? str.length - dot - 1 : 0;
            str = str.replace('.', '');
            if (digits > 8)
                str = str.substr(0, str.length - digits + 8);
            else if (digits < 8)
                for (var i = digits; i < 8; i++)
                    str += '0';
            return new Fixed8(Neo.Uint64.parse(str));
        };
        Fixed8.prototype.subtract = function (other) {
            if (this.data.compareTo(other.data) < 0)
                throw new Error();
            return new Fixed8(this.data.subtract(other.data));
        };
        Fixed8.prototype.toString = function () {
            var str = this.data.toString();
            while (str.length <= 8)
                str = '0' + str;
            str = str.substr(0, str.length - 8) + '.' + str.substr(str.length - 8);
            var e = 0;
            for (var i = str.length - 1; i >= 0; i--)
                if (str[i] == '0')
                    e++;
                else
                    break;
            str = str.substr(0, str.length - e);
            if (str[str.length - 1] == '.')
                str = str.substr(0, str.length - 1);
            return str;
        };
        Fixed8.prototype.deserialize = function (reader) {
            this.data = reader.readUint64();
        };
        Fixed8.prototype.serialize = function (writer) {
            writer.writeUint64(this.getData());
        };
        return Fixed8;
    } ());
    Neo.Fixed8 = Fixed8;
})(Neo || (Neo = {}));
Array.copy = function (src, srcOffset, dst, dstOffset, count) {
    for (var i = 0; i < count; i++)
        dst[i + dstOffset] = src[i + srcOffset];
};
Array.fromArray = function (arr) {
    var array = new Array(arr.length);
    for (var i = 0; i < array.length; i++)
        array[i] = arr[i];
    return array;
};
Uint8Array.fromArrayBuffer = function (buffer) {
    if (buffer instanceof Uint8Array)
        return buffer;
    else if (buffer instanceof ArrayBuffer)
        return new Uint8Array(buffer);
    else {
        var view = buffer;
        return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }
};
String.prototype.hexToBytes = function () {
    if ((this.length & 1) != 0)
        throw new RangeError();
    var str = this;
    if (this.length >= 2 && this[0] == '0' && this[1] == 'x')
        str = this.substr(2);
    var bytes = new Uint8Array(str.length / 2);
    for (var i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(str.substr(i * 2, 2), 16);
    }
    return bytes;
};
Uint8Array.prototype.clone = function () {
    var u8 = new Uint8Array(this.length);
    for (var i = 0; i < this.length; i++)
        u8[i] = this[i];
    return u8;
};
Uint8Array.prototype.toHexString = function () {
    var s = "";
    for (var i = 0; i < this.length; i++) {
        s += (this[i] >>> 4).toString(16);
        s += (this[i] & 0xf).toString(16);
    }
    return s;
};
var Neo;
(function (Neo) {
    var DB = 26;
    var DM = (1 << DB) - 1;
    var DV = DM + 1;
    var _minusone, _one, _zero;
    var BigInteger = (function () {
        function BigInteger(value) {
            this._sign = 0;
            this._bits = new Array();
            if (typeof value === "number") {
                if (!isFinite(value) || isNaN(value))
                    throw new RangeError();
                var parts = BigInteger.getDoubleParts(value);
                if (parts.man.equals(Neo.Uint64.Zero) || parts.exp <= -64)
                    return;
                if (parts.exp <= 0) {
                    this.fromUint64(parts.man.rightShift(-parts.exp), parts.sign);
                }
                else if (parts.exp <= 11) {
                    this.fromUint64(parts.man.leftShift(parts.exp), parts.sign);
                }
                else {
                    parts.man = parts.man.leftShift(11);
                    parts.exp -= 11;
                    var units = Math.ceil((parts.exp + 64) / DB);
                    var cu = Math.ceil(parts.exp / DB);
                    var cbit = cu * DB - parts.exp;
                    for (var i = cu; i < units; i++)
                        this._bits[i] = parts.man.rightShift(cbit + (i - cu) * DB).toUint32() & DM;
                    if (cbit > 0)
                        this._bits[cu - 1] = (parts.man.toUint32() << (DB - cbit)) & DM;
                    this._sign = parts.sign;
                    this.clamp();
                }
            }
            else if (typeof value === "string") {
                this.fromString(value);
            }
            else if (value instanceof Uint8Array) {
                this.fromUint8Array(value);
            }
            else if (value instanceof ArrayBuffer) {
                this.fromUint8Array(new Uint8Array(value));
            }
        }
        Object.defineProperty(BigInteger, "MinusOne", {
            get: function () { return _minusone || (_minusone = new BigInteger(-1)); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(BigInteger, "One", {
            get: function () { return _one || (_one = new BigInteger(1)); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(BigInteger, "Zero", {
            get: function () { return _zero || (_zero = new BigInteger(0)); },
            enumerable: true,
            configurable: true
        });
        BigInteger.add = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_x._sign == 0)
                return bi_y;
            if (bi_y._sign == 0)
                return bi_x;
            if ((bi_x._sign > 0) != (bi_y._sign > 0))
                return BigInteger.subtract(bi_x, bi_y.negate());
            var bits_r = new Array();
            BigInteger.addTo(bi_x._bits, bi_y._bits, bits_r);
            return BigInteger.create(bi_x._sign, bits_r);
        };
        BigInteger.prototype.add = function (other) {
            return BigInteger.add(this, other);
        };
        BigInteger.addTo = function (x, y, r) {
            if (x.length < y.length) {
                var t = x;
                x = y;
                y = t;
            }
            var c = 0, i = 0;
            while (i < y.length) {
                c += x[i] + y[i];
                r[i++] = c & DM;
                c >>>= DB;
            }
            while (i < x.length) {
                c += x[i];
                r[i++] = c & DM;
                c >>>= DB;
            }
            if (c > 0)
                r[i] = c;
        };
        BigInteger.prototype.bitLength = function () {
            var l = this._bits.length;
            if (l == 0)
                return 0;
            return --l * DB + BigInteger.bitLengthInternal(this._bits[l]);
        };
        BigInteger.bitLengthInternal = function (w) {
            return (w < 1 << 15 ? (w < 1 << 7
                ? (w < 1 << 3 ? (w < 1 << 1
                    ? (w < 1 << 0 ? (w < 0 ? 32 : 0) : 1)
                    : (w < 1 << 2 ? 2 : 3)) : (w < 1 << 5
                        ? (w < 1 << 4 ? 4 : 5)
                        : (w < 1 << 6 ? 6 : 7)))
                : (w < 1 << 11
                    ? (w < 1 << 9 ? (w < 1 << 8 ? 8 : 9) : (w < 1 << 10 ? 10 : 11))
                    : (w < 1 << 13 ? (w < 1 << 12 ? 12 : 13) : (w < 1 << 14 ? 14 : 15)))) : (w < 1 << 23 ? (w < 1 << 19
                        ? (w < 1 << 17 ? (w < 1 << 16 ? 16 : 17) : (w < 1 << 18 ? 18 : 19))
                        : (w < 1 << 21 ? (w < 1 << 20 ? 20 : 21) : (w < 1 << 22 ? 22 : 23))) : (w < 1 << 27
                            ? (w < 1 << 25 ? (w < 1 << 24 ? 24 : 25) : (w < 1 << 26 ? 26 : 27))
                            : (w < 1 << 29 ? (w < 1 << 28 ? 28 : 29) : (w < 1 << 30 ? 30 : 31)))));
        };
        BigInteger.prototype.clamp = function () {
            var l = this._bits.length;
            while (l > 0 && (this._bits[--l] | 0) == 0)
                this._bits.pop();
            while (l > 0)
                this._bits[--l] |= 0;
            if (this._bits.length == 0)
                this._sign = 0;
        };
        BigInteger.compare = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_x._sign >= 0 && bi_y._sign < 0)
                return +1;
            if (bi_x._sign < 0 && bi_y._sign >= 0)
                return -1;
            var c = BigInteger.compareAbs(bi_x, bi_y);
            return bi_x._sign < 0 ? -c : c;
        };
        BigInteger.compareAbs = function (x, y) {
            if (x._bits.length > y._bits.length)
                return +1;
            if (x._bits.length < y._bits.length)
                return -1;
            for (var i = x._bits.length - 1; i >= 0; i--)
                if (x._bits[i] > y._bits[i])
                    return +1;
                else if (x._bits[i] < y._bits[i])
                    return -1;
            return 0;
        };
        BigInteger.prototype.compareTo = function (other) {
            return BigInteger.compare(this, other);
        };
        BigInteger.create = function (sign, bits, clamp) {
            if (clamp === void 0) { clamp = false; }
            var bi = Object.create(BigInteger.prototype);
            bi._sign = sign;
            bi._bits = bits;
            if (clamp)
                bi.clamp();
            return bi;
        };
        BigInteger.divide = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            return BigInteger.divRem(bi_x, bi_y).result;
        };
        BigInteger.prototype.divide = function (other) {
            return BigInteger.divide(this, other);
        };
        BigInteger.divRem = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_y._sign == 0)
                throw new RangeError();
            if (bi_x._sign == 0)
                return { result: BigInteger.Zero, remainder: BigInteger.Zero };
            if (bi_y._sign == 1 && bi_y._bits == null)
                return { result: bi_x, remainder: BigInteger.Zero };
            if (bi_y._sign == -1 && bi_y._bits == null)
                return { result: bi_x.negate(), remainder: BigInteger.Zero };
            var sign_result = (bi_x._sign > 0) == (bi_y._sign > 0) ? +1 : -1;
            var c = BigInteger.compareAbs(bi_x, bi_y);
            if (c == 0)
                return { result: sign_result > 0 ? BigInteger.One : BigInteger.MinusOne, remainder: BigInteger.Zero };
            if (c < 0)
                return { result: BigInteger.Zero, remainder: bi_x };
            var bits_result = new Array();
            var bits_rem = new Array();
            Array.copy(bi_x._bits, 0, bits_rem, 0, bi_x._bits.length);
            var df = bi_y._bits[bi_y._bits.length - 1];
            for (var i = bi_x._bits.length - 1; i >= bi_y._bits.length - 1; i--) {
                var offset = i - bi_y._bits.length + 1;
                var d = bits_rem[i] + (bits_rem[i + 1] || 0) * DV;
                var max = Math.floor(d / df);
                if (max > DM)
                    max = DM;
                var min = 0;
                while (min != max) {
                    var bits_sub_1 = new Array(offset + bi_y._bits.length);
                    for (var i_1 = 0; i_1 < offset; i_1++)
                        bits_sub_1[i_1] = 0;
                    bits_result[offset] = Math.ceil((min + max) / 2);
                    BigInteger.multiplyTo(bi_y._bits, [bits_result[offset]], bits_sub_1, offset);
                    if (BigInteger.subtractTo(bits_rem, bits_sub_1))
                        max = bits_result[offset] - 1;
                    else
                        min = bits_result[offset];
                }
                var bits_sub = new Array(offset + bi_y._bits.length);
                for (var i_2 = 0; i_2 < offset; i_2++)
                    bits_sub[i_2] = 0;
                bits_result[offset] = min;
                BigInteger.multiplyTo(bi_y._bits, [bits_result[offset]], bits_sub, offset);
                BigInteger.subtractTo(bits_rem, bits_sub, bits_rem);
            }
            return { result: BigInteger.create(sign_result, bits_result, true), remainder: BigInteger.create(bi_x._sign, bits_rem, true) };
        };
        BigInteger.equals = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_x._sign != bi_y._sign)
                return false;
            if (bi_x._bits.length != bi_y._bits.length)
                return false;
            for (var i = 0; i < bi_x._bits.length; i++)
                if (bi_x._bits[i] != bi_y._bits[i])
                    return false;
            return true;
        };
        BigInteger.prototype.equals = function (other) {
            return BigInteger.equals(this, other);
        };
        BigInteger.fromString = function (str, radix) {
            if (radix === void 0) { radix = 10; }
            var bi = Object.create(BigInteger.prototype);
            bi.fromString(str, radix);
            return bi;
        };
        BigInteger.prototype.fromString = function (str, radix) {
            if (radix === void 0) { radix = 10; }
            if (radix < 2 || radix > 36)
                throw new RangeError();
            if (str.length == 0) {
                this._sign == 0;
                this._bits = [];
                return;
            }
            var bits_radix = [radix];
            var bits_a = [0];
            var first = str.charCodeAt(0);
            var withsign = first == 0x2b || first == 0x2d;
            this._sign = first == 0x2d ? -1 : +1;
            this._bits = [];
            for (var i = withsign ? 1 : 0; i < str.length; i++) {
                bits_a[0] = str.charCodeAt(i);
                if (bits_a[0] >= 0x30 && bits_a[0] <= 0x39)
                    bits_a[0] -= 0x30;
                else if (bits_a[0] >= 0x41 && bits_a[0] <= 0x5a)
                    bits_a[0] -= 0x37;
                else if (bits_a[0] >= 0x61 && bits_a[0] <= 0x7a)
                    bits_a[0] -= 0x57;
                else
                    throw new RangeError();
                var bits_temp = new Array();
                BigInteger.multiplyTo(this._bits, bits_radix, bits_temp);
                BigInteger.addTo(bits_temp, bits_a, this._bits);
            }
            this.clamp();
        };
        BigInteger.fromUint8Array = function (arr, sign, littleEndian) {
            if (sign === void 0) { sign = 1; }
            if (littleEndian === void 0) { littleEndian = true; }
            var bi = Object.create(BigInteger.prototype);
            bi.fromUint8Array(arr, sign, littleEndian);
            return bi;
        };
        BigInteger.prototype.fromUint8Array = function (arr, sign, littleEndian) {
            if (sign === void 0) { sign = 1; }
            if (littleEndian === void 0) { littleEndian = true; }
            if (!littleEndian) {
                var arr_new = new Uint8Array(arr.length);
                for (var i = 0; i < arr.length; i++)
                    arr_new[arr.length - 1 - i] = arr[i];
                arr = arr_new;
            }
            var actual_length = BigInteger.getActualLength(arr);
            var bits = actual_length * 8;
            var units = Math.ceil(bits / DB);
            this._bits = [];
            for (var i = 0; i < units; i++) {
                var cb = i * DB;
                var cu = Math.floor(cb / 8);
                cb %= 8;
                this._bits[i] = ((arr[cu] | arr[cu + 1] << 8 | arr[cu + 2] << 16 | arr[cu + 3] << 24) >>> cb) & DM;
            }
            this._sign = sign < 0 ? -1 : +1;
            this.clamp();
        };
        BigInteger.prototype.fromUint64 = function (i, sign) {
            while (i.bits[0] != 0 || i.bits[1] != 0) {
                this._bits.push(i.toUint32() & DM);
                i = i.rightShift(DB);
            }
            this._sign = sign;
            this.clamp();
        };
        BigInteger.getActualLength = function (arr) {
            var actual_length = arr.length;
            for (var i = arr.length - 1; i >= 0; i--)
                if (arr[i] != 0) {
                    actual_length = i + 1;
                    break;
                }
            return actual_length;
        };
        BigInteger.getDoubleParts = function (dbl) {
            var uu = new Uint32Array(2);
            new Float64Array(uu.buffer)[0] = dbl;
            var result = {
                sign: 1 - ((uu[1] >>> 30) & 2),
                man: new Neo.Uint64(uu[0], uu[1] & 0x000FFFFF),
                exp: (uu[1] >>> 20) & 0x7FF,
                fFinite: true
            };
            if (result.exp == 0) {
                if (!result.man.equals(Neo.Uint64.Zero))
                    result.exp = -1074;
            }
            else if (result.exp == 0x7FF) {
                result.fFinite = false;
            }
            else {
                result.man = result.man.or(new Neo.Uint64(0, 0x00100000));
                result.exp -= 1075;
            }
            return result;
        };
        BigInteger.prototype.getLowestSetBit = function () {
            if (this._sign == 0)
                return -1;
            var w = 0;
            while (this._bits[w] == 0)
                w++;
            for (var x = 0; x < DB; x++)
                if ((this._bits[w] & 1 << x) > 0)
                    return x + w * DB;
        };
        BigInteger.prototype.isEven = function () {
            if (this._sign == 0)
                return true;
            return (this._bits[0] & 1) == 0;
        };
        BigInteger.prototype.isZero = function () {
            return this._sign == 0;
        };
        BigInteger.prototype.leftShift = function (shift) {
            if (shift == 0)
                return this;
            var shift_units = Math.floor(shift / DB);
            shift %= DB;
            var bits_new = new Array(this._bits.length + shift_units);
            if (shift == 0) {
                for (var i = 0; i < this._bits.length; i++)
                    bits_new[i + shift_units] = this._bits[i];
            }
            else {
                for (var i = shift_units; i < bits_new.length; i++)
                    bits_new[i] = (this._bits[i - shift_units] << shift | this._bits[i - shift_units - 1] >>> (DB - shift)) & DM;
                bits_new[bits_new.length] = this._bits[this._bits.length - 1] >>> (DB - shift) & DM;
            }
            return BigInteger.create(this._sign, bits_new, true);
        };
        BigInteger.mod = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            var bi_new = BigInteger.divRem(bi_x, bi_y).remainder;
            if (bi_new._sign < 0)
                bi_new = BigInteger.add(bi_new, bi_y);
            return bi_new;
        };
        BigInteger.prototype.mod = function (other) {
            return BigInteger.mod(this, other);
        };
        BigInteger.modInverse = function (value, modulus) {
            var a = typeof value === "number" ? new BigInteger(value) : value;
            var n = typeof modulus === "number" ? new BigInteger(modulus) : modulus;
            var i = n, v = BigInteger.Zero, d = BigInteger.One;
            while (a._sign > 0) {
                var t = BigInteger.divRem(i, a);
                var x = d;
                i = a;
                a = t.remainder;
                d = v.subtract(t.result.multiply(x));
                v = x;
            }
            return BigInteger.mod(v, n);
        };
        BigInteger.prototype.modInverse = function (modulus) {
            return BigInteger.modInverse(this, modulus);
        };
        BigInteger.modPow = function (value, exponent, modulus) {
            var bi_v = typeof value === "number" ? new BigInteger(value) : value;
            var bi_e = typeof exponent === "number" ? new BigInteger(exponent) : exponent;
            var bi_m = typeof modulus === "number" ? new BigInteger(modulus) : modulus;
            if (bi_e._sign < 0 || bi_m._sign == 0)
                throw new RangeError();
            if (Math.abs(bi_m._sign) == 1 && bi_m._bits == null)
                return BigInteger.Zero;
            var h = bi_e.bitLength();
            var bi_new = BigInteger.One;
            for (var i = 0; i < h; i++) {
                if (i > 0)
                    bi_v = BigInteger.multiply(bi_v, bi_v);
                bi_v = bi_v.remainder(bi_m);
                if (bi_e.testBit(i))
                    bi_new = BigInteger.multiply(bi_v, bi_new).remainder(bi_m);
            }
            if (bi_new._sign < 0)
                bi_new = BigInteger.add(bi_new, bi_m);
            return bi_new;
        };
        BigInteger.prototype.modPow = function (exponent, modulus) {
            return BigInteger.modPow(this, exponent, modulus);
        };
        BigInteger.multiply = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_x._sign == 0)
                return bi_x;
            if (bi_y._sign == 0)
                return bi_y;
            if (bi_x._sign == 1 && bi_x._bits == null)
                return bi_y;
            if (bi_x._sign == -1 && bi_x._bits == null)
                return bi_y.negate();
            if (bi_y._sign == 1 && bi_y._bits == null)
                return bi_x;
            if (bi_y._sign == -1 && bi_y._bits == null)
                return bi_x.negate();
            var bits_r = new Array();
            BigInteger.multiplyTo(bi_x._bits, bi_y._bits, bits_r);
            return BigInteger.create((bi_x._sign > 0) == (bi_y._sign > 0) ? +1 : -1, bits_r);
        };
        BigInteger.prototype.multiply = function (other) {
            return BigInteger.multiply(this, other);
        };
        BigInteger.multiplyTo = function (x, y, r, offset) {
            if (offset === void 0) { offset = 0; }
            if (x.length > y.length) {
                var t = x;
                x = y;
                y = t;
            }
            for (var i = x.length + y.length - 2; i >= 0; i--)
                r[i + offset] = 0;
            for (var i = 0; i < x.length; i++) {
                if (x[i] == 0)
                    continue;
                for (var j = 0; j < y.length; j++) {
                    var c = x[i] * y[j];
                    if (c == 0)
                        continue;
                    var k = i + j;
                    do {
                        c += r[k + offset] || 0;
                        r[k + offset] = c & DM;
                        c = Math.floor(c / DV);
                        k++;
                    } while (c > 0);
                }
            }
        };
        BigInteger.prototype.negate = function () {
            return BigInteger.create(-this._sign, this._bits);
        };
        BigInteger.parse = function (str) {
            return BigInteger.fromString(str);
        };
        BigInteger.pow = function (value, exponent) {
            var bi_v = typeof value === "number" ? new BigInteger(value) : value;
            if (exponent < 0 || exponent > 0x7fffffff)
                throw new RangeError();
            if (exponent == 0)
                return BigInteger.One;
            if (exponent == 1)
                return bi_v;
            if (bi_v._sign == 0)
                return bi_v;
            if (bi_v._bits.length == 1) {
                if (bi_v._bits[0] == 1)
                    return bi_v;
                if (bi_v._bits[0] == -1)
                    return (exponent & 1) != 0 ? bi_v : BigInteger.One;
            }
            var h = BigInteger.bitLengthInternal(exponent);
            var bi_new = BigInteger.One;
            for (var i = 0; i < h; i++) {
                var e = 1 << i;
                if (e > 1)
                    bi_v = BigInteger.multiply(bi_v, bi_v);
                if ((exponent & e) != 0)
                    bi_new = BigInteger.multiply(bi_v, bi_new);
            }
            return bi_new;
        };
        BigInteger.prototype.pow = function (exponent) {
            return BigInteger.pow(this, exponent);
        };
        BigInteger.random = function (bitLength, rng) {
            if (bitLength == 0)
                return BigInteger.Zero;
            var bytes = new Uint8Array(Math.ceil(bitLength / 8));
            if (rng == null) {
                for (var i = 0; i < bytes.length; i++)
                    bytes[i] = Math.random() * 256;
            }
            else {
                rng.getRandomValues(bytes);
            }
            bytes[bytes.length - 1] &= 0xff >>> (8 - bitLength % 8);
            return new BigInteger(bytes);
        };
        BigInteger.remainder = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            return BigInteger.divRem(bi_x, bi_y).remainder;
        };
        BigInteger.prototype.remainder = function (other) {
            return BigInteger.remainder(this, other);
        };
        BigInteger.prototype.rightShift = function (shift) {
            if (shift == 0)
                return this;
            var shift_units = Math.floor(shift / DB);
            shift %= DB;
            if (this._bits.length <= shift_units)
                return BigInteger.Zero;
            var bits_new = new Array(this._bits.length - shift_units);
            if (shift == 0) {
                for (var i = 0; i < bits_new.length; i++)
                    bits_new[i] = this._bits[i + shift_units];
            }
            else {
                for (var i = 0; i < bits_new.length; i++)
                    bits_new[i] = (this._bits[i + shift_units] >>> shift | this._bits[i + shift_units + 1] << (DB - shift)) & DM;
            }
            return BigInteger.create(this._sign, bits_new, true);
        };
        BigInteger.prototype.sign = function () {
            return this._sign;
        };
        BigInteger.subtract = function (x, y) {
            var bi_x = typeof x === "number" ? new BigInteger(x) : x;
            var bi_y = typeof y === "number" ? new BigInteger(y) : y;
            if (bi_x._sign == 0)
                return bi_y.negate();
            if (bi_y._sign == 0)
                return bi_x;
            if ((bi_x._sign > 0) != (bi_y._sign > 0))
                return BigInteger.add(bi_x, bi_y.negate());
            var c = BigInteger.compareAbs(bi_x, bi_y);
            if (c == 0)
                return BigInteger.Zero;
            if (c < 0)
                return BigInteger.subtract(bi_y, bi_x).negate();
            var bits_r = new Array();
            BigInteger.subtractTo(bi_x._bits, bi_y._bits, bits_r);
            return BigInteger.create(bi_x._sign, bits_r, true);
        };
        BigInteger.prototype.subtract = function (other) {
            return BigInteger.subtract(this, other);
        };
        BigInteger.subtractTo = function (x, y, r) {
            if (r == null)
                r = [];
            var l = Math.min(x.length, y.length);
            var c = 0, i = 0;
            while (i < l) {
                c += x[i] - y[i];
                r[i++] = c & DM;
                c >>= DB;
            }
            if (x.length < y.length)
                while (i < y.length) {
                    c -= y[i];
                    r[i++] = c & DM;
                    c >>= DB;
                }
            else
                while (i < x.length) {
                    c += x[i];
                    r[i++] = c & DM;
                    c >>= DB;
                }
            return c < 0;
        };
        BigInteger.prototype.testBit = function (n) {
            var units = Math.floor(n / DB);
            if (this._bits.length <= units)
                return false;
            return (this._bits[units] & (1 << (n %= DB))) != 0;
        };
        BigInteger.prototype.toInt32 = function () {
            if (this._sign == 0)
                return 0;
            if (this._bits.length == 1)
                return this._bits[0] * this._sign;
            return ((this._bits[0] | this._bits[1] * DV) & 0x7fffffff) * this._sign;
        };
        BigInteger.prototype.toString = function (radix) {
            if (radix === void 0) { radix = 10; }
            if (this._sign == 0)
                return "0";
            if (radix < 2 || radix > 36)
                throw new RangeError();
            var s = "";
            for (var bi = this; bi._sign != 0;) {
                var r = BigInteger.divRem(bi, radix);
                var rem = Math.abs(r.remainder.toInt32());
                if (rem < 10)
                    rem += 0x30;
                else
                    rem += 0x57;
                s = String.fromCharCode(rem) + s;
                bi = r.result;
            }
            if (this._sign < 0)
                s = "-" + s;
            return s;
        };
        BigInteger.prototype.toUint8Array = function (littleEndian, length) {
            if (littleEndian === void 0) { littleEndian = true; }
            if (this._sign == 0)
                return new Uint8Array(length || 1);
            var cb = Math.ceil(this._bits.length * DB / 8);
            var array = new Uint8Array(length || cb);
            for (var i = 0; i < array.length; i++) {
                var offset = littleEndian ? i : array.length - 1 - i;
                var cbits = i * 8;
                var cu = Math.floor(cbits / DB);
                cbits %= DB;
                if (DB - cbits < 8)
                    array[offset] = (this._bits[cu] >>> cbits | this._bits[cu + 1] << (DB - cbits)) & 0xff;
                else
                    array[offset] = this._bits[cu] >>> cbits & 0xff;
            }
            length = length || BigInteger.getActualLength(array);
            if (length < array.length)
                array = array.subarray(0, length);
            return array;
        };
        return BigInteger;
    } ());
    Neo.BigInteger = BigInteger;
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var IO;
    (function (IO) {
        var BinaryReader = (function () {
            function BinaryReader(input) {
                this.input = input;
                this._buffer = new ArrayBuffer(8);
            }
            BinaryReader.prototype.canRead = function () {
                return this.input.length() - this.input.position();
            };
            BinaryReader.prototype.close = function () {
            };
            BinaryReader.prototype.fillBuffer = function (buffer, count) {
                var i = 0;
                while (count > 0) {
                    var actual_count = this.input.read(buffer, 0, count);
                    if (actual_count == 0)
                        throw new Error("EOF");
                    i += actual_count;
                    count -= actual_count;
                }
            };
            BinaryReader.prototype.read = function (buffer, index, count) {
                return this.input.read(buffer, index, count);
            };
            BinaryReader.prototype.readBoolean = function () {
                return this.readByte() != 0;
            };
            BinaryReader.prototype.readByte = function () {
                this.fillBuffer(this._buffer, 1);
                if (this.array_uint8 == null)
                    this.array_uint8 = new Uint8Array(this._buffer, 0, 1);
                return this.array_uint8[0];
            };
            BinaryReader.prototype.readBytes = function (count) {
                var buffer = new ArrayBuffer(count);
                this.fillBuffer(buffer, count);
                return buffer;
            };
            BinaryReader.prototype.readDouble = function () {
                this.fillBuffer(this._buffer, 8);
                if (this.array_float64 == null)
                    this.array_float64 = new Float64Array(this._buffer, 0, 1);
                return this.array_float64[0];
            };
            BinaryReader.prototype.readFixed8 = function () {
                return new Neo.Fixed8(this.readUint64());
            };
            BinaryReader.prototype.readInt16 = function () {
                this.fillBuffer(this._buffer, 2);
                if (this.array_int16 == null)
                    this.array_int16 = new Int16Array(this._buffer, 0, 1);
                return this.array_int16[0];
            };
            BinaryReader.prototype.readInt32 = function () {
                this.fillBuffer(this._buffer, 4);
                if (this.array_int32 == null)
                    this.array_int32 = new Int32Array(this._buffer, 0, 1);
                return this.array_int32[0];
            };
            BinaryReader.prototype.readSByte = function () {
                this.fillBuffer(this._buffer, 1);
                if (this.array_int8 == null)
                    this.array_int8 = new Int8Array(this._buffer, 0, 1);
                return this.array_int8[0];
            };
            BinaryReader.prototype.readSerializable = function (T) {
                var obj = new T();
                obj.deserialize(this);
                return obj;
            };
            BinaryReader.prototype.readSerializableArray = function (T) {
                var array = new Array(this.readVarInt(0x10000000));
                for (var i = 0; i < array.length; i++)
                    array[i] = this.readSerializable(T);
                return array;
            };
            BinaryReader.prototype.readSingle = function () {
                this.fillBuffer(this._buffer, 4);
                if (this.array_float32 == null)
                    this.array_float32 = new Float32Array(this._buffer, 0, 1);
                return this.array_float32[0];
            };
            BinaryReader.prototype.readUint16 = function () {
                this.fillBuffer(this._buffer, 2);
                if (this.array_uint16 == null)
                    this.array_uint16 = new Uint16Array(this._buffer, 0, 1);
                return this.array_uint16[0];
            };
            BinaryReader.prototype.readUint160 = function () {
                return new Neo.Uint160(this.readBytes(20));
            };
            BinaryReader.prototype.readUint256 = function () {
                return new Neo.Uint256(this.readBytes(32));
            };
            BinaryReader.prototype.readUint32 = function () {
                this.fillBuffer(this._buffer, 4);
                if (this.array_uint32 == null)
                    this.array_uint32 = new Uint32Array(this._buffer, 0, 1);
                return this.array_uint32[0];
            };
            BinaryReader.prototype.readUint64 = function () {
                this.fillBuffer(this._buffer, 8);
                if (this.array_uint32 == null)
                    this.array_uint32 = new Uint32Array(this._buffer, 0, 2);
                return new Neo.Uint64(this.array_uint32[0], this.array_uint32[1]);
            };
            BinaryReader.prototype.readVarBytes = function (max) {
                if (max === void 0) { max = 0X7fffffc7; }
                return this.readBytes(this.readVarInt(max));
            };
            BinaryReader.prototype.readVarInt = function (max) {
                if (max === void 0) { max = 9007199254740991; }
                var fb = this.readByte();
                var value;
                if (fb == 0xfd)
                    value = this.readUint16();
                else if (fb == 0xfe)
                    value = this.readUint32();
                else if (fb == 0xff)
                    value = this.readUint64().toNumber();
                else
                    value = fb;
                if (value > max)
                    throw new RangeError();
                return value;
            };
            BinaryReader.prototype.readVarString = function () {
                return decodeURIComponent(escape(String.fromCharCode.apply(null, new Uint8Array(this.readVarBytes()))));
            };
            return BinaryReader;
        } ());
        IO.BinaryReader = BinaryReader;
    })(IO = Neo.IO || (Neo.IO = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var IO;
    (function (IO) {
        var BinaryWriter = (function () {
            function BinaryWriter(output) {
                this.output = output;
                this._buffer = new ArrayBuffer(8);
            }
            BinaryWriter.prototype.close = function () {
            };
            BinaryWriter.prototype.seek = function (offset, origin) {
                return this.output.seek(offset, origin);
            };
            BinaryWriter.prototype.write = function (buffer, index, count) {
                if (index === void 0) { index = 0; }
                if (count === void 0) { count = buffer.byteLength - index; }
                this.output.write(buffer, index, count);
            };
            BinaryWriter.prototype.writeBoolean = function (value) {
                this.writeByte(value ? 0xff : 0);
            };
            BinaryWriter.prototype.writeByte = function (value) {
                if (this.array_uint8 == null)
                    this.array_uint8 = new Uint8Array(this._buffer, 0, 1);
                this.array_uint8[0] = value;
                this.output.write(this._buffer, 0, 1);
            };
            BinaryWriter.prototype.writeDouble = function (value) {
                if (this.array_float64 == null)
                    this.array_float64 = new Float64Array(this._buffer, 0, 1);
                this.array_float64[0] = value;
                this.output.write(this._buffer, 0, 8);
            };
            BinaryWriter.prototype.writeInt16 = function (value) {
                if (this.array_int16 == null)
                    this.array_int16 = new Int16Array(this._buffer, 0, 1);
                this.array_int16[0] = value;
                this.output.write(this._buffer, 0, 2);
            };
            BinaryWriter.prototype.writeInt32 = function (value) {
                if (this.array_int32 == null)
                    this.array_int32 = new Int32Array(this._buffer, 0, 1);
                this.array_int32[0] = value;
                this.output.write(this._buffer, 0, 4);
            };
            BinaryWriter.prototype.writeSByte = function (value) {
                if (this.array_int8 == null)
                    this.array_int8 = new Int8Array(this._buffer, 0, 1);
                this.array_int8[0] = value;
                this.output.write(this._buffer, 0, 1);
            };
            BinaryWriter.prototype.writeSerializableArray = function (array) {
                this.writeVarInt(array.length);
                for (var i = 0; i < array.length; i++)
                    array[i].serialize(this);
            };
            BinaryWriter.prototype.writeSingle = function (value) {
                if (this.array_float32 == null)
                    this.array_float32 = new Float32Array(this._buffer, 0, 1);
                this.array_float32[0] = value;
                this.output.write(this._buffer, 0, 4);
            };
            BinaryWriter.prototype.writeUint16 = function (value) {
                if (this.array_uint16 == null)
                    this.array_uint16 = new Uint16Array(this._buffer, 0, 1);
                this.array_uint16[0] = value;
                this.output.write(this._buffer, 0, 2);
            };
            BinaryWriter.prototype.writeUint32 = function (value) {
                if (this.array_uint32 == null)
                    this.array_uint32 = new Uint32Array(this._buffer, 0, 1);
                this.array_uint32[0] = value;
                this.output.write(this._buffer, 0, 4);
            };
            BinaryWriter.prototype.writeUint64 = function (value) {
                this.writeUintVariable(value);
            };
            BinaryWriter.prototype.writeUintVariable = function (value) {
                this.write(value.bits.buffer);
            };
            BinaryWriter.prototype.writeVarBytes = function (value) {
                this.writeVarInt(value.byteLength);
                this.output.write(value, 0, value.byteLength);
            };
            BinaryWriter.prototype.writeVarInt = function (value) {
                if (value < 0)
                    throw new RangeError();
                if (value < 0xfd) {
                    this.writeByte(value);
                }
                else if (value <= 0xffff) {
                    this.writeByte(0xfd);
                    this.writeUint16(value);
                }
                else if (value <= 0xFFFFFFFF) {
                    this.writeByte(0xfe);
                    this.writeUint32(value);
                }
                else {
                    this.writeByte(0xff);
                    this.writeUint32(value);
                    this.writeUint32(value / Math.pow(2, 32));
                }
            };
            BinaryWriter.prototype.writeVarString = function (value) {
                value = unescape(encodeURIComponent(value));
                var codes = new Uint8Array(value.length);
                for (var i = 0; i < codes.length; i++)
                    codes[i] = value.charCodeAt(i);
                this.writeVarBytes(codes.buffer);
            };
            return BinaryWriter;
        } ());
        IO.BinaryWriter = BinaryWriter;
    })(IO = Neo.IO || (Neo.IO = {}));
})(Neo || (Neo = {}));
Uint8Array.prototype.asSerializable = function (T) {
    var ms = new Neo.IO.MemoryStream(this.buffer, false);
    var reader = new Neo.IO.BinaryReader(ms);
    return reader.readSerializable(T);
};
Uint8Array.fromSerializable = function (obj) {
    var ms = new Neo.IO.MemoryStream();
    var writer = new Neo.IO.BinaryWriter(ms);
    obj.serialize(writer);
    return new Uint8Array(ms.toArray());
};
var Neo;
(function (Neo) {
    var IO;
    (function (IO) {
        var SeekOrigin;
        (function (SeekOrigin) {
            SeekOrigin[SeekOrigin["Begin"] = 0] = "Begin";
            SeekOrigin[SeekOrigin["Current"] = 1] = "Current";
            SeekOrigin[SeekOrigin["End"] = 2] = "End";
        })(SeekOrigin = IO.SeekOrigin || (IO.SeekOrigin = {}));
        var Stream = (function () {
            function Stream() {
                this._array = new Uint8Array(1);
            }
            Stream.prototype.close = function () { };
            Stream.prototype.readByte = function () {
                if (this.read(this._array.buffer, 0, 1) == 0)
                    return -1;
                return this._array[0];
            };
            Stream.prototype.writeByte = function (value) {
                if (value < 0 || value > 255)
                    throw new RangeError();
                this._array[0] = value;
                this.write(this._array.buffer, 0, 1);
            };
            return Stream;
        } ());
        IO.Stream = Stream;
    })(IO = Neo.IO || (Neo.IO = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var IO;
    (function (IO) {
        var BufferSize = 1024;
        var MemoryStream = (function (_super) {
            __extends(MemoryStream, _super);
            function MemoryStream() {
                var _this = _super.call(this) || this;
                _this._buffers = new Array();
                _this._origin = 0;
                _this._position = 0;
                if (arguments.length == 0) {
                    _this._length = 0;
                    _this._capacity = 0;
                    _this._expandable = true;
                    _this._writable = true;
                }
                else if (arguments.length == 1 && typeof arguments[0] === "number") {
                    _this._length = 0;
                    _this._capacity = arguments[0];
                    _this._expandable = true;
                    _this._writable = true;
                    _this._buffers.push(new ArrayBuffer(_this._capacity));
                }
                else {
                    var buffer = arguments[0];
                    _this._buffers.push(buffer);
                    _this._expandable = false;
                    if (arguments.length == 1) {
                        _this._writable = false;
                        _this._length = buffer.byteLength;
                    }
                    else if (typeof arguments[1] === "boolean") {
                        _this._writable = arguments[1];
                        _this._length = buffer.byteLength;
                    }
                    else {
                        _this._origin = arguments[1];
                        _this._length = arguments[2];
                        _this._writable = arguments.length == 4 ? arguments[3] : false;
                        if (_this._origin < 0 || _this._origin + _this._length > buffer.byteLength)
                            throw new RangeError();
                    }
                    _this._capacity = _this._length;
                }
                return _this;
            }
            MemoryStream.prototype.canRead = function () {
                return true;
            };
            MemoryStream.prototype.canSeek = function () {
                return true;
            };
            MemoryStream.prototype.canWrite = function () {
                return this._writable;
            };
            MemoryStream.prototype.capacity = function () {
                return this._capacity;
            };
            MemoryStream.prototype.findBuffer = function (position) {
                var iBuff, pBuff;
                var firstSize = this._buffers[0] == null ? BufferSize : this._buffers[0].byteLength;
                if (position < firstSize) {
                    iBuff = 0;
                    pBuff = position;
                }
                else {
                    iBuff = Math.floor((position - firstSize) / BufferSize) + 1;
                    pBuff = (position - firstSize) % BufferSize;
                }
                return { iBuff: iBuff, pBuff: pBuff };
            };
            MemoryStream.prototype.length = function () {
                return this._length;
            };
            MemoryStream.prototype.position = function () {
                return this._position;
            };
            MemoryStream.prototype.read = function (buffer, offset, count) {
                if (this._position + count > this._length)
                    count = this._length - this._position;
                this.readInternal(new Uint8Array(buffer, offset, count), this._position);
                this._position += count;
                return count;
            };
            MemoryStream.prototype.readInternal = function (dst, srcPos) {
                if (this._expandable) {
                    var i = 0, count = dst.length;
                    var d = this.findBuffer(srcPos);
                    while (count > 0) {
                        var actual_count = void 0;
                        if (this._buffers[d.iBuff] == null) {
                            actual_count = Math.min(count, BufferSize - d.pBuff);
                            dst.fill(0, i, i + actual_count);
                        }
                        else {
                            actual_count = Math.min(count, this._buffers[d.iBuff].byteLength - d.pBuff);
                            var src = new Uint8Array(this._buffers[d.iBuff]);
                            Array.copy(src, d.pBuff, dst, i, actual_count);
                        }
                        i += actual_count;
                        count -= actual_count;
                        d.iBuff++;
                        d.pBuff = 0;
                    }
                }
                else {
                    var src = new Uint8Array(this._buffers[0], this._origin, this._length);
                    Array.copy(src, srcPos, dst, 0, dst.length);
                }
            };
            MemoryStream.prototype.seek = function (offset, origin) {
                switch (origin) {
                    case IO.SeekOrigin.Begin:
                        break;
                    case IO.SeekOrigin.Current:
                        offset += this._position;
                        break;
                    case IO.SeekOrigin.End:
                        offset += this._length;
                        break;
                    default:
                        throw new RangeError();
                }
                if (offset < 0 || offset > this._length)
                    throw new RangeError();
                this._position = offset;
                return offset;
            };
            MemoryStream.prototype.setLength = function (value) {
                if (value < 0 || (value != this._length && !this._writable) || (value > this._capacity && !this._expandable))
                    throw new RangeError();
                this._length = value;
                if (this._position > this._length)
                    this._position = this._length;
                if (this._capacity < this._length)
                    this._capacity = this._length;
            };
            MemoryStream.prototype.toArray = function () {
                if (this._buffers.length == 1 && this._origin == 0 && this._length == this._buffers[0].byteLength)
                    return this._buffers[0];
                var bw = new Uint8Array(this._length);
                this.readInternal(bw, 0);
                return bw.buffer;
            };
            MemoryStream.prototype.write = function (buffer, offset, count) {
                if (!this._writable || (!this._expandable && this._capacity - this._position < count))
                    throw new Error();
                if (this._expandable) {
                    var src = new Uint8Array(buffer);
                    var d = this.findBuffer(this._position);
                    while (count > 0) {
                        if (this._buffers[d.iBuff] == null)
                            this._buffers[d.iBuff] = new ArrayBuffer(BufferSize);
                        var actual_count = Math.min(count, this._buffers[d.iBuff].byteLength - d.pBuff);
                        var dst = new Uint8Array(this._buffers[d.iBuff]);
                        Array.copy(src, offset, dst, d.pBuff, actual_count);
                        this._position += actual_count;
                        offset += actual_count;
                        count -= actual_count;
                        d.iBuff++;
                        d.pBuff = 0;
                    }
                }
                else {
                    var src = new Uint8Array(buffer, offset, count);
                    var dst = new Uint8Array(this._buffers[0], this._origin, this._capacity);
                    Array.copy(src, 0, dst, this._position, count);
                    this._position += count;
                }
                if (this._length < this._position)
                    this._length = this._position;
                if (this._capacity < this._length)
                    this._capacity = this._length;
            };
            return MemoryStream;
        } (IO.Stream));
        IO.MemoryStream = MemoryStream;
    })(IO = Neo.IO || (Neo.IO = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var UintVariable = (function () {
        function UintVariable(bits) {
            if (typeof bits === "number") {
                if (bits <= 0 || bits % 32 != 0)
                    throw new RangeError();
                this._bits = new Uint32Array(bits / 32);
            }
            else if (bits instanceof Uint8Array) {
                if (bits.length == 0 || bits.length % 4 != 0)
                    throw new RangeError();
                if (bits.byteOffset % 4 == 0) {
                    this._bits = new Uint32Array(bits.buffer, bits.byteOffset, bits.length / 4);
                }
                else {
                    var bits_new = new Uint8Array(bits);
                    this._bits = new Uint32Array(bits_new.buffer);
                }
            }
            else if (bits instanceof Uint32Array) {
                this._bits = bits;
            }
            else if (bits instanceof Array) {
                if (bits.length == 0)
                    throw new RangeError();
                this._bits = new Uint32Array(bits);
            }
        }
        Object.defineProperty(UintVariable.prototype, "bits", {
            get: function () {
                return this._bits;
            },
            enumerable: true,
            configurable: true
        });
        UintVariable.prototype.compareTo = function (other) {
            var max = Math.max(this._bits.length, other._bits.length);
            for (var i = max - 1; i >= 0; i--)
                if ((this._bits[i] || 0) > (other._bits[i] || 0))
                    return 1;
                else if ((this._bits[i] || 0) < (other._bits[i] || 0))
                    return -1;
            return 0;
        };
        UintVariable.prototype.equals = function (other) {
            var max = Math.max(this._bits.length, other._bits.length);
            for (var i = 0; i < max; i++)
                if ((this._bits[i] || 0) != (other._bits[i] || 0))
                    return false;
            return true;
        };
        UintVariable.prototype.toString = function () {
            var s = "";
            for (var i = this._bits.length * 32 - 4; i >= 0; i -= 4)
                s += ((this._bits[i >>> 5] >>> (i % 32)) & 0xf).toString(16);
            return s;
        };
        return UintVariable;
    } ());
    Neo.UintVariable = UintVariable;
    var _max, _min;
    var Uint64 = (function (_super) {
        __extends(Uint64, _super);
        function Uint64(low, high) {
            if (low === void 0) { low = 0; }
            if (high === void 0) { high = 0; }
            return _super.call(this, [low, high]) || this;
        }
        Object.defineProperty(Uint64, "MaxValue", {
            get: function () { return _max || (_max = new Uint64(0xffffffff, 0xffffffff)); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Uint64, "MinValue", {
            get: function () { return _min || (_min = new Uint64()); },
            enumerable: true,
            configurable: true
        });
        Object.defineProperty(Uint64, "Zero", {
            get: function () { return Uint64.MinValue; },
            enumerable: true,
            configurable: true
        });
        Uint64.prototype.add = function (other) {
            var low = this._bits[0] + other._bits[0];
            var high = this._bits[1] + other._bits[1] + (low > 0xffffffff ? 1 : 0);
            return new Uint64(low, high);
        };
        Uint64.prototype.and = function (other) {
            if (typeof other === "number") {
                return this.and(new Uint64(other));
            }
            else {
                var bits = new Uint32Array(this._bits.length);
                for (var i = 0; i < bits.length; i++)
                    bits[i] = this._bits[i] & other._bits[i];
                return new Uint64(bits[0], bits[1]);
            }
        };
        Uint64.prototype.leftShift = function (shift) {
            if (shift == 0)
                return this;
            var shift_units = shift >>> 5;
            shift = shift & 0x1f;
            var bits = new Uint32Array(this._bits.length);
            for (var i = shift_units; i < bits.length; i++)
                if (shift == 0)
                    bits[i] = this._bits[i - shift_units];
                else
                    bits[i] = this._bits[i - shift_units] << shift | this._bits[i - shift_units - 1] >>> (32 - shift);
            return new Uint64(bits[0], bits[1]);
        };
        Uint64.prototype.not = function () {
            var bits = new Uint32Array(this._bits.length);
            for (var i = 0; i < bits.length; i++)
                bits[i] = ~this._bits[i];
            return new Uint64(bits[0], bits[1]);
        };
        Uint64.prototype.or = function (other) {
            if (typeof other === "number") {
                return this.or(new Uint64(other));
            }
            else {
                var bits = new Uint32Array(this._bits.length);
                for (var i = 0; i < bits.length; i++)
                    bits[i] = this._bits[i] | other._bits[i];
                return new Uint64(bits[0], bits[1]);
            }
        };
        Uint64.parse = function (str) {
            var bi = Neo.BigInteger.parse(str);
            if (bi.bitLength() > 64)
                throw new RangeError();
            var array = new Uint32Array(bi.toUint8Array(true, 8).buffer);
            return new Uint64(array[0], array[1]);
        };
        Uint64.prototype.rightShift = function (shift) {
            if (shift == 0)
                return this;
            var shift_units = shift >>> 5;
            shift = shift & 0x1f;
            var bits = new Uint32Array(this._bits.length);
            for (var i = 0; i < bits.length - shift_units; i++)
                if (shift == 0)
                    bits[i] = this._bits[i + shift_units];
                else
                    bits[i] = this._bits[i + shift_units] >>> shift | this._bits[i + shift_units + 1] << (32 - shift);
            return new Uint64(bits[0], bits[1]);
        };
        Uint64.prototype.subtract = function (other) {
            var low = this._bits[0] - other._bits[0];
            var high = this._bits[1] - other._bits[1] - (this._bits[0] < other._bits[0] ? 1 : 0);
            return new Uint64(low, high);
        };
        Uint64.prototype.toInt32 = function () {
            return this._bits[0] | 0;
        };
        Uint64.prototype.toNumber = function () {
            return this._bits[0] + this._bits[1] * Math.pow(2, 32);
        };
        Uint64.prototype.toString = function () {
            return (new Neo.BigInteger(this._bits.buffer)).toString();
        };
        Uint64.prototype.toUint32 = function () {
            return this._bits[0];
        };
        Uint64.prototype.xor = function (other) {
            if (typeof other === "number") {
                return this.xor(new Uint64(other));
            }
            else {
                var bits = new Uint32Array(this._bits.length);
                for (var i = 0; i < bits.length; i++)
                    bits[i] = this._bits[i] ^ other._bits[i];
                return new Uint64(bits[0], bits[1]);
            }
        };
        return Uint64;
    } (Neo.UintVariable));
    Neo.Uint64 = Uint64;
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var _zero;
    var Uint160 = (function (_super) {
        __extends(Uint160, _super);
        function Uint160(value) {
            var _this = this;
            if (value == null)
                value = new ArrayBuffer(20);
            if (value.byteLength != 20)
                throw new RangeError();
            _this = _super.call(this, new Uint32Array(value)) || this;
            return _this;
        }
        Object.defineProperty(Uint160, "Zero", {
            get: function () { return _zero || (_zero = new Uint160()); },
            enumerable: true,
            configurable: true
        });
        Uint160.parse = function (str) {
            if (str.length != 40)
                throw new RangeError();
            var x = str.hexToBytes();
            var y = new Uint8Array(x.length);
            for (var i = 0; i < y.length; i++)
                y[i] = x[x.length - i - 1];
            return new Uint160(y.buffer);
        };
        return Uint160;
    } (Neo.UintVariable));
    Neo.Uint160 = Uint160;
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var _zero;
    var Uint256 = (function (_super) {
        __extends(Uint256, _super);
        function Uint256(value) {
            var _this = this;
            if (value == null)
                value = new ArrayBuffer(32);
            if (value.byteLength != 32)
                throw new RangeError();
            _this = _super.call(this, new Uint32Array(value)) || this;
            return _this;
        }
        Object.defineProperty(Uint256, "Zero", {
            get: function () { return _zero || (_zero = new Uint256()); },
            enumerable: true,
            configurable: true
        });
        Uint256.parse = function (str) {
            if (str.length != 64)
                throw new RangeError();
            var x = str.hexToBytes();
            var y = new Uint8Array(x.length);
            for (var i = 0; i < y.length; i++)
                y[i] = x[x.length - i - 1];
            return new Uint256(y.buffer);
        };
        return Uint256;
    } (Neo.UintVariable));
    Neo.Uint256 = Uint256;
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var IO;
    (function (IO) {
        var SeekOrigin;
        (function (SeekOrigin) {
            SeekOrigin[SeekOrigin["Begin"] = 0] = "Begin";
            SeekOrigin[SeekOrigin["Current"] = 1] = "Current";
            SeekOrigin[SeekOrigin["End"] = 2] = "End";
        })(SeekOrigin = IO.SeekOrigin || (IO.SeekOrigin = {}));
        var Stream = (function () {
            function Stream() {
                this._array = new Uint8Array(1);
            }
            Stream.prototype.close = function () { };
            Stream.prototype.readByte = function () {
                if (this.read(this._array.buffer, 0, 1) == 0)
                    return -1;
                return this._array[0];
            };
            Stream.prototype.writeByte = function (value) {
                if (value < 0 || value > 255)
                    throw new RangeError();
                this._array[0] = value;
                this.write(this._array.buffer, 0, 1);
            };
            return Stream;
        } ());
        IO.Stream = Stream;
    })(IO = Neo.IO || (Neo.IO = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var Aes = (function () {
            function Aes(key, iv) {
                this._Ke = [];
                this._Kd = [];
                this._lastCipherblock = new Uint8Array(16);
                var rounds = Aes.numberOfRounds[key.byteLength];
                if (rounds == null) {
                    throw new RangeError('invalid key size (must be length 16, 24 or 32)');
                }
                if (iv.byteLength != 16) {
                    throw new RangeError('initialation vector iv must be of length 16');
                }
                for (var i = 0; i <= rounds; i++) {
                    this._Ke.push([0, 0, 0, 0]);
                    this._Kd.push([0, 0, 0, 0]);
                }
                var roundKeyCount = (rounds + 1) * 4;
                var KC = key.byteLength / 4;
                var tk = Aes.convertToInt32(Uint8Array.fromArrayBuffer(key));
                var index;
                for (var i = 0; i < KC; i++) {
                    index = i >> 2;
                    this._Ke[index][i % 4] = tk[i];
                    this._Kd[rounds - index][i % 4] = tk[i];
                }
                var rconpointer = 0;
                var t = KC, tt;
                while (t < roundKeyCount) {
                    tt = tk[KC - 1];
                    tk[0] ^= ((Aes.S[(tt >> 16) & 0xFF] << 24) ^
                        (Aes.S[(tt >> 8) & 0xFF] << 16) ^
                        (Aes.S[tt & 0xFF] << 8) ^
                        Aes.S[(tt >> 24) & 0xFF] ^
                        (Aes.rcon[rconpointer] << 24));
                    rconpointer += 1;
                    if (KC != 8) {
                        for (var i = 1; i < KC; i++) {
                            tk[i] ^= tk[i - 1];
                        }
                    }
                    else {
                        for (var i = 1; i < (KC / 2); i++) {
                            tk[i] ^= tk[i - 1];
                        }
                        tt = tk[(KC / 2) - 1];
                        tk[KC / 2] ^= (Aes.S[tt & 0xFF] ^
                            (Aes.S[(tt >> 8) & 0xFF] << 8) ^
                            (Aes.S[(tt >> 16) & 0xFF] << 16) ^
                            (Aes.S[(tt >> 24) & 0xFF] << 24));
                        for (var i = (KC / 2) + 1; i < KC; i++) {
                            tk[i] ^= tk[i - 1];
                        }
                    }
                    var i = 0;
                    while (i < KC && t < roundKeyCount) {
                        var r_1 = t >> 2;
                        var c_1 = t % 4;
                        this._Ke[r_1][c_1] = tk[i];
                        this._Kd[rounds - r_1][c_1] = tk[i++];
                        t++;
                    }
                }
                for (var r = 1; r < rounds; r++) {
                    for (var c = 0; c < 4; c++) {
                        tt = this._Kd[r][c];
                        this._Kd[r][c] = (Aes.U1[(tt >> 24) & 0xFF] ^
                            Aes.U2[(tt >> 16) & 0xFF] ^
                            Aes.U3[(tt >> 8) & 0xFF] ^
                            Aes.U4[tt & 0xFF]);
                    }
                }
                this._lastCipherblock.set(Uint8Array.fromArrayBuffer(iv));
            }
            Object.defineProperty(Aes.prototype, "mode", {
                get: function () {
                    return "CBC";
                },
                enumerable: true,
                configurable: true
            });
            Aes.convertToInt32 = function (bytes) {
                var result = [];
                for (var i = 0; i < bytes.length; i += 4) {
                    result.push((bytes[i] << 24) |
                        (bytes[i + 1] << 16) |
                        (bytes[i + 2] << 8) |
                        bytes[i + 3]);
                }
                return result;
            };
            Aes.prototype.decrypt = function (ciphertext) {
                if (ciphertext.byteLength == 0 || ciphertext.byteLength % 16 != 0)
                    throw new RangeError();
                var plaintext = new Uint8Array(ciphertext.byteLength);
                var ciphertext_view = Uint8Array.fromArrayBuffer(ciphertext);
                for (var i = 0; i < ciphertext_view.length; i += 16)
                    this.decryptBlock(ciphertext_view.subarray(i, i + 16), plaintext.subarray(i, i + 16));
                return plaintext.buffer.slice(0, plaintext.length - plaintext[plaintext.length - 1]);
            };
            Aes.prototype.decryptBlock = function (ciphertext, plaintext) {
                if (ciphertext.length != 16 || plaintext.length != 16)
                    throw new RangeError();
                var rounds = this._Kd.length - 1;
                var a = [0, 0, 0, 0];
                var t = Aes.convertToInt32(ciphertext);
                for (var i = 0; i < 4; i++) {
                    t[i] ^= this._Kd[0][i];
                }
                for (var r = 1; r < rounds; r++) {
                    for (var i = 0; i < 4; i++) {
                        a[i] = (Aes.T5[(t[i] >> 24) & 0xff] ^
                            Aes.T6[(t[(i + 3) % 4] >> 16) & 0xff] ^
                            Aes.T7[(t[(i + 2) % 4] >> 8) & 0xff] ^
                            Aes.T8[t[(i + 1) % 4] & 0xff] ^
                            this._Kd[r][i]);
                    }
                    t = a.slice(0);
                }
                for (var i = 0; i < 4; i++) {
                    var tt = this._Kd[rounds][i];
                    plaintext[4 * i] = (Aes.Si[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
                    plaintext[4 * i + 1] = (Aes.Si[(t[(i + 3) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
                    plaintext[4 * i + 2] = (Aes.Si[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff;
                    plaintext[4 * i + 3] = (Aes.Si[t[(i + 1) % 4] & 0xff] ^ tt) & 0xff;
                }
                for (var i = 0; i < 16; i++) {
                    plaintext[i] ^= this._lastCipherblock[i];
                }
                Array.copy(ciphertext, 0, this._lastCipherblock, 0, ciphertext.length);
            };
            Aes.prototype.encrypt = function (plaintext) {
                var block_count = Math.ceil((plaintext.byteLength + 1) / 16);
                var ciphertext = new Uint8Array(block_count * 16);
                var plaintext_view = Uint8Array.fromArrayBuffer(plaintext);
                for (var i = 0; i < block_count - 1; i++)
                    this.encryptBlock(plaintext_view.subarray(i * 16, (i + 1) * 16), ciphertext.subarray(i * 16, (i + 1) * 16));
                var padding = ciphertext.length - plaintext.byteLength;
                var final_block = new Uint8Array(16);
                final_block.fill(padding);
                if (padding < 16)
                    Array.copy(plaintext_view, ciphertext.length - 16, final_block, 0, 16 - padding);
                this.encryptBlock(final_block, ciphertext.subarray(ciphertext.length - 16));
                return ciphertext.buffer;
            };
            Aes.prototype.encryptBlock = function (plaintext, ciphertext) {
                if (plaintext.length != 16 || ciphertext.length != 16)
                    throw new RangeError();
                var precipherblock = new Uint8Array(plaintext.length);
                for (var i = 0; i < precipherblock.length; i++) {
                    precipherblock[i] = plaintext[i] ^ this._lastCipherblock[i];
                }
                var rounds = this._Ke.length - 1;
                var a = [0, 0, 0, 0];
                var t = Aes.convertToInt32(precipherblock);
                for (var i = 0; i < 4; i++) {
                    t[i] ^= this._Ke[0][i];
                }
                for (var r = 1; r < rounds; r++) {
                    for (var i = 0; i < 4; i++) {
                        a[i] = (Aes.T1[(t[i] >> 24) & 0xff] ^
                            Aes.T2[(t[(i + 1) % 4] >> 16) & 0xff] ^
                            Aes.T3[(t[(i + 2) % 4] >> 8) & 0xff] ^
                            Aes.T4[t[(i + 3) % 4] & 0xff] ^
                            this._Ke[r][i]);
                    }
                    t = a.slice(0);
                }
                for (var i = 0; i < 4; i++) {
                    var tt = this._Ke[rounds][i];
                    ciphertext[4 * i] = (Aes.S[(t[i] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
                    ciphertext[4 * i + 1] = (Aes.S[(t[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
                    ciphertext[4 * i + 2] = (Aes.S[(t[(i + 2) % 4] >> 8) & 0xff] ^ (tt >> 8)) & 0xff;
                    ciphertext[4 * i + 3] = (Aes.S[t[(i + 3) % 4] & 0xff] ^ tt) & 0xff;
                }
                Array.copy(ciphertext, 0, this._lastCipherblock, 0, ciphertext.length);
            };
            Aes.numberOfRounds = { 16: 10, 24: 12, 32: 14 };
            Aes.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91];
            Aes.S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
            Aes.Si = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];
            Aes.T1 = [0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554, 0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a, 0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b, 0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b, 0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f, 0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f, 0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5, 0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f, 0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb, 0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497, 0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed, 0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a, 0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594, 0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3, 0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504, 0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d, 0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739, 0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395, 0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883, 0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76, 0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4, 0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b, 0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0, 0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818, 0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651, 0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85, 0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12, 0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9, 0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7, 0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a, 0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8, 0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a];
            Aes.T2 = [0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5, 0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676, 0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0, 0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0, 0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc, 0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515, 0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a, 0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575, 0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0, 0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484, 0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b, 0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf, 0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585, 0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8, 0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5, 0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2, 0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717, 0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373, 0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888, 0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb, 0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c, 0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979, 0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9, 0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808, 0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6, 0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a, 0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e, 0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e, 0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494, 0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf, 0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868, 0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616];
            Aes.T3 = [0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5, 0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76, 0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0, 0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0, 0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc, 0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15, 0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a, 0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75, 0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0, 0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384, 0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b, 0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf, 0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185, 0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8, 0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5, 0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2, 0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17, 0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673, 0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88, 0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb, 0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c, 0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279, 0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9, 0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008, 0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6, 0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a, 0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e, 0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e, 0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394, 0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df, 0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068, 0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16];
            Aes.T4 = [0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491, 0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec, 0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb, 0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b, 0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83, 0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a, 0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f, 0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea, 0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b, 0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713, 0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6, 0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85, 0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411, 0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b, 0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1, 0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf, 0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e, 0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6, 0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b, 0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad, 0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8, 0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2, 0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049, 0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810, 0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197, 0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f, 0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c, 0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927, 0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733, 0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5, 0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0, 0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c];
            Aes.T5 = [0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96, 0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393, 0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25, 0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f, 0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1, 0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6, 0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da, 0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844, 0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd, 0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4, 0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45, 0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94, 0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7, 0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a, 0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5, 0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c, 0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1, 0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a, 0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75, 0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051, 0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46, 0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff, 0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77, 0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb, 0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000, 0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e, 0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927, 0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a, 0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e, 0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16, 0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d, 0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8, 0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd, 0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34, 0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163, 0xd731dcca, 0x42638510, 0x13972240, 0x84c61120, 0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d, 0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0, 0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422, 0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef, 0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36, 0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4, 0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662, 0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5, 0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3, 0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b, 0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8, 0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6, 0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6, 0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0, 0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815, 0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f, 0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df, 0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f, 0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e, 0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713, 0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89, 0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c, 0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf, 0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86, 0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f, 0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541, 0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190, 0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742];
            Aes.T6 = [0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e, 0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303, 0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c, 0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3, 0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0, 0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9, 0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259, 0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8, 0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971, 0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a, 0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f, 0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b, 0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8, 0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab, 0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708, 0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682, 0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2, 0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe, 0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb, 0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10, 0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd, 0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015, 0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e, 0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee, 0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000, 0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72, 0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39, 0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e, 0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91, 0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a, 0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17, 0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9, 0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60, 0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e, 0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1, 0xcad731dc, 0x10426385, 0x40139722, 0x2084c611, 0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1, 0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3, 0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964, 0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390, 0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b, 0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf, 0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46, 0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af, 0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512, 0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb, 0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a, 0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8, 0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c, 0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266, 0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8, 0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6, 0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604, 0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551, 0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41, 0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647, 0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c, 0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1, 0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737, 0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db, 0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340, 0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95, 0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1, 0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857];
            Aes.T7 = [0xa75051f4, 0x65537e41, 0xa4c31a17, 0x5e963a27, 0x6bcb3bab, 0x45f11f9d, 0x58abacfa, 0x03934be3, 0xfa552030, 0x6df6ad76, 0x769188cc, 0x4c25f502, 0xd7fc4fe5, 0xcbd7c52a, 0x44802635, 0xa38fb562, 0x5a49deb1, 0x1b6725ba, 0x0e9845ea, 0xc0e15dfe, 0x7502c32f, 0xf012814c, 0x97a38d46, 0xf9c66bd3, 0x5fe7038f, 0x9c951592, 0x7aebbf6d, 0x59da9552, 0x832dd4be, 0x21d35874, 0x692949e0, 0xc8448ec9, 0x896a75c2, 0x7978f48e, 0x3e6b9958, 0x71dd27b9, 0x4fb6bee1, 0xad17f088, 0xac66c920, 0x3ab47dce, 0x4a1863df, 0x3182e51a, 0x33609751, 0x7f456253, 0x77e0b164, 0xae84bb6b, 0xa01cfe81, 0x2b94f908, 0x68587048, 0xfd198f45, 0x6c8794de, 0xf8b7527b, 0xd323ab73, 0x02e2724b, 0x8f57e31f, 0xab2a6655, 0x2807b2eb, 0xc2032fb5, 0x7b9a86c5, 0x08a5d337, 0x87f23028, 0xa5b223bf, 0x6aba0203, 0x825ced16, 0x1c2b8acf, 0xb492a779, 0xf2f0f307, 0xe2a14e69, 0xf4cd65da, 0xbed50605, 0x621fd134, 0xfe8ac4a6, 0x539d342e, 0x55a0a2f3, 0xe132058a, 0xeb75a4f6, 0xec390b83, 0xefaa4060, 0x9f065e71, 0x1051bd6e, 0x8af93e21, 0x063d96dd, 0x05aedd3e, 0xbd464de6, 0x8db59154, 0x5d0571c4, 0xd46f0406, 0x15ff6050, 0xfb241998, 0xe997d6bd, 0x43cc8940, 0x9e7767d9, 0x42bdb0e8, 0x8b880789, 0x5b38e719, 0xeedb79c8, 0x0a47a17c, 0x0fe97c42, 0x1ec9f884, 0x00000000, 0x86830980, 0xed48322b, 0x70ac1e11, 0x724e6c5a, 0xfffbfd0e, 0x38560f85, 0xd51e3dae, 0x3927362d, 0xd9640a0f, 0xa621685c, 0x54d19b5b, 0x2e3a2436, 0x67b10c0a, 0xe70f9357, 0x96d2b4ee, 0x919e1b9b, 0xc54f80c0, 0x20a261dc, 0x4b695a77, 0x1a161c12, 0xba0ae293, 0x2ae5c0a0, 0xe0433c22, 0x171d121b, 0x0d0b0e09, 0xc7adf28b, 0xa8b92db6, 0xa9c8141e, 0x198557f1, 0x074caf75, 0xddbbee99, 0x60fda37f, 0x269ff701, 0xf5bc5c72, 0x3bc54466, 0x7e345bfb, 0x29768b43, 0xc6dccb23, 0xfc68b6ed, 0xf163b8e4, 0xdccad731, 0x85104263, 0x22401397, 0x112084c6, 0x247d854a, 0x3df8d2bb, 0x3211aef9, 0xa16dc729, 0x2f4b1d9e, 0x30f3dcb2, 0x52ec0d86, 0xe3d077c1, 0x166c2bb3, 0xb999a970, 0x48fa1194, 0x642247e9, 0x8cc4a8fc, 0x3f1aa0f0, 0x2cd8567d, 0x90ef2233, 0x4ec78749, 0xd1c1d938, 0xa2fe8cca, 0x0b3698d4, 0x81cfa6f5, 0xde28a57a, 0x8e26dab7, 0xbfa43fad, 0x9de42c3a, 0x920d5078, 0xcc9b6a5f, 0x4662547e, 0x13c2f68d, 0xb8e890d8, 0xf75e2e39, 0xaff582c3, 0x80be9f5d, 0x937c69d0, 0x2da96fd5, 0x12b3cf25, 0x993bc8ac, 0x7da71018, 0x636ee89c, 0xbb7bdb3b, 0x7809cd26, 0x18f46e59, 0xb701ec9a, 0x9aa8834f, 0x6e65e695, 0xe67eaaff, 0xcf0821bc, 0xe8e6ef15, 0x9bd9bae7, 0x36ce4a6f, 0x09d4ea9f, 0x7cd629b0, 0xb2af31a4, 0x23312a3f, 0x9430c6a5, 0x66c035a2, 0xbc37744e, 0xcaa6fc82, 0xd0b0e090, 0xd81533a7, 0x984af104, 0xdaf741ec, 0x500e7fcd, 0xf62f1791, 0xd68d764d, 0xb04d43ef, 0x4d54ccaa, 0x04dfe496, 0xb5e39ed1, 0x881b4c6a, 0x1fb8c12c, 0x517f4665, 0xea049d5e, 0x355d018c, 0x7473fa87, 0x412efb0b, 0x1d5ab367, 0xd25292db, 0x5633e910, 0x47136dd6, 0x618c9ad7, 0x0c7a37a1, 0x148e59f8, 0x3c89eb13, 0x27eecea9, 0xc935b761, 0xe5ede11c, 0xb13c7a47, 0xdf599cd2, 0x733f55f2, 0xce791814, 0x37bf73c7, 0xcdea53f7, 0xaa5b5ffd, 0x6f14df3d, 0xdb867844, 0xf381caaf, 0xc43eb968, 0x342c3824, 0x405fc2a3, 0xc372161d, 0x250cbce2, 0x498b283c, 0x9541ff0d, 0x017139a8, 0xb3de080c, 0xe49cd8b4, 0xc1906456, 0x84617bcb, 0xb670d532, 0x5c74486c, 0x5742d0b8];
            Aes.T8 = [0xf4a75051, 0x4165537e, 0x17a4c31a, 0x275e963a, 0xab6bcb3b, 0x9d45f11f, 0xfa58abac, 0xe303934b, 0x30fa5520, 0x766df6ad, 0xcc769188, 0x024c25f5, 0xe5d7fc4f, 0x2acbd7c5, 0x35448026, 0x62a38fb5, 0xb15a49de, 0xba1b6725, 0xea0e9845, 0xfec0e15d, 0x2f7502c3, 0x4cf01281, 0x4697a38d, 0xd3f9c66b, 0x8f5fe703, 0x929c9515, 0x6d7aebbf, 0x5259da95, 0xbe832dd4, 0x7421d358, 0xe0692949, 0xc9c8448e, 0xc2896a75, 0x8e7978f4, 0x583e6b99, 0xb971dd27, 0xe14fb6be, 0x88ad17f0, 0x20ac66c9, 0xce3ab47d, 0xdf4a1863, 0x1a3182e5, 0x51336097, 0x537f4562, 0x6477e0b1, 0x6bae84bb, 0x81a01cfe, 0x082b94f9, 0x48685870, 0x45fd198f, 0xde6c8794, 0x7bf8b752, 0x73d323ab, 0x4b02e272, 0x1f8f57e3, 0x55ab2a66, 0xeb2807b2, 0xb5c2032f, 0xc57b9a86, 0x3708a5d3, 0x2887f230, 0xbfa5b223, 0x036aba02, 0x16825ced, 0xcf1c2b8a, 0x79b492a7, 0x07f2f0f3, 0x69e2a14e, 0xdaf4cd65, 0x05bed506, 0x34621fd1, 0xa6fe8ac4, 0x2e539d34, 0xf355a0a2, 0x8ae13205, 0xf6eb75a4, 0x83ec390b, 0x60efaa40, 0x719f065e, 0x6e1051bd, 0x218af93e, 0xdd063d96, 0x3e05aedd, 0xe6bd464d, 0x548db591, 0xc45d0571, 0x06d46f04, 0x5015ff60, 0x98fb2419, 0xbde997d6, 0x4043cc89, 0xd99e7767, 0xe842bdb0, 0x898b8807, 0x195b38e7, 0xc8eedb79, 0x7c0a47a1, 0x420fe97c, 0x841ec9f8, 0x00000000, 0x80868309, 0x2bed4832, 0x1170ac1e, 0x5a724e6c, 0x0efffbfd, 0x8538560f, 0xaed51e3d, 0x2d392736, 0x0fd9640a, 0x5ca62168, 0x5b54d19b, 0x362e3a24, 0x0a67b10c, 0x57e70f93, 0xee96d2b4, 0x9b919e1b, 0xc0c54f80, 0xdc20a261, 0x774b695a, 0x121a161c, 0x93ba0ae2, 0xa02ae5c0, 0x22e0433c, 0x1b171d12, 0x090d0b0e, 0x8bc7adf2, 0xb6a8b92d, 0x1ea9c814, 0xf1198557, 0x75074caf, 0x99ddbbee, 0x7f60fda3, 0x01269ff7, 0x72f5bc5c, 0x663bc544, 0xfb7e345b, 0x4329768b, 0x23c6dccb, 0xedfc68b6, 0xe4f163b8, 0x31dccad7, 0x63851042, 0x97224013, 0xc6112084, 0x4a247d85, 0xbb3df8d2, 0xf93211ae, 0x29a16dc7, 0x9e2f4b1d, 0xb230f3dc, 0x8652ec0d, 0xc1e3d077, 0xb3166c2b, 0x70b999a9, 0x9448fa11, 0xe9642247, 0xfc8cc4a8, 0xf03f1aa0, 0x7d2cd856, 0x3390ef22, 0x494ec787, 0x38d1c1d9, 0xcaa2fe8c, 0xd40b3698, 0xf581cfa6, 0x7ade28a5, 0xb78e26da, 0xadbfa43f, 0x3a9de42c, 0x78920d50, 0x5fcc9b6a, 0x7e466254, 0x8d13c2f6, 0xd8b8e890, 0x39f75e2e, 0xc3aff582, 0x5d80be9f, 0xd0937c69, 0xd52da96f, 0x2512b3cf, 0xac993bc8, 0x187da710, 0x9c636ee8, 0x3bbb7bdb, 0x267809cd, 0x5918f46e, 0x9ab701ec, 0x4f9aa883, 0x956e65e6, 0xffe67eaa, 0xbccf0821, 0x15e8e6ef, 0xe79bd9ba, 0x6f36ce4a, 0x9f09d4ea, 0xb07cd629, 0xa4b2af31, 0x3f23312a, 0xa59430c6, 0xa266c035, 0x4ebc3774, 0x82caa6fc, 0x90d0b0e0, 0xa7d81533, 0x04984af1, 0xecdaf741, 0xcd500e7f, 0x91f62f17, 0x4dd68d76, 0xefb04d43, 0xaa4d54cc, 0x9604dfe4, 0xd1b5e39e, 0x6a881b4c, 0x2c1fb8c1, 0x65517f46, 0x5eea049d, 0x8c355d01, 0x877473fa, 0x0b412efb, 0x671d5ab3, 0xdbd25292, 0x105633e9, 0xd647136d, 0xd7618c9a, 0xa10c7a37, 0xf8148e59, 0x133c89eb, 0xa927eece, 0x61c935b7, 0x1ce5ede1, 0x47b13c7a, 0xd2df599c, 0xf2733f55, 0x14ce7918, 0xc737bf73, 0xf7cdea53, 0xfdaa5b5f, 0x3d6f14df, 0x44db8678, 0xaff381ca, 0x68c43eb9, 0x24342c38, 0xa3405fc2, 0x1dc37216, 0xe2250cbc, 0x3c498b28, 0x0d9541ff, 0xa8017139, 0x0cb3de08, 0xb4e49cd8, 0x56c19064, 0xcb84617b, 0x32b670d5, 0x6c5c7448, 0xb85742d0];
            Aes.U1 = [0x00000000, 0x0e090d0b, 0x1c121a16, 0x121b171d, 0x3824342c, 0x362d3927, 0x24362e3a, 0x2a3f2331, 0x70486858, 0x7e416553, 0x6c5a724e, 0x62537f45, 0x486c5c74, 0x4665517f, 0x547e4662, 0x5a774b69, 0xe090d0b0, 0xee99ddbb, 0xfc82caa6, 0xf28bc7ad, 0xd8b4e49c, 0xd6bde997, 0xc4a6fe8a, 0xcaaff381, 0x90d8b8e8, 0x9ed1b5e3, 0x8ccaa2fe, 0x82c3aff5, 0xa8fc8cc4, 0xa6f581cf, 0xb4ee96d2, 0xbae79bd9, 0xdb3bbb7b, 0xd532b670, 0xc729a16d, 0xc920ac66, 0xe31f8f57, 0xed16825c, 0xff0d9541, 0xf104984a, 0xab73d323, 0xa57ade28, 0xb761c935, 0xb968c43e, 0x9357e70f, 0x9d5eea04, 0x8f45fd19, 0x814cf012, 0x3bab6bcb, 0x35a266c0, 0x27b971dd, 0x29b07cd6, 0x038f5fe7, 0x0d8652ec, 0x1f9d45f1, 0x119448fa, 0x4be30393, 0x45ea0e98, 0x57f11985, 0x59f8148e, 0x73c737bf, 0x7dce3ab4, 0x6fd52da9, 0x61dc20a2, 0xad766df6, 0xa37f60fd, 0xb16477e0, 0xbf6d7aeb, 0x955259da, 0x9b5b54d1, 0x894043cc, 0x87494ec7, 0xdd3e05ae, 0xd33708a5, 0xc12c1fb8, 0xcf2512b3, 0xe51a3182, 0xeb133c89, 0xf9082b94, 0xf701269f, 0x4de6bd46, 0x43efb04d, 0x51f4a750, 0x5ffdaa5b, 0x75c2896a, 0x7bcb8461, 0x69d0937c, 0x67d99e77, 0x3daed51e, 0x33a7d815, 0x21bccf08, 0x2fb5c203, 0x058ae132, 0x0b83ec39, 0x1998fb24, 0x1791f62f, 0x764dd68d, 0x7844db86, 0x6a5fcc9b, 0x6456c190, 0x4e69e2a1, 0x4060efaa, 0x527bf8b7, 0x5c72f5bc, 0x0605bed5, 0x080cb3de, 0x1a17a4c3, 0x141ea9c8, 0x3e218af9, 0x302887f2, 0x223390ef, 0x2c3a9de4, 0x96dd063d, 0x98d40b36, 0x8acf1c2b, 0x84c61120, 0xaef93211, 0xa0f03f1a, 0xb2eb2807, 0xbce2250c, 0xe6956e65, 0xe89c636e, 0xfa877473, 0xf48e7978, 0xdeb15a49, 0xd0b85742, 0xc2a3405f, 0xccaa4d54, 0x41ecdaf7, 0x4fe5d7fc, 0x5dfec0e1, 0x53f7cdea, 0x79c8eedb, 0x77c1e3d0, 0x65daf4cd, 0x6bd3f9c6, 0x31a4b2af, 0x3fadbfa4, 0x2db6a8b9, 0x23bfa5b2, 0x09808683, 0x07898b88, 0x15929c95, 0x1b9b919e, 0xa17c0a47, 0xaf75074c, 0xbd6e1051, 0xb3671d5a, 0x99583e6b, 0x97513360, 0x854a247d, 0x8b432976, 0xd134621f, 0xdf3d6f14, 0xcd267809, 0xc32f7502, 0xe9105633, 0xe7195b38, 0xf5024c25, 0xfb0b412e, 0x9ad7618c, 0x94de6c87, 0x86c57b9a, 0x88cc7691, 0xa2f355a0, 0xacfa58ab, 0xbee14fb6, 0xb0e842bd, 0xea9f09d4, 0xe49604df, 0xf68d13c2, 0xf8841ec9, 0xd2bb3df8, 0xdcb230f3, 0xcea927ee, 0xc0a02ae5, 0x7a47b13c, 0x744ebc37, 0x6655ab2a, 0x685ca621, 0x42638510, 0x4c6a881b, 0x5e719f06, 0x5078920d, 0x0a0fd964, 0x0406d46f, 0x161dc372, 0x1814ce79, 0x322bed48, 0x3c22e043, 0x2e39f75e, 0x2030fa55, 0xec9ab701, 0xe293ba0a, 0xf088ad17, 0xfe81a01c, 0xd4be832d, 0xdab78e26, 0xc8ac993b, 0xc6a59430, 0x9cd2df59, 0x92dbd252, 0x80c0c54f, 0x8ec9c844, 0xa4f6eb75, 0xaaffe67e, 0xb8e4f163, 0xb6edfc68, 0x0c0a67b1, 0x02036aba, 0x10187da7, 0x1e1170ac, 0x342e539d, 0x3a275e96, 0x283c498b, 0x26354480, 0x7c420fe9, 0x724b02e2, 0x605015ff, 0x6e5918f4, 0x44663bc5, 0x4a6f36ce, 0x587421d3, 0x567d2cd8, 0x37a10c7a, 0x39a80171, 0x2bb3166c, 0x25ba1b67, 0x0f853856, 0x018c355d, 0x13972240, 0x1d9e2f4b, 0x47e96422, 0x49e06929, 0x5bfb7e34, 0x55f2733f, 0x7fcd500e, 0x71c45d05, 0x63df4a18, 0x6dd64713, 0xd731dcca, 0xd938d1c1, 0xcb23c6dc, 0xc52acbd7, 0xef15e8e6, 0xe11ce5ed, 0xf307f2f0, 0xfd0efffb, 0xa779b492, 0xa970b999, 0xbb6bae84, 0xb562a38f, 0x9f5d80be, 0x91548db5, 0x834f9aa8, 0x8d4697a3];
            Aes.U2 = [0x00000000, 0x0b0e090d, 0x161c121a, 0x1d121b17, 0x2c382434, 0x27362d39, 0x3a24362e, 0x312a3f23, 0x58704868, 0x537e4165, 0x4e6c5a72, 0x4562537f, 0x74486c5c, 0x7f466551, 0x62547e46, 0x695a774b, 0xb0e090d0, 0xbbee99dd, 0xa6fc82ca, 0xadf28bc7, 0x9cd8b4e4, 0x97d6bde9, 0x8ac4a6fe, 0x81caaff3, 0xe890d8b8, 0xe39ed1b5, 0xfe8ccaa2, 0xf582c3af, 0xc4a8fc8c, 0xcfa6f581, 0xd2b4ee96, 0xd9bae79b, 0x7bdb3bbb, 0x70d532b6, 0x6dc729a1, 0x66c920ac, 0x57e31f8f, 0x5ced1682, 0x41ff0d95, 0x4af10498, 0x23ab73d3, 0x28a57ade, 0x35b761c9, 0x3eb968c4, 0x0f9357e7, 0x049d5eea, 0x198f45fd, 0x12814cf0, 0xcb3bab6b, 0xc035a266, 0xdd27b971, 0xd629b07c, 0xe7038f5f, 0xec0d8652, 0xf11f9d45, 0xfa119448, 0x934be303, 0x9845ea0e, 0x8557f119, 0x8e59f814, 0xbf73c737, 0xb47dce3a, 0xa96fd52d, 0xa261dc20, 0xf6ad766d, 0xfda37f60, 0xe0b16477, 0xebbf6d7a, 0xda955259, 0xd19b5b54, 0xcc894043, 0xc787494e, 0xaedd3e05, 0xa5d33708, 0xb8c12c1f, 0xb3cf2512, 0x82e51a31, 0x89eb133c, 0x94f9082b, 0x9ff70126, 0x464de6bd, 0x4d43efb0, 0x5051f4a7, 0x5b5ffdaa, 0x6a75c289, 0x617bcb84, 0x7c69d093, 0x7767d99e, 0x1e3daed5, 0x1533a7d8, 0x0821bccf, 0x032fb5c2, 0x32058ae1, 0x390b83ec, 0x241998fb, 0x2f1791f6, 0x8d764dd6, 0x867844db, 0x9b6a5fcc, 0x906456c1, 0xa14e69e2, 0xaa4060ef, 0xb7527bf8, 0xbc5c72f5, 0xd50605be, 0xde080cb3, 0xc31a17a4, 0xc8141ea9, 0xf93e218a, 0xf2302887, 0xef223390, 0xe42c3a9d, 0x3d96dd06, 0x3698d40b, 0x2b8acf1c, 0x2084c611, 0x11aef932, 0x1aa0f03f, 0x07b2eb28, 0x0cbce225, 0x65e6956e, 0x6ee89c63, 0x73fa8774, 0x78f48e79, 0x49deb15a, 0x42d0b857, 0x5fc2a340, 0x54ccaa4d, 0xf741ecda, 0xfc4fe5d7, 0xe15dfec0, 0xea53f7cd, 0xdb79c8ee, 0xd077c1e3, 0xcd65daf4, 0xc66bd3f9, 0xaf31a4b2, 0xa43fadbf, 0xb92db6a8, 0xb223bfa5, 0x83098086, 0x8807898b, 0x9515929c, 0x9e1b9b91, 0x47a17c0a, 0x4caf7507, 0x51bd6e10, 0x5ab3671d, 0x6b99583e, 0x60975133, 0x7d854a24, 0x768b4329, 0x1fd13462, 0x14df3d6f, 0x09cd2678, 0x02c32f75, 0x33e91056, 0x38e7195b, 0x25f5024c, 0x2efb0b41, 0x8c9ad761, 0x8794de6c, 0x9a86c57b, 0x9188cc76, 0xa0a2f355, 0xabacfa58, 0xb6bee14f, 0xbdb0e842, 0xd4ea9f09, 0xdfe49604, 0xc2f68d13, 0xc9f8841e, 0xf8d2bb3d, 0xf3dcb230, 0xeecea927, 0xe5c0a02a, 0x3c7a47b1, 0x37744ebc, 0x2a6655ab, 0x21685ca6, 0x10426385, 0x1b4c6a88, 0x065e719f, 0x0d507892, 0x640a0fd9, 0x6f0406d4, 0x72161dc3, 0x791814ce, 0x48322bed, 0x433c22e0, 0x5e2e39f7, 0x552030fa, 0x01ec9ab7, 0x0ae293ba, 0x17f088ad, 0x1cfe81a0, 0x2dd4be83, 0x26dab78e, 0x3bc8ac99, 0x30c6a594, 0x599cd2df, 0x5292dbd2, 0x4f80c0c5, 0x448ec9c8, 0x75a4f6eb, 0x7eaaffe6, 0x63b8e4f1, 0x68b6edfc, 0xb10c0a67, 0xba02036a, 0xa710187d, 0xac1e1170, 0x9d342e53, 0x963a275e, 0x8b283c49, 0x80263544, 0xe97c420f, 0xe2724b02, 0xff605015, 0xf46e5918, 0xc544663b, 0xce4a6f36, 0xd3587421, 0xd8567d2c, 0x7a37a10c, 0x7139a801, 0x6c2bb316, 0x6725ba1b, 0x560f8538, 0x5d018c35, 0x40139722, 0x4b1d9e2f, 0x2247e964, 0x2949e069, 0x345bfb7e, 0x3f55f273, 0x0e7fcd50, 0x0571c45d, 0x1863df4a, 0x136dd647, 0xcad731dc, 0xc1d938d1, 0xdccb23c6, 0xd7c52acb, 0xe6ef15e8, 0xede11ce5, 0xf0f307f2, 0xfbfd0eff, 0x92a779b4, 0x99a970b9, 0x84bb6bae, 0x8fb562a3, 0xbe9f5d80, 0xb591548d, 0xa8834f9a, 0xa38d4697];
            Aes.U3 = [0x00000000, 0x0d0b0e09, 0x1a161c12, 0x171d121b, 0x342c3824, 0x3927362d, 0x2e3a2436, 0x23312a3f, 0x68587048, 0x65537e41, 0x724e6c5a, 0x7f456253, 0x5c74486c, 0x517f4665, 0x4662547e, 0x4b695a77, 0xd0b0e090, 0xddbbee99, 0xcaa6fc82, 0xc7adf28b, 0xe49cd8b4, 0xe997d6bd, 0xfe8ac4a6, 0xf381caaf, 0xb8e890d8, 0xb5e39ed1, 0xa2fe8cca, 0xaff582c3, 0x8cc4a8fc, 0x81cfa6f5, 0x96d2b4ee, 0x9bd9bae7, 0xbb7bdb3b, 0xb670d532, 0xa16dc729, 0xac66c920, 0x8f57e31f, 0x825ced16, 0x9541ff0d, 0x984af104, 0xd323ab73, 0xde28a57a, 0xc935b761, 0xc43eb968, 0xe70f9357, 0xea049d5e, 0xfd198f45, 0xf012814c, 0x6bcb3bab, 0x66c035a2, 0x71dd27b9, 0x7cd629b0, 0x5fe7038f, 0x52ec0d86, 0x45f11f9d, 0x48fa1194, 0x03934be3, 0x0e9845ea, 0x198557f1, 0x148e59f8, 0x37bf73c7, 0x3ab47dce, 0x2da96fd5, 0x20a261dc, 0x6df6ad76, 0x60fda37f, 0x77e0b164, 0x7aebbf6d, 0x59da9552, 0x54d19b5b, 0x43cc8940, 0x4ec78749, 0x05aedd3e, 0x08a5d337, 0x1fb8c12c, 0x12b3cf25, 0x3182e51a, 0x3c89eb13, 0x2b94f908, 0x269ff701, 0xbd464de6, 0xb04d43ef, 0xa75051f4, 0xaa5b5ffd, 0x896a75c2, 0x84617bcb, 0x937c69d0, 0x9e7767d9, 0xd51e3dae, 0xd81533a7, 0xcf0821bc, 0xc2032fb5, 0xe132058a, 0xec390b83, 0xfb241998, 0xf62f1791, 0xd68d764d, 0xdb867844, 0xcc9b6a5f, 0xc1906456, 0xe2a14e69, 0xefaa4060, 0xf8b7527b, 0xf5bc5c72, 0xbed50605, 0xb3de080c, 0xa4c31a17, 0xa9c8141e, 0x8af93e21, 0x87f23028, 0x90ef2233, 0x9de42c3a, 0x063d96dd, 0x0b3698d4, 0x1c2b8acf, 0x112084c6, 0x3211aef9, 0x3f1aa0f0, 0x2807b2eb, 0x250cbce2, 0x6e65e695, 0x636ee89c, 0x7473fa87, 0x7978f48e, 0x5a49deb1, 0x5742d0b8, 0x405fc2a3, 0x4d54ccaa, 0xdaf741ec, 0xd7fc4fe5, 0xc0e15dfe, 0xcdea53f7, 0xeedb79c8, 0xe3d077c1, 0xf4cd65da, 0xf9c66bd3, 0xb2af31a4, 0xbfa43fad, 0xa8b92db6, 0xa5b223bf, 0x86830980, 0x8b880789, 0x9c951592, 0x919e1b9b, 0x0a47a17c, 0x074caf75, 0x1051bd6e, 0x1d5ab367, 0x3e6b9958, 0x33609751, 0x247d854a, 0x29768b43, 0x621fd134, 0x6f14df3d, 0x7809cd26, 0x7502c32f, 0x5633e910, 0x5b38e719, 0x4c25f502, 0x412efb0b, 0x618c9ad7, 0x6c8794de, 0x7b9a86c5, 0x769188cc, 0x55a0a2f3, 0x58abacfa, 0x4fb6bee1, 0x42bdb0e8, 0x09d4ea9f, 0x04dfe496, 0x13c2f68d, 0x1ec9f884, 0x3df8d2bb, 0x30f3dcb2, 0x27eecea9, 0x2ae5c0a0, 0xb13c7a47, 0xbc37744e, 0xab2a6655, 0xa621685c, 0x85104263, 0x881b4c6a, 0x9f065e71, 0x920d5078, 0xd9640a0f, 0xd46f0406, 0xc372161d, 0xce791814, 0xed48322b, 0xe0433c22, 0xf75e2e39, 0xfa552030, 0xb701ec9a, 0xba0ae293, 0xad17f088, 0xa01cfe81, 0x832dd4be, 0x8e26dab7, 0x993bc8ac, 0x9430c6a5, 0xdf599cd2, 0xd25292db, 0xc54f80c0, 0xc8448ec9, 0xeb75a4f6, 0xe67eaaff, 0xf163b8e4, 0xfc68b6ed, 0x67b10c0a, 0x6aba0203, 0x7da71018, 0x70ac1e11, 0x539d342e, 0x5e963a27, 0x498b283c, 0x44802635, 0x0fe97c42, 0x02e2724b, 0x15ff6050, 0x18f46e59, 0x3bc54466, 0x36ce4a6f, 0x21d35874, 0x2cd8567d, 0x0c7a37a1, 0x017139a8, 0x166c2bb3, 0x1b6725ba, 0x38560f85, 0x355d018c, 0x22401397, 0x2f4b1d9e, 0x642247e9, 0x692949e0, 0x7e345bfb, 0x733f55f2, 0x500e7fcd, 0x5d0571c4, 0x4a1863df, 0x47136dd6, 0xdccad731, 0xd1c1d938, 0xc6dccb23, 0xcbd7c52a, 0xe8e6ef15, 0xe5ede11c, 0xf2f0f307, 0xfffbfd0e, 0xb492a779, 0xb999a970, 0xae84bb6b, 0xa38fb562, 0x80be9f5d, 0x8db59154, 0x9aa8834f, 0x97a38d46];
            Aes.U4 = [0x00000000, 0x090d0b0e, 0x121a161c, 0x1b171d12, 0x24342c38, 0x2d392736, 0x362e3a24, 0x3f23312a, 0x48685870, 0x4165537e, 0x5a724e6c, 0x537f4562, 0x6c5c7448, 0x65517f46, 0x7e466254, 0x774b695a, 0x90d0b0e0, 0x99ddbbee, 0x82caa6fc, 0x8bc7adf2, 0xb4e49cd8, 0xbde997d6, 0xa6fe8ac4, 0xaff381ca, 0xd8b8e890, 0xd1b5e39e, 0xcaa2fe8c, 0xc3aff582, 0xfc8cc4a8, 0xf581cfa6, 0xee96d2b4, 0xe79bd9ba, 0x3bbb7bdb, 0x32b670d5, 0x29a16dc7, 0x20ac66c9, 0x1f8f57e3, 0x16825ced, 0x0d9541ff, 0x04984af1, 0x73d323ab, 0x7ade28a5, 0x61c935b7, 0x68c43eb9, 0x57e70f93, 0x5eea049d, 0x45fd198f, 0x4cf01281, 0xab6bcb3b, 0xa266c035, 0xb971dd27, 0xb07cd629, 0x8f5fe703, 0x8652ec0d, 0x9d45f11f, 0x9448fa11, 0xe303934b, 0xea0e9845, 0xf1198557, 0xf8148e59, 0xc737bf73, 0xce3ab47d, 0xd52da96f, 0xdc20a261, 0x766df6ad, 0x7f60fda3, 0x6477e0b1, 0x6d7aebbf, 0x5259da95, 0x5b54d19b, 0x4043cc89, 0x494ec787, 0x3e05aedd, 0x3708a5d3, 0x2c1fb8c1, 0x2512b3cf, 0x1a3182e5, 0x133c89eb, 0x082b94f9, 0x01269ff7, 0xe6bd464d, 0xefb04d43, 0xf4a75051, 0xfdaa5b5f, 0xc2896a75, 0xcb84617b, 0xd0937c69, 0xd99e7767, 0xaed51e3d, 0xa7d81533, 0xbccf0821, 0xb5c2032f, 0x8ae13205, 0x83ec390b, 0x98fb2419, 0x91f62f17, 0x4dd68d76, 0x44db8678, 0x5fcc9b6a, 0x56c19064, 0x69e2a14e, 0x60efaa40, 0x7bf8b752, 0x72f5bc5c, 0x05bed506, 0x0cb3de08, 0x17a4c31a, 0x1ea9c814, 0x218af93e, 0x2887f230, 0x3390ef22, 0x3a9de42c, 0xdd063d96, 0xd40b3698, 0xcf1c2b8a, 0xc6112084, 0xf93211ae, 0xf03f1aa0, 0xeb2807b2, 0xe2250cbc, 0x956e65e6, 0x9c636ee8, 0x877473fa, 0x8e7978f4, 0xb15a49de, 0xb85742d0, 0xa3405fc2, 0xaa4d54cc, 0xecdaf741, 0xe5d7fc4f, 0xfec0e15d, 0xf7cdea53, 0xc8eedb79, 0xc1e3d077, 0xdaf4cd65, 0xd3f9c66b, 0xa4b2af31, 0xadbfa43f, 0xb6a8b92d, 0xbfa5b223, 0x80868309, 0x898b8807, 0x929c9515, 0x9b919e1b, 0x7c0a47a1, 0x75074caf, 0x6e1051bd, 0x671d5ab3, 0x583e6b99, 0x51336097, 0x4a247d85, 0x4329768b, 0x34621fd1, 0x3d6f14df, 0x267809cd, 0x2f7502c3, 0x105633e9, 0x195b38e7, 0x024c25f5, 0x0b412efb, 0xd7618c9a, 0xde6c8794, 0xc57b9a86, 0xcc769188, 0xf355a0a2, 0xfa58abac, 0xe14fb6be, 0xe842bdb0, 0x9f09d4ea, 0x9604dfe4, 0x8d13c2f6, 0x841ec9f8, 0xbb3df8d2, 0xb230f3dc, 0xa927eece, 0xa02ae5c0, 0x47b13c7a, 0x4ebc3774, 0x55ab2a66, 0x5ca62168, 0x63851042, 0x6a881b4c, 0x719f065e, 0x78920d50, 0x0fd9640a, 0x06d46f04, 0x1dc37216, 0x14ce7918, 0x2bed4832, 0x22e0433c, 0x39f75e2e, 0x30fa5520, 0x9ab701ec, 0x93ba0ae2, 0x88ad17f0, 0x81a01cfe, 0xbe832dd4, 0xb78e26da, 0xac993bc8, 0xa59430c6, 0xd2df599c, 0xdbd25292, 0xc0c54f80, 0xc9c8448e, 0xf6eb75a4, 0xffe67eaa, 0xe4f163b8, 0xedfc68b6, 0x0a67b10c, 0x036aba02, 0x187da710, 0x1170ac1e, 0x2e539d34, 0x275e963a, 0x3c498b28, 0x35448026, 0x420fe97c, 0x4b02e272, 0x5015ff60, 0x5918f46e, 0x663bc544, 0x6f36ce4a, 0x7421d358, 0x7d2cd856, 0xa10c7a37, 0xa8017139, 0xb3166c2b, 0xba1b6725, 0x8538560f, 0x8c355d01, 0x97224013, 0x9e2f4b1d, 0xe9642247, 0xe0692949, 0xfb7e345b, 0xf2733f55, 0xcd500e7f, 0xc45d0571, 0xdf4a1863, 0xd647136d, 0x31dccad7, 0x38d1c1d9, 0x23c6dccb, 0x2acbd7c5, 0x15e8e6ef, 0x1ce5ede1, 0x07f2f0f3, 0x0efffbfd, 0x79b492a7, 0x70b999a9, 0x6bae84bb, 0x62a38fb5, 0x5d80be9f, 0x548db591, 0x4f9aa883, 0x4697a38d];
            return Aes;
        } ());
        Cryptography.Aes = Aes;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var Base58 = (function () {
            function Base58() {
            }
            Base58.decode = function (input) {
                var bi = Neo.BigInteger.Zero;
                for (var i = input.length - 1; i >= 0; i--) {
                    var index = Base58.Alphabet.indexOf(input[i]);
                    if (index == -1)
                        throw new RangeError();
                    bi = Neo.BigInteger.add(bi, Neo.BigInteger.multiply(Neo.BigInteger.pow(Base58.Alphabet.length, input.length - 1 - i), index));
                }
                var bytes = bi.toUint8Array();
                var leadingZeros = 0;
                for (var i = 0; i < input.length && input[i] == Base58.Alphabet[0]; i++) {
                    leadingZeros++;
                }
                var tmp = new Uint8Array(bytes.length + leadingZeros);
                for (var i = 0; i < bytes.length; i++)
                    tmp[i + leadingZeros] = bytes[bytes.length - 1 - i];
                return tmp;
            };
            Base58.encode = function (input) {
                var value = Neo.BigInteger.fromUint8Array(input, 1, false);
                var s = "";
                while (!value.isZero()) {
                    var r = Neo.BigInteger.divRem(value, Base58.Alphabet.length);
                    s = Base58.Alphabet[r.remainder.toInt32()] + s;
                    value = r.result;
                }
                for (var i = 0; i < input.length; i++) {
                    if (input[i] == 0)
                        s = Base58.Alphabet[0] + s;
                    else
                        break;
                }
                return s;
            };
            Base58.Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            return Base58;
        } ());
        Cryptography.Base58 = Base58;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var CryptoKey = (function () {
            function CryptoKey(type, extractable, algorithm, usages) {
                this.type = type;
                this.extractable = extractable;
                this.algorithm = algorithm;
                this.usages = usages;
            }
            return CryptoKey;
        } ());
        Cryptography.CryptoKey = CryptoKey;
        var AesCryptoKey = (function (_super) {
            __extends(AesCryptoKey, _super);
            function AesCryptoKey(_key_bytes) {
                var _this = _super.call(this, "secret", true, { name: "AES-CBC", length: _key_bytes.length * 8 }, ["encrypt", "decrypt"]) || this;
                _this._key_bytes = _key_bytes;
                return _this;
            }
            // AesCryptoKey.create = function (length) {
            //     if (length != 128 && length != 192 && length != 256)
            //         throw new RangeError();
            //     var key = new AesCryptoKey(new Uint8Array(length / 8));
            //     window.crypto.getRandomValues(key._key_bytes);
            //     return key;
            // };
            AesCryptoKey.prototype.export = function () {
                return this._key_bytes;
            };
            AesCryptoKey.import = function (keyData) {
                if (keyData.byteLength != 16 && keyData.byteLength != 24 && keyData.byteLength != 32)
                    throw new RangeError();
                return new AesCryptoKey(Uint8Array.fromArrayBuffer(keyData));
            };
            return AesCryptoKey;
        } (Neo.Cryptography.CryptoKey));
        Cryptography.AesCryptoKey = AesCryptoKey;
        var ECDsaCryptoKey = (function (_super) {
            __extends(ECDsaCryptoKey, _super);
            function ECDsaCryptoKey(publicKey, privateKey) {
                var _this = _super.call(this, privateKey == null ? "public" : "private", true, { name: "ECDSA", namedCurve: "P-256" }, [privateKey == null ? "verify" : "sign"]) || this;
                _this.publicKey = publicKey;
                _this.privateKey = privateKey;
                return _this;
            }
            return ECDsaCryptoKey;
        } (CryptoKey));
        Cryptography.ECDsaCryptoKey = ECDsaCryptoKey;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var _secp256k1;
        var _secp256r1;
        var ECCurve = (function () {
            function ECCurve(Q, A, B, N, G) {
                this.Q = Q;
                this.A = new Cryptography.ECFieldElement(A, this);
                this.B = new Cryptography.ECFieldElement(B, this);
                this.N = N;
                this.Infinity = new Cryptography.ECPoint(null, null, this);
                this.G = Cryptography.ECPoint.decodePoint(G, this);
            }
            Object.defineProperty(ECCurve, "secp256k1", {
                get: function () {
                    return _secp256k1 || (_secp256k1 = new ECCurve(Neo.BigInteger.fromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16), Neo.BigInteger.Zero, new Neo.BigInteger(7), Neo.BigInteger.fromString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16), ("04" + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").hexToBytes()));
                },
                enumerable: true,
                configurable: true
            });
            Object.defineProperty(ECCurve, "secp256r1", {
                get: function () {
                    return _secp256r1 || (_secp256r1 = new ECCurve(Neo.BigInteger.fromString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16), Neo.BigInteger.fromString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16), Neo.BigInteger.fromString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16), Neo.BigInteger.fromString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16), ("04" + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5").hexToBytes()));
                },
                enumerable: true,
                configurable: true
            });
            return ECCurve;
        } ());
        Cryptography.ECCurve = ECCurve;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var ECDsa = (function () {
            function ECDsa(key) {
                this.key = key;
            }
            ECDsa.calculateE = function (n, message) {
                return Neo.BigInteger.fromUint8Array(new Uint8Array(Cryptography.Sha256.computeHash(message)), 1, false);
            };
            ECDsa.generateKey = function (curve) {
                var prikey = new Uint8Array(32);
                // window.crypto.getRandomValues(prikey);
                var pubkey = Cryptography.ECPoint.multiply(curve.G, prikey);
                return {
                    privateKey: new Cryptography.ECDsaCryptoKey(pubkey, prikey),
                    publicKey: new Cryptography.ECDsaCryptoKey(pubkey)
                };
            };
            ECDsa.prototype.sign = function (message) {
                if (this.key.privateKey == null)
                    throw new Error();
                var e = ECDsa.calculateE(this.key.publicKey.curve.N, message);
                var d = Neo.BigInteger.fromUint8Array(this.key.privateKey, 1, false);
                var r, s;
                do {
                    var k = void 0;
                    do {
                        do {
                            // k = Neo.BigInteger.random(this.key.publicKey.curve.N.bitLength(), window.crypto);
                            k = Neo.BigInteger.random(this.key.publicKey.curve.N.bitLength());
                        } while (k.sign() == 0 || k.compareTo(this.key.publicKey.curve.N) >= 0);
                        var p = Cryptography.ECPoint.multiply(this.key.publicKey.curve.G, k);
                        var x = p.x.value;
                        r = x.mod(this.key.publicKey.curve.N);
                    } while (r.sign() == 0);
                    s = k.modInverse(this.key.publicKey.curve.N).multiply(e.add(d.multiply(r))).mod(this.key.publicKey.curve.N);
                    if (s.compareTo(this.key.publicKey.curve.N.divide(2)) > 0) {
                        s = this.key.publicKey.curve.N.subtract(s);
                    }
                } while (s.sign() == 0);
                var arr = new Uint8Array(64);
                Array.copy(r.toUint8Array(false, 32), 0, arr, 0, 32);
                Array.copy(s.toUint8Array(false, 32), 0, arr, 32, 32);
                return arr.buffer;
            };
            ECDsa.sumOfTwoMultiplies = function (P, k, Q, l) {
                var m = Math.max(k.bitLength(), l.bitLength());
                var Z = Cryptography.ECPoint.add(P, Q);
                var R = P.curve.Infinity;
                for (var i = m - 1; i >= 0; --i) {
                    R = R.twice();
                    if (k.testBit(i)) {
                        if (l.testBit(i))
                            R = Cryptography.ECPoint.add(R, Z);
                        else
                            R = Cryptography.ECPoint.add(R, P);
                    }
                    else {
                        if (l.testBit(i))
                            R = Cryptography.ECPoint.add(R, Q);
                    }
                }
                return R;
            };
            ECDsa.prototype.verify = function (message, signature) {
                var arr = Uint8Array.fromArrayBuffer(signature);
                var r = Neo.BigInteger.fromUint8Array(arr.subarray(0, 32), 1, false);
                var s = Neo.BigInteger.fromUint8Array(arr.subarray(32, 64), 1, false);
                if (r.compareTo(this.key.publicKey.curve.N) >= 0 || s.compareTo(this.key.publicKey.curve.N) >= 0)
                    return false;
                var e = ECDsa.calculateE(this.key.publicKey.curve.N, message);
                var c = s.modInverse(this.key.publicKey.curve.N);
                var u1 = e.multiply(c).mod(this.key.publicKey.curve.N);
                var u2 = r.multiply(c).mod(this.key.publicKey.curve.N);
                var point = ECDsa.sumOfTwoMultiplies(this.key.publicKey.curve.G, u1, this.key.publicKey, u2);
                var v = point.x.value.mod(this.key.publicKey.curve.N);
                return v.equals(r);
            };
            return ECDsa;
        } ());
        Cryptography.ECDsa = ECDsa;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var ECFieldElement = (function () {
            function ECFieldElement(value, curve) {
                this.value = value;
                this.curve = curve;
                if (Neo.BigInteger.compare(value, curve.Q) >= 0)
                    throw new RangeError("x value too large in field element");
            }
            ECFieldElement.prototype.add = function (other) {
                return new ECFieldElement(this.value.add(other.value).mod(this.curve.Q), this.curve);
            };
            ECFieldElement.prototype.compareTo = function (other) {
                if (this === other)
                    return 0;
                return this.value.compareTo(other.value);
            };
            ECFieldElement.prototype.divide = function (other) {
                return new ECFieldElement(this.value.multiply(other.value.modInverse(this.curve.Q)).mod(this.curve.Q), this.curve);
            };
            ECFieldElement.prototype.equals = function (other) {
                return this.value.equals(other.value);
            };
            ECFieldElement.fastLucasSequence = function (p, P, Q, k) {
                var n = k.bitLength();
                var s = k.getLowestSetBit();
                console.assert(k.testBit(s));
                var Uh = Neo.BigInteger.One;
                var Vl = new Neo.BigInteger(2);
                var Vh = P;
                var Ql = Neo.BigInteger.One;
                var Qh = Neo.BigInteger.One;
                for (var j = n - 1; j >= s + 1; --j) {
                    Ql = Neo.BigInteger.mod(Neo.BigInteger.multiply(Ql, Qh), p);
                    if (k.testBit(j)) {
                        Qh = Ql.multiply(Q).mod(p);
                        Uh = Uh.multiply(Vh).mod(p);
                        Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                        Vh = Vh.multiply(Vh).subtract(Qh.leftShift(1)).mod(p);
                    }
                    else {
                        Qh = Ql;
                        Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
                        Vh = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                        Vl = Vl.multiply(Vl).subtract(Ql.leftShift(1)).mod(p);
                    }
                }
                Ql = Ql.multiply(Qh).mod(p);
                Qh = Ql.multiply(Q).mod(p);
                Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
                Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
                Ql = Ql.multiply(Qh).mod(p);
                for (var j = 1; j <= s; ++j) {
                    Uh = Uh.multiply(Vl).multiply(p);
                    Vl = Vl.multiply(Vl).subtract(Ql.leftShift(1)).mod(p);
                    Ql = Ql.multiply(Ql).mod(p);
                }
                return [Uh, Vl];
            };
            ECFieldElement.prototype.multiply = function (other) {
                return new ECFieldElement(this.value.multiply(other.value).mod(this.curve.Q), this.curve);
            };
            ECFieldElement.prototype.negate = function () {
                return new ECFieldElement(this.value.negate().mod(this.curve.Q), this.curve);
            };
            ECFieldElement.prototype.sqrt = function () {
                if (this.curve.Q.testBit(1)) {
                    var z = new ECFieldElement(Neo.BigInteger.modPow(this.value, this.curve.Q.rightShift(2).add(1), this.curve.Q), this.curve);
                    return z.square().equals(this) ? z : null;
                }
                var qMinusOne = this.curve.Q.subtract(1);
                var legendreExponent = qMinusOne.rightShift(1);
                if (Neo.BigInteger.modPow(this.value, legendreExponent, this.curve.Q).equals(1))
                    return null;
                var u = qMinusOne.rightShift(2);
                var k = u.leftShift(1).add(1);
                var Q = this.value;
                var fourQ = Q.leftShift(2).mod(this.curve.Q);
                var U, V;
                do {
                    var P = void 0;
                    do {
                        P = Neo.BigInteger.random(this.curve.Q.bitLength());
                    } while (P.compareTo(this.curve.Q) >= 0 || !Neo.BigInteger.modPow(P.multiply(P).subtract(fourQ), legendreExponent, this.curve.Q).equals(qMinusOne));
                    var result = ECFieldElement.fastLucasSequence(this.curve.Q, P, Q, k);
                    U = result[0];
                    V = result[1];
                    if (V.multiply(V).mod(this.curve.Q).equals(fourQ)) {
                        if (V.testBit(0)) {
                            V = V.add(this.curve.Q);
                        }
                        V = V.rightShift(1);
                        console.assert(V.multiply(V).mod(this.curve.Q).equals(this.value));
                        return new ECFieldElement(V, this.curve);
                    }
                } while (U.equals(Neo.BigInteger.One) || U.equals(qMinusOne));
                return null;
            };
            ECFieldElement.prototype.square = function () {
                return new ECFieldElement(this.value.multiply(this.value).mod(this.curve.Q), this.curve);
            };
            ECFieldElement.prototype.subtract = function (other) {
                return new ECFieldElement(this.value.subtract(other.value).mod(this.curve.Q), this.curve);
            };
            return ECFieldElement;
        } ());
        Cryptography.ECFieldElement = ECFieldElement;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var ECPoint = (function () {
            function ECPoint(x, y, curve) {
                this.x = x;
                this.y = y;
                this.curve = curve;
                if ((x == null) != (y == null))
                    throw new RangeError("Exactly one of the field elements is null");
            }
            ECPoint.add = function (x, y) {
                if (x.isInfinity())
                    return y;
                if (y.isInfinity())
                    return x;
                if (x.x.equals(y.x)) {
                    if (x.y.equals(y.y))
                        return x.twice();
                    console.assert(x.y.equals(y.y.negate()));
                    return x.curve.Infinity;
                }
                var gamma = y.y.subtract(x.y).divide(y.x.subtract(x.x));
                var x3 = gamma.square().subtract(x.x).subtract(y.x);
                var y3 = gamma.multiply(x.x.subtract(x3)).subtract(x.y);
                return new ECPoint(x3, y3, x.curve);
            };
            ECPoint.prototype.compareTo = function (other) {
                if (this === other)
                    return 0;
                var result = this.x.compareTo(other.x);
                if (result != 0)
                    return result;
                return this.y.compareTo(other.y);
            };
            ECPoint.decodePoint = function (encoded, curve) {
                var p;
                var expectedLength = Math.ceil(curve.Q.bitLength() / 8);
                switch (encoded[0]) {
                    case 0x00:
                        {
                            if (encoded.length != 1)
                                throw new RangeError("Incorrect length for infinity encoding");
                            p = curve.Infinity;
                            break;
                        }
                    case 0x02:
                    case 0x03:
                        {
                            if (encoded.length != (expectedLength + 1))
                                throw new RangeError("Incorrect length for compressed encoding");
                            var yTilde = encoded[0] & 1;
                            var X1 = Neo.BigInteger.fromUint8Array(encoded.subarray(1), 1, false);
                            p = ECPoint.decompressPoint(yTilde, X1, curve);
                            break;
                        }
                    case 0x04:
                    case 0x06:
                    case 0x07:
                        {
                            if (encoded.length != (2 * expectedLength + 1))
                                throw new RangeError("Incorrect length for uncompressed/hybrid encoding");
                            var X1 = Neo.BigInteger.fromUint8Array(encoded.subarray(1, 1 + expectedLength), 1, false);
                            var Y1 = Neo.BigInteger.fromUint8Array(encoded.subarray(1 + expectedLength), 1, false);
                            p = new ECPoint(new Cryptography.ECFieldElement(X1, curve), new Cryptography.ECFieldElement(Y1, curve), curve);
                            break;
                        }
                    default:
                        throw new RangeError("Invalid point encoding " + encoded[0]);
                }
                return p;
            };
            ECPoint.decompressPoint = function (yTilde, X1, curve) {
                var x = new Cryptography.ECFieldElement(X1, curve);
                var alpha = x.multiply(x.square().add(curve.A)).add(curve.B);
                var beta = alpha.sqrt();
                if (beta == null)
                    throw new RangeError("Invalid point compression");
                var betaValue = beta.value;
                var bit0 = betaValue.isEven() ? 0 : 1;
                if (bit0 != yTilde) {
                    beta = new Cryptography.ECFieldElement(curve.Q.subtract(betaValue), curve);
                }
                return new ECPoint(x, beta, curve);
            };
            ECPoint.deserializeFrom = function (reader, curve) {
                var expectedLength = Math.floor((curve.Q.bitLength() + 7) / 8);
                var array = new Uint8Array(1 + expectedLength * 2);
                array[0] = reader.readByte();
                switch (array[0]) {
                    case 0x00:
                        return curve.Infinity;
                    case 0x02:
                    case 0x03:
                        reader.read(array.buffer, 1, expectedLength);
                        return ECPoint.decodePoint(new Uint8Array(array.buffer, 0, 33), curve);
                    case 0x04:
                    case 0x06:
                    case 0x07:
                        reader.read(array.buffer, 1, expectedLength * 2);
                        return ECPoint.decodePoint(array, curve);
                    default:
                        throw new Error("Invalid point encoding " + array[0]);
                }
            };
            ECPoint.prototype.encodePoint = function (commpressed) {
                if (this.isInfinity())
                    return new Uint8Array(1);
                var data;
                if (commpressed) {
                    data = new Uint8Array(33);
                }
                else {
                    data = new Uint8Array(65);
                    var yBytes = this.y.value.toUint8Array();
                    for (var i = 0; i < yBytes.length; i++)
                        data[65 - yBytes.length + i] = yBytes[yBytes.length - 1 - i];
                }
                var xBytes = this.x.value.toUint8Array();
                for (var i = 0; i < xBytes.length; i++)
                    data[33 - xBytes.length + i] = xBytes[xBytes.length - 1 - i];
                data[0] = commpressed ? this.y.value.isEven() ? 0x02 : 0x03 : 0x04;
                return data;
            };
            ECPoint.prototype.equals = function (other) {
                if (this === other)
                    return true;
                if (null === other)
                    return false;
                if (this.isInfinity && other.isInfinity)
                    return true;
                if (this.isInfinity || other.isInfinity)
                    return false;
                return this.x.equals(other.x) && this.y.equals(other.y);
            };
            ECPoint.fromUint8Array = function (arr, curve) {
                switch (arr.length) {
                    case 33:
                    case 65:
                        return ECPoint.decodePoint(arr, curve);
                    case 64:
                    case 72:
                        {
                            var arr_new = new Uint8Array(65);
                            arr_new[0] = 0x04;
                            arr_new.set(arr.subarray(arr.length - 64), 1);
                            return ECPoint.decodePoint(arr_new, curve);
                        }
                    case 96:
                    case 104:
                        {
                            var arr_new = new Uint8Array(65);
                            arr_new[0] = 0x04;
                            arr_new.set(arr.subarray(arr.length - 96, arr.length - 32), 1);
                            return ECPoint.decodePoint(arr_new, curve);
                        }
                    default:
                        throw new RangeError();
                }
            };
            ECPoint.prototype.isInfinity = function () {
                return this.x == null && this.y == null;
            };
            ECPoint.multiply = function (p, n) {
                var k = n instanceof Uint8Array ? Neo.BigInteger.fromUint8Array(n, 1, false) : n;
                if (p.isInfinity())
                    return p;
                if (k.isZero())
                    return p.curve.Infinity;
                var m = k.bitLength();
                var width;
                var reqPreCompLen;
                if (m < 13) {
                    width = 2;
                    reqPreCompLen = 1;
                }
                else if (m < 41) {
                    width = 3;
                    reqPreCompLen = 2;
                }
                else if (m < 121) {
                    width = 4;
                    reqPreCompLen = 4;
                }
                else if (m < 337) {
                    width = 5;
                    reqPreCompLen = 8;
                }
                else if (m < 897) {
                    width = 6;
                    reqPreCompLen = 16;
                }
                else if (m < 2305) {
                    width = 7;
                    reqPreCompLen = 32;
                }
                else {
                    width = 8;
                    reqPreCompLen = 127;
                }
                var preCompLen = 1;
                var preComp = [p];
                var twiceP = p.twice();
                if (preCompLen < reqPreCompLen) {
                    var oldPreComp = preComp;
                    preComp = new Array(reqPreCompLen);
                    for (var i = 0; i < preCompLen; i++)
                        preComp[i] = oldPreComp[i];
                    for (var i = preCompLen; i < reqPreCompLen; i++) {
                        preComp[i] = ECPoint.add(twiceP, preComp[i - 1]);
                    }
                }
                var wnaf = ECPoint.windowNaf(width, k);
                var l = wnaf.length;
                var q = p.curve.Infinity;
                for (var i = l - 1; i >= 0; i--) {
                    q = q.twice();
                    if (wnaf[i] != 0) {
                        if (wnaf[i] > 0) {
                            q = ECPoint.add(q, preComp[Math.floor((wnaf[i] - 1) / 2)]);
                        }
                        else {
                            q = ECPoint.subtract(q, preComp[Math.floor((-wnaf[i] - 1) / 2)]);
                        }
                    }
                }
                return q;
            };
            ECPoint.prototype.negate = function () {
                return new ECPoint(this.x, this.y.negate(), this.curve);
            };
            ECPoint.parse = function (str, curve) {
                return ECPoint.decodePoint(str.hexToBytes(), curve);
            };
            ECPoint.subtract = function (x, y) {
                if (y.isInfinity())
                    return x;
                return ECPoint.add(x, y.negate());
            };
            ECPoint.prototype.toString = function () {
                return this.encodePoint(true).toHexString();
            };
            ECPoint.prototype.twice = function () {
                if (this.isInfinity())
                    return this;
                if (this.y.value.sign() == 0)
                    return this.curve.Infinity;
                var TWO = new Cryptography.ECFieldElement(new Neo.BigInteger(2), this.curve);
                var THREE = new Cryptography.ECFieldElement(new Neo.BigInteger(3), this.curve);
                var gamma = this.x.square().multiply(THREE).add(this.curve.A).divide(this.y.multiply(TWO));
                var x3 = gamma.square().subtract(this.x.multiply(TWO));
                var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
                return new ECPoint(x3, y3, this.curve);
            };
            ECPoint.windowNaf = function (width, k) {
                var wnaf = new Array(k.bitLength() + 1);
                var pow2wB = 1 << width;
                var i = 0;
                var length = 0;
                while (k.sign() > 0) {
                    if (!k.isEven()) {
                        var remainder = Neo.BigInteger.remainder(k, pow2wB);
                        if (remainder.testBit(width - 1)) {
                            wnaf[i] = Neo.BigInteger.subtract(remainder, pow2wB).toInt32();
                        }
                        else {
                            wnaf[i] = remainder.toInt32();
                        }
                        k = k.subtract(wnaf[i]);
                        length = i;
                    }
                    else {
                        wnaf[i] = 0;
                    }
                    k = k.rightShift(1);
                    i++;
                }
                wnaf.length = length + 1;
                return wnaf;
            };
            return ECPoint;
        } ());
        Cryptography.ECPoint = ECPoint;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var RandomNumberGenerator = (function () {
            function RandomNumberGenerator() {
            }
            RandomNumberGenerator.addEntropy = function (data, strength) {
                if (RandomNumberGenerator._stopped)
                    return;
                for (var i = 0; i < data.length; i++)
                    if (data[i] != null && data[i] != 0) {
                        RandomNumberGenerator._entropy.push(data[i]);
                        RandomNumberGenerator._strength += strength;
                        RandomNumberGenerator._key = null;
                    }
                if (RandomNumberGenerator._strength >= 512)
                    RandomNumberGenerator.stopCollectors();
            };
            RandomNumberGenerator.getRandomValues = function (array) {
                if (RandomNumberGenerator._strength < 256)
                    throw new Error();
                if (RandomNumberGenerator._key == null) {
                    var data = new Float64Array(RandomNumberGenerator._entropy);
                    RandomNumberGenerator._key = new Uint8Array(Cryptography.Sha256.computeHash(data));
                }
                var aes = new Cryptography.Aes(RandomNumberGenerator._key, RandomNumberGenerator.getWeakRandomValues(16));
                var src = new Uint8Array(16);
                var dst = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
                for (var i = 0; i < dst.length; i += 16) {
                    aes.encryptBlock(RandomNumberGenerator.getWeakRandomValues(16), src);
                    Array.copy(src, 0, dst, i, Math.min(dst.length - i, 16));
                }
                return array;
            };
            RandomNumberGenerator.getWeakRandomValues = function (array) {
                var buffer = typeof array === "number" ? new Uint8Array(array) : array;
                for (var i = 0; i < buffer.length; i++)
                    buffer[i] = Math.random() * 256;
                return buffer;
            };
            RandomNumberGenerator.processDeviceMotionEvent = function (event) {
                RandomNumberGenerator.addEntropy([event.accelerationIncludingGravity.x, event.accelerationIncludingGravity.y, event.accelerationIncludingGravity.z], 1);
                RandomNumberGenerator.processEvent(event);
            };
            RandomNumberGenerator.processEvent = function (event) {
                // if (window.performance && window.performance.now)
                //     RandomNumberGenerator.addEntropy([window.performance.now()], 20);
                // else
                //     RandomNumberGenerator.addEntropy([event.timeStamp], 2);
            };
            RandomNumberGenerator.processMouseEvent = function (event) {
                RandomNumberGenerator.addEntropy([event.clientX, event.clientY, event.offsetX, event.offsetY, event.screenX, event.screenY], 4);
                RandomNumberGenerator.processEvent(event);
            };
            RandomNumberGenerator.processTouchEvent = function (event) {
                var touches = event.changedTouches || event.touches;
                for (var i = 0; i < touches.length; i++)
                    RandomNumberGenerator.addEntropy([touches[i].clientX, touches[i].clientY, touches[i]["radiusX"], touches[i]["radiusY"], touches[i]["force"]], 1);
                RandomNumberGenerator.processEvent(event);
            };
            RandomNumberGenerator.startCollectors = function () {
                // if (RandomNumberGenerator._started)
                //     return;
                // window.addEventListener("load", RandomNumberGenerator.processEvent, false);
                // window.addEventListener("mousemove", RandomNumberGenerator.processMouseEvent, false);
                // window.addEventListener("keypress", RandomNumberGenerator.processEvent, false);
                // window.addEventListener("devicemotion", RandomNumberGenerator.processDeviceMotionEvent, false);
                // window.addEventListener("touchmove", RandomNumberGenerator.processTouchEvent, false);
                // RandomNumberGenerator._started = true;
            };
            RandomNumberGenerator.stopCollectors = function () {
                // if (RandomNumberGenerator._stopped)
                //     return;
                // window.removeEventListener("load", RandomNumberGenerator.processEvent, false);
                // window.removeEventListener("mousemove", RandomNumberGenerator.processMouseEvent, false);
                // window.removeEventListener("keypress", RandomNumberGenerator.processEvent, false);
                // window.removeEventListener("devicemotion", RandomNumberGenerator.processDeviceMotionEvent, false);
                // window.removeEventListener("touchmove", RandomNumberGenerator.processTouchEvent, false);
                // RandomNumberGenerator._stopped = true;
            };
            RandomNumberGenerator._entropy = [];
            RandomNumberGenerator._strength = 0;
            RandomNumberGenerator._started = false;
            RandomNumberGenerator._stopped = false;
            return RandomNumberGenerator;
        } ());
        Cryptography.RandomNumberGenerator = RandomNumberGenerator;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var RIPEMD160 = (function () {
            function RIPEMD160() {
            }
            RIPEMD160.bytesToWords = function (bytes) {
                var words = [];
                for (var i = 0, b = 0; i < bytes.length; i++ , b += 8) {
                    words[b >>> 5] |= bytes[i] << (24 - b % 32);
                }
                return words;
            };
            RIPEMD160.wordsToBytes = function (words) {
                var bytes = [];
                for (var b = 0; b < words.length * 32; b += 8) {
                    bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
                }
                return bytes;
            };
            RIPEMD160.processBlock = function (H, M, offset) {
                for (var i = 0; i < 16; i++) {
                    var offset_i = offset + i;
                    var M_offset_i = M[offset_i];
                    M[offset_i] = ((((M_offset_i << 8) | (M_offset_i >>> 24)) & 0x00ff00ff) |
                        (((M_offset_i << 24) | (M_offset_i >>> 8)) & 0xff00ff00));
                }
                var al, bl, cl, dl, el;
                var ar, br, cr, dr, er;
                ar = al = H[0];
                br = bl = H[1];
                cr = cl = H[2];
                dr = dl = H[3];
                er = el = H[4];
                var t;
                for (var i = 0; i < 80; i += 1) {
                    t = (al + M[offset + RIPEMD160.zl[i]]) | 0;
                    if (i < 16) {
                        t += RIPEMD160.f1(bl, cl, dl) + RIPEMD160.hl[0];
                    }
                    else if (i < 32) {
                        t += RIPEMD160.f2(bl, cl, dl) + RIPEMD160.hl[1];
                    }
                    else if (i < 48) {
                        t += RIPEMD160.f3(bl, cl, dl) + RIPEMD160.hl[2];
                    }
                    else if (i < 64) {
                        t += RIPEMD160.f4(bl, cl, dl) + RIPEMD160.hl[3];
                    }
                    else {
                        t += RIPEMD160.f5(bl, cl, dl) + RIPEMD160.hl[4];
                    }
                    t = t | 0;
                    t = RIPEMD160.rotl(t, RIPEMD160.sl[i]);
                    t = (t + el) | 0;
                    al = el;
                    el = dl;
                    dl = RIPEMD160.rotl(cl, 10);
                    cl = bl;
                    bl = t;
                    t = (ar + M[offset + RIPEMD160.zr[i]]) | 0;
                    if (i < 16) {
                        t += RIPEMD160.f5(br, cr, dr) + RIPEMD160.hr[0];
                    }
                    else if (i < 32) {
                        t += RIPEMD160.f4(br, cr, dr) + RIPEMD160.hr[1];
                    }
                    else if (i < 48) {
                        t += RIPEMD160.f3(br, cr, dr) + RIPEMD160.hr[2];
                    }
                    else if (i < 64) {
                        t += RIPEMD160.f2(br, cr, dr) + RIPEMD160.hr[3];
                    }
                    else {
                        t += RIPEMD160.f1(br, cr, dr) + RIPEMD160.hr[4];
                    }
                    t = t | 0;
                    t = RIPEMD160.rotl(t, RIPEMD160.sr[i]);
                    t = (t + er) | 0;
                    ar = er;
                    er = dr;
                    dr = RIPEMD160.rotl(cr, 10);
                    cr = br;
                    br = t;
                }
                t = (H[1] + cl + dr) | 0;
                H[1] = (H[2] + dl + er) | 0;
                H[2] = (H[3] + el + ar) | 0;
                H[3] = (H[4] + al + br) | 0;
                H[4] = (H[0] + bl + cr) | 0;
                H[0] = t;
            };
            RIPEMD160.f1 = function (x, y, z) { return ((x) ^ (y) ^ (z)); };
            RIPEMD160.f2 = function (x, y, z) { return (((x) & (y)) | ((~x) & (z))); };
            RIPEMD160.f3 = function (x, y, z) { return (((x) | (~(y))) ^ (z)); };
            RIPEMD160.f4 = function (x, y, z) { return (((x) & (z)) | ((y) & (~(z)))); };
            RIPEMD160.f5 = function (x, y, z) { return ((x) ^ ((y) | (~(z)))); };
            RIPEMD160.rotl = function (x, n) { return (x << n) | (x >>> (32 - n)); };
            RIPEMD160.computeHash = function (data) {
                var H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
                var m = RIPEMD160.bytesToWords(Uint8Array.fromArrayBuffer(data));
                var nBitsLeft = data.byteLength * 8;
                var nBitsTotal = data.byteLength * 8;
                m[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
                m[(((nBitsLeft + 64) >>> 9) << 4) + 14] = ((((nBitsTotal << 8) | (nBitsTotal >>> 24)) & 0x00ff00ff) |
                    (((nBitsTotal << 24) | (nBitsTotal >>> 8)) & 0xff00ff00));
                for (var i = 0; i < m.length; i += 16) {
                    RIPEMD160.processBlock(H, m, i);
                }
                for (var i = 0; i < 5; i++) {
                    var H_i = H[i];
                    H[i] = (((H_i << 8) | (H_i >>> 24)) & 0x00ff00ff) |
                        (((H_i << 24) | (H_i >>> 8)) & 0xff00ff00);
                }
                var digestbytes = RIPEMD160.wordsToBytes(H);
                return new Uint8Array(digestbytes).buffer;
            };
            RIPEMD160.zl = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
            ];
            RIPEMD160.zr = [
                5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
            ];
            RIPEMD160.sl = [
                11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
            ];
            RIPEMD160.sr = [
                8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
                9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
                15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
            ];
            RIPEMD160.hl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
            RIPEMD160.hr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
            return RIPEMD160;
        } ());
        Cryptography.RIPEMD160 = RIPEMD160;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Neo;
(function (Neo) {
    var Cryptography;
    (function (Cryptography) {
        var Sha256 = (function () {
            function Sha256() {
            }
            Sha256.computeHash = function (data) {
                var H = new Uint32Array([
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                ]);
                var l = data.byteLength / 4 + 2;
                var N = Math.ceil(l / 16);
                var M = new Array(N);
                var view = Uint8Array.fromArrayBuffer(data);
                for (var i = 0; i < N; i++) {
                    M[i] = new Uint32Array(16);
                    for (var j = 0; j < 16; j++) {
                        M[i][j] = (view[i * 64 + j * 4] << 24) | (view[i * 64 + j * 4 + 1] << 16) |
                            (view[i * 64 + j * 4 + 2] << 8) | (view[i * 64 + j * 4 + 3]);
                    }
                }
                M[Math.floor(data.byteLength / 4 / 16)][Math.floor(data.byteLength / 4) % 16] |= 0x80 << ((3 - data.byteLength % 4) * 8);
                M[N - 1][14] = (data.byteLength * 8) / Math.pow(2, 32);
                M[N - 1][15] = (data.byteLength * 8) & 0xffffffff;
                var W = new Uint32Array(64);
                var a, b, c, d, e, f, g, h;
                for (var i = 0; i < N; i++) {
                    for (var t = 0; t < 16; t++)
                        W[t] = M[i][t];
                    for (var t = 16; t < 64; t++)
                        W[t] = (Sha256.σ1(W[t - 2]) + W[t - 7] + Sha256.σ0(W[t - 15]) + W[t - 16]) & 0xffffffff;
                    a = H[0];
                    b = H[1];
                    c = H[2];
                    d = H[3];
                    e = H[4];
                    f = H[5];
                    g = H[6];
                    h = H[7];
                    for (var t = 0; t < 64; t++) {
                        var T1 = h + Sha256.Σ1(e) + Sha256.Ch(e, f, g) + Sha256.K[t] + W[t];
                        var T2 = Sha256.Σ0(a) + Sha256.Maj(a, b, c);
                        h = g;
                        g = f;
                        f = e;
                        e = (d + T1) & 0xffffffff;
                        d = c;
                        c = b;
                        b = a;
                        a = (T1 + T2) & 0xffffffff;
                    }
                    H[0] = (H[0] + a) & 0xffffffff;
                    H[1] = (H[1] + b) & 0xffffffff;
                    H[2] = (H[2] + c) & 0xffffffff;
                    H[3] = (H[3] + d) & 0xffffffff;
                    H[4] = (H[4] + e) & 0xffffffff;
                    H[5] = (H[5] + f) & 0xffffffff;
                    H[6] = (H[6] + g) & 0xffffffff;
                    H[7] = (H[7] + h) & 0xffffffff;
                }
                var result = new Uint8Array(32);
                for (var i = 0; i < H.length; i++) {
                    result[i * 4 + 0] = (H[i] >>> (3 * 8)) & 0xff;
                    result[i * 4 + 1] = (H[i] >>> (2 * 8)) & 0xff;
                    result[i * 4 + 2] = (H[i] >>> (1 * 8)) & 0xff;
                    result[i * 4 + 3] = (H[i] >>> (0 * 8)) & 0xff;
                }
                return result.buffer;
            };
            Sha256.ROTR = function (n, x) { return (x >>> n) | (x << (32 - n)); };
            Sha256.Σ0 = function (x) { return Sha256.ROTR(2, x) ^ Sha256.ROTR(13, x) ^ Sha256.ROTR(22, x); };
            Sha256.Σ1 = function (x) { return Sha256.ROTR(6, x) ^ Sha256.ROTR(11, x) ^ Sha256.ROTR(25, x); };
            Sha256.σ0 = function (x) { return Sha256.ROTR(7, x) ^ Sha256.ROTR(18, x) ^ (x >>> 3); };
            Sha256.σ1 = function (x) { return Sha256.ROTR(17, x) ^ Sha256.ROTR(19, x) ^ (x >>> 10); };
            Sha256.Ch = function (x, y, z) { return (x & y) ^ (~x & z); };
            Sha256.Maj = function (x, y, z) { return (x & y) ^ (x & z) ^ (y & z); };
            Sha256.K = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            ];
            return Sha256;
        } ());
        Cryptography.Sha256 = Sha256;
    })(Cryptography = Neo.Cryptography || (Neo.Cryptography = {}));
})(Neo || (Neo = {}));
var Tool = (function () {
    function Tool() {
    }
    Tool.selectMainNet = function () {
        Tool.api_net = "https://api.nel.group/api/mainnet";
    };
    Tool.selectTestNet = function () {
        Tool.api_net = "https://api.nel.group/api/testnet";
    };
    Tool.makeRpcPostBody = function (method) {
        var _params = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            _params[_i - 1] = arguments[_i];
        }
        var body = {};
        body["jsonrpc"] = "2.0";
        body["id"] = 1;
        body["method"] = method;
        var params = [];
        for (var i = 0; i < _params.length; i++) {
            params.push(_params[i]);
        }
        body["params"] = params;
        return body;
    };
    Tool.makeRpcUrl = function (url, method) {
        var _params = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            _params[_i - 2] = arguments[_i];
        }
        var urlout = url + "?jsonrpc=2.0&id=1&method=" + encodeURIComponent(method) + "&params=[";
        for (var i = 0; i < _params.length; i++) {
            urlout += encodeURIComponent(JSON.stringify(_params[i]));
            if (i != _params.length - 1)
                urlout += ",";
        }
        urlout += "]";
        return urlout;
    };
    Tool.paresInvokeJson = function (scripthash, args) {
        var sb = new ThinNeo.ScriptBuilder();
        var random_int;
        try {
            var random_uint8 = Neo.Cryptography.RandomNumberGenerator.getRandomValues(new Uint8Array(32));
            random_int = Neo.BigInteger.fromUint8Array(random_uint8);
        }
        catch (e) {
            var math_rand = parseInt((Math.random() * 10000000).toString());
            random_int = new Neo.BigInteger(math_rand);
        }
        sb.EmitPushNumber(random_int);
        sb.Emit(ThinNeo.OpCode.DROP);
        sb.EmitParamJson(args[1]);
        sb.EmitParamJson(args[0]);
        var appcall = scripthash.hexToBytes().reverse();
        sb.EmitAppCall(appcall);
        return sb.ToArray();
    };
    Tool.buildInvokeTransData_attributes = function (script) {
        var tran = new ThinNeo.Transaction();
        tran.inputs = [];
        tran.outputs = [];
        tran.type = ThinNeo.TransactionType.InvocationTransaction;
        tran.extdata = new ThinNeo.InvokeTransData();
        tran.extdata.script = script;
        tran.attributes = new Array(1);
        tran.attributes[0] = new ThinNeo.Attribute();
        tran.attributes[0].usage = ThinNeo.TransactionAttributeUsage.Script;
        tran.attributes[0].data = ThinNeo.Helper.GetPublicKeyScriptHash_FromAddress(Tool.address);
        if (tran.witnesses == null)
            tran.witnesses = [];
        var data = Tool.signData(tran);
        return data;
    };
    Tool.signData = function (tran) {
        try {
            var msg = tran.GetMessage().clone();
            var addr = Tool.address;
            var pub = Tool.pubkey.clone();
            var pre = Tool.prikey.clone();
            var signdata = ThinNeo.Helper.Sign(msg, pre);
            tran.AddWitness(signdata, pub, addr);
            var data = tran.GetRawData();
            return data;
        }
        catch (error) {
            return null;
        }
    };
    Tool.hexToString = function (hex) {
        var trimhex = hex.trim();
        var rawStr = trimhex.substr(0, 2).toLowerCase() === "0x" ? trimhex.substr(2) : trimhex;
        var len = rawStr.length;
        if (len % 2 !== 0) {
            alert("Illegal Format ASCII Code!");
            return "";
        }
        var cuChar;
        var result = [];
        for (var i = 0; i < len; i = i + 2) {
            cuChar = parseInt(rawStr.substr(i, 2), 16);
            result.push(String.fromCharCode(cuChar));
        }
        return result.join("");
    };
    Tool.stringToHex = function (str) {
        if (str === "")
            return "";
        var hexChar = [];
        for (var i = 0; i < str.length; i++) {
            hexChar.push((str.charCodeAt(i)).toString(16));
        }
        return hexChar.join("");
    };
    Tool.hexToNumber = function (hex) {
        var num = hex.hexToBytes();
        var str = new Neo.BigInteger(num);
        return str.toString();
    };
    Tool.numberToHex = function (str) {
        var num = new Neo.BigInteger(str);
        var text = num.toUint8Array().toHexString();
        return text;
    };
    Tool.api_net = "https://api.nel.group/api/testnet";
    return Tool;
}());
var AsynTask = (function () {
    function AsynTask(onFin) {
        this._asynCount = 0;
        this._asynLength = 0;
        this._onFin = onFin;
    }
    AsynTask.prototype.execute = function (code) {
        this._asynLength++;
    };
    AsynTask.prototype.complete = function () {
        this._asynCount++;
        if (this._asynCount == this._asynLength) {
            this._onFin && this._onFin.run();
        }
    };
    return AsynTask;
}());
var ArrayUtils = (function () {
    function ArrayUtils() {
    }
    ArrayUtils.randOrder = function (arr) {
        var arrClone = arr.concat();
        var newArr = [];
        while (arrClone.length > 0) {
            var obj = arrClone.splice(MathUtils.rand(arrClone.length), 1)[0];
            newArr.push(obj);
        }
        var len = arr.length;
        for (var i = 0; i < len; i++) {
            arr[i] = newArr[i];
        }
    };
    ArrayUtils.insert = function (arr, index) {
        var arg = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            arg[_i - 2] = arguments[_i];
        }
        var returnIndex;
        if (index == -1) {
            returnIndex = arr.length;
            arr.push.apply(arr, arg);
        }
        else {
            returnIndex = index;
            arr.splice.apply(arr, [index, 0].concat(arg));
        }
        return returnIndex;
    };
    ArrayUtils.delete = function (arr, index) {
        return index == -1 ? arr.pop() : arr.splice(index, 1)[0];
    };
    ArrayUtils.remove = function (arr, obj) {
        var idx = arr.indexOf(obj);
        if (idx == -1)
            return null;
        return arr.splice(idx, 1)[0];
    };
    ArrayUtils.get = function (arr, index) {
        var index = index == -1 ? arr.length - 1 : index;
        return arr[index];
    };
    ArrayUtils.set = function (arr, index, paramValue) {
        function setValue(obj, paramValue) {
            for (var s in paramValue) {
                obj[s] = paramValue[s];
            }
        }
        if (index == -2) {
            var len = arr.length;
            for (var i = 0; i < len; i++) {
                setValue(arr[i], paramValue);
            }
            return arr;
        }
        else if (index == -1) {
            var obj = arr[arr.length - 1];
            setValue(obj, paramValue);
            return [obj];
        }
        else {
            var obj = arr[index];
            setValue(obj, paramValue);
            return [obj];
        }
    };
    ArrayUtils.insertToNullPosition = function (arr, obj) {
        var idx = ArrayUtils.getNullPosition(arr);
        arr[idx] = obj;
        return idx;
    };
    ArrayUtils.getNullPosition = function (arr) {
        var index = -1;
        for (var i = 0; i < arr.length; i++) {
            if (!arr[i]) {
                index = i;
                break;
            }
        }
        if (index == -1)
            index = arr.length;
        return index;
    };
    ArrayUtils.removeSameObject = function (arr) {
        var newArr = [];
        for (var i = arr.length - 1; i >= 0; i--) {
            var obj = arr[i];
            if (newArr.indexOf(obj) == -1) {
                newArr.push(obj);
            }
        }
        return newArr.reverse();
    };
    ;
    ArrayUtils.matchAttributes = function (arr, matchData, onlyOne, symbol, indexOfMode) {
        if (symbol === void 0) { symbol = "=="; }
        if (indexOfMode === void 0) { indexOfMode = false; }
        var matchs = [];
        for (var i in arr) {
            var obj = arr[i];
            if (!obj)
                continue;
            var isMatch = true;
            for (var s in matchData) {
                if ((symbol == "==" && obj[s] != matchData[s]) ||
                    (symbol == ">=" && obj[s] < matchData[s]) ||
                    (symbol == "<=" && obj[s] > matchData[s]) ||
                    (symbol == ">" && obj[s] <= matchData[s]) ||
                    (symbol == "<" && obj[s] >= matchData[s]) ||
                    (symbol == "!=" && obj[s] == matchData[s])) {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) {
                matchs.push(indexOfMode ? parseInt(i) : obj);
                if (onlyOne)
                    break;
            }
        }
        return matchs;
    };
    ;
    ArrayUtils.matchAttributesD2 = function (arr, attribute, matchData, onlyOne, symbol) {
        if (symbol === void 0) { symbol = "=="; }
        var matchs = [];
        for (var i in arr) {
            var obj = arr[i];
            var isMatch = true;
            if (!obj[attribute])
                continue;
            for (var s in matchData) {
                if ((symbol == "==" && obj[attribute][s] != matchData[s]) ||
                    (symbol == ">=" && obj[attribute][s] < matchData[s]) ||
                    (symbol == "<=" && obj[attribute][s] > matchData[s]) ||
                    (symbol == ">" && obj[attribute][s] <= matchData[s]) ||
                    (symbol == "<" && obj[attribute][s] >= matchData[s]) ||
                    (symbol == "!=" && obj[attribute][s] == matchData[s])) {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) {
                matchs.push(obj);
                if (onlyOne)
                    break;
            }
        }
        return matchs;
    };
    ;
    ArrayUtils.matchAttributesD3 = function (arr, attribute, attribute2, matchData, onlyOne, symbol) {
        if (symbol === void 0) { symbol = "=="; }
        var matchs = [];
        for (var i in arr) {
            var obj = arr[i];
            var isMatch = true;
            if (!obj[attribute])
                continue;
            if (!obj[attribute][attribute2])
                continue;
            for (var s in matchData) {
                if ((symbol == "==" && obj[attribute][attribute2][s] != matchData[s]) ||
                    (symbol == ">=" && obj[attribute][attribute2][s] < matchData[s]) ||
                    (symbol == "<=" && obj[attribute][attribute2][s] > matchData[s]) ||
                    (symbol == ">" && obj[attribute][attribute2][s] <= matchData[s]) ||
                    (symbol == "<" && obj[attribute][attribute2][s] >= matchData[s]) ||
                    (symbol == "!=" && obj[attribute][attribute2][s] == matchData[s])) {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) {
                matchs.push(obj);
                if (onlyOne)
                    break;
            }
        }
        return matchs;
    };
    ;
    ArrayUtils.getElementSize = function (arr, value) {
        var n = 0;
        for (var i in arr) {
            if (arr[i] == value)
                n++;
        }
        return n;
    };
    ArrayUtils.createObjects = function (objCls, size, onCreateOne, arr) {
        if (onCreateOne === void 0) { onCreateOne = null; }
        if (arr === void 0) { arr = null; }
        if (!arr)
            arr = [];
        for (var i = 0; i < size; i++) {
            var o = new objCls();
            onCreateOne && onCreateOne(i, o);
            arr.push(o);
        }
        return arr;
    };
    ArrayUtils.swap = function (arr, index1, index2) {
        var last = arr[index1];
        arr[index1] = arr[index2];
        arr[index2] = last;
    };
    ArrayUtils.adjustment = function (arr, element, index) {
        var idx = arr.indexOf(element);
        if (idx == -1)
            return;
        arr.splice(idx, 1);
        idx < index && index--;
        arr.splice(index + 1, 0, element);
    };
    ArrayUtils.sort = function (arr, attributeName, isAsc) {
        function order(a, b) {
            var aStr = a[attributeName];
            var bStr = b[attributeName];
            var min = Math.min(aStr.length, bStr.length);
            for (var i = 0; i < min; i++) {
                var code1 = aStr[i].toLocaleLowerCase().charCodeAt(0);
                var code2 = bStr[i].toLocaleLowerCase().charCodeAt(0);
                if (code1 == code2) {
                    continue;
                }
                return isAsc ? (code1 < code2 ? -1 : 1) : (code1 < code2 ? 1 : -1);
            }
            return -1;
        }
        arr.sort(order);
    };
    ;
    ArrayUtils.compare = function (aArr, bArr) {
        var appended = [];
        if (aArr == null)
            aArr = [];
        if (bArr == null)
            bArr = [];
        var subtract = bArr.concat();
        var aLen = aArr.length;
        for (var i = 0; i < aLen; i++) {
            var a = aArr[i];
            var idx = subtract.indexOf(a);
            if (idx != -1) {
                subtract.splice(idx, 1);
            }
            else {
                appended.push(a);
            }
        }
        return {
            appended: appended,
            subtract: subtract
        };
    };
    ArrayUtils.getTreeNodeArray = function (treeNode, childrenAttr, arrayList, checkIsOpen, isOpenAttr) {
        if (childrenAttr === void 0) { childrenAttr = "children"; }
        if (arrayList === void 0) { arrayList = null; }
        if (checkIsOpen === void 0) { checkIsOpen = false; }
        if (isOpenAttr === void 0) { isOpenAttr = "isOpen"; }
        if (!arrayList)
            arrayList = [];
        arrayList.push(treeNode);
        var children = treeNode[childrenAttr];
        if (!children)
            return arrayList;
        if (!checkIsOpen || (checkIsOpen && treeNode[isOpenAttr])) {
            var len = children.length;
            for (var i = 0; i < len; i++) {
                ArrayUtils.getTreeNodeArray(children[i], childrenAttr, arrayList, checkIsOpen, isOpenAttr);
            }
        }
        return arrayList;
    };
    return ArrayUtils;
}());
var EventUtils = (function () {
    function EventUtils() {
    }
    EventUtils.addEventListener = function (obj, type, callBack, isOnce) {
        if (isOnce === void 0) { isOnce = false; }
        if (!obj)
            return;
        var evIdx = obj["__evIdx"];
        var evTypes;
        if (evIdx != null) {
            evTypes = EventUtils.evList[evIdx];
        }
        else {
            evTypes = {};
            evIdx = ArrayUtils.insertToNullPosition(EventUtils.evList, evTypes);
            obj["__evIdx"] = evIdx;
        }
        var evArrs = evTypes[type];
        if (!evArrs)
            evTypes[type] = evArrs = [];
        var evArr = [callBack, isOnce];
        evArrs.push(evArr);
    };
    EventUtils.removeEventListener = function (obj, type, callBack) {
        if (!obj)
            return;
        var evIdx = obj["__evIdx"];
        if (evIdx != null) {
            var evTypes = EventUtils.evList[evIdx];
            var evArrs = evTypes[type];
            for (var i in evArrs) {
                var evArr = evArrs[i];
                if (evArr[0] == callBack) {
                    evArrs.splice(parseInt(i), 1);
                    break;
                }
            }
        }
    };
    EventUtils.happen = function (obj, type, args) {
        if (args === void 0) { args = null; }
        if (!obj)
            return;
        var evIdx = obj["__evIdx"];
        var happenFuncs = [];
        if (evIdx != null) {
            var evTypes = EventUtils.evList[evIdx];
            var evArrs = evTypes[type];
            if (!evArrs)
                return;
            for (var i = 0; i < evArrs.length; i++) {
                var evArr = evArrs[i];
                var callback = evArr[0];
                var isOnce = evArr[1];
                if (isOnce) {
                    evArrs.splice(i, 1);
                    i--;
                }
                happenFuncs.push(callback);
            }
            happenFuncs.forEach(function (callback, index, array) {
                args ? callback.runWith(args) : callback.run();
            });
        }
    };
    EventUtils.clear = function (obj, type) {
        if (type === void 0) { type = null; }
        if (!obj)
            return;
        var evIdx = obj["__evIdx"];
        if (evIdx != null) {
            EventUtils.evList[evIdx] = null;
            delete obj["__evIdx"];
        }
    };
    EventUtils.evList = [];
    return EventUtils;
}());
var ObjectUtils = (function () {
    function ObjectUtils() {
    }
    ObjectUtils.getInstanceID = function () {
        return ObjectUtils.idCount++;
    };
    ObjectUtils.getRandID = function () {
        return (new Date().getTime() - 1557554040401) + "_" + Math.random();
    };
    ObjectUtils.clone = function (form, to) {
        for (var i in form) {
            to[i] = form[i];
        }
    };
    ObjectUtils.cloneExcludeNonExistentAttribute = function (form, to) {
        for (var i in to) {
            to[i] = form[i];
        }
    };
    ObjectUtils.depthClone = function (o) {
        return JSON.parse(JSON.stringify(o));
    };
    ObjectUtils.same = function (a, b) {
        if ((a == null && b != null) || (a != null && b == null))
            return false;
        for (var i in a) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    };
    ObjectUtils.depthSame = function (a, b) {
        if ((a == null && b != null) || (a != null && b == null))
            return false;
        var aLen = 0, bLen = 0;
        for (var i in a) {
            aLen++;
        }
        for (var i in b) {
            bLen++;
        }
        if (bLen != aLen)
            return false;
        for (var i in a) {
            var aValue = a[i];
            if (typeof aValue == "boolean" || typeof aValue == "number" || typeof aValue == "string") {
                if (aValue != b[i]) {
                    return false;
                }
            }
            else {
                if (!ObjectUtils.depthSame(aValue, b[i])) {
                    return false;
                }
            }
        }
        return true;
    };
    ObjectUtils.assignment = function (a, b) {
        for (var i in b) {
            var value = b[i];
            var attrType = typeof value;
            if (attrType == "number" || attrType == "string" || attrType == "boolean") {
                a[i] = value;
            }
            else if (typeof a[i] == "function") {
                continue;
            }
            else {
                if (a[i]) {
                    this.assignment(a[i], value);
                }
            }
        }
    };
    ObjectUtils.reDefineGetSet = function (target, defineContent) {
        for (var i in defineContent) {
            var str = "\n            Object.defineProperty(" + target + ", \"" + i + "\", {\n                set: function (v) {\n                    this._" + i + " = v;\n                    defineContent." + i + ".apply(this,[v]);\n                },\n                get: function () {\n                    return this._" + i + "\n                }\n            });\n            ";
            eval(str);
        }
        var arr = target.split(".");
        if (arr.pop() == "prototype") {
            eval("setTimeout(function(){new " + arr.join(".") + "()},0);");
        }
    };
    ObjectUtils.redefinedEventFunc = function (clsName, types, toObjName) {
        var EvArr = ["hasListener", "event", "on", "once", "off", "offAll", "isMouseEvent"];
        var typesStr = JSON.stringify(types);
        for (var i in EvArr) {
            eval("\n                    " + clsName + ".prototype._" + EvArr[i] + " = " + clsName + ".prototype." + EvArr[i] + ";\n                    " + clsName + ".prototype." + EvArr[i] + " = function(type){\n                        if(" + typesStr + ".indexOf(type)!=-1){\n                            this." + toObjName + "." + EvArr[i] + ".apply(this." + toObjName + ",arguments);\n                        }\n                        else{\n                            this._" + EvArr[i] + ".apply(this,arguments);\n                        }\n                    }\n                ");
        }
    };
    ObjectUtils.idCount = 0;
    return ObjectUtils;
}());
var StringUtils = (function () {
    function StringUtils() {
    }
    StringUtils.getRealLength = function (str) {
        var realLength = 0, len = str.length, charCode = -1;
        for (var i = 0; i < len; i++) {
            charCode = str.charCodeAt(i);
            if (charCode >= 0 && charCode <= 128)
                realLength += 1;
            else
                realLength += 2;
        }
        return realLength;
    };
    StringUtils.clearHtmlTag = function (str) {
        return str.replace(/<(s|\/s)pa[^>]+>/g, "");
    };
    StringUtils.toHtmlEscape = function (t) {
        t = t.replace(/\</g, "〈");
        t = t.replace(/\>/g, "〉");
        t = t.replace(/&/g, "&amp;");
        t = t.replace(/ /g, "&nbsp;");
        return t;
    };
    StringUtils.getMiddleDiff = function (str1, str2) {
        var oldFirstEndIndex = 0;
        var newSccondStartIndex = 0;
        var shortLen = Math.min(str1.length, str2.length);
        for (var i = 0; i < shortLen; i++) {
            if (str1[i] == str2[i]) {
                oldFirstEndIndex = i + 1;
            }
            else {
                break;
            }
        }
        var nStr1 = str1.substr(oldFirstEndIndex);
        var nStr2 = str2.substr(oldFirstEndIndex);
        shortLen -= oldFirstEndIndex;
        for (var i = 0; i < shortLen; i++) {
            var oldIndex = nStr1.length - 1 - i;
            var newIndex = nStr2.length - 1 - i;
            if (nStr1[oldIndex] == nStr2[newIndex]) {
                newSccondStartIndex = i + 1;
            }
            else {
                break;
            }
        }
        return [oldFirstEndIndex, newSccondStartIndex];
    };
    ;
    return StringUtils;
}());
var SyncTask = (function () {
    function SyncTask(taskName, func, arg, thisPtr, isConver, jumpQuere) {
        if (func === void 0) { func = null; }
        if (arg === void 0) { arg = null; }
        if (thisPtr === void 0) { thisPtr = null; }
        if (isConver === void 0) { isConver = false; }
        if (jumpQuere === void 0) { jumpQuere = false; }
        var taskList = SyncTask.taskLists[taskName];
        if (!taskList)
            taskList = SyncTask.taskLists[taskName] = [];
        if (isConver) {
            var sameTaskList = ArrayUtils.matchAttributes(taskList, { func: func }, false);
            while (sameTaskList.length > 0) {
                var idx = taskList.indexOf(sameTaskList.shift());
                taskList.splice(idx, 1);
            }
        }
        if (jumpQuere) {
            taskList.unshift(this);
        }
        else {
            taskList.push(this);
        }
        this.func = func;
        this.arg = arg;
        this.thisPtr = thisPtr;
        SyncTask.doTask(taskName);
    }
    SyncTask.prototype.execute = function (taskName) {
        SyncTask.taskExecuteing[taskName] = true;
        if (!this.func)
            return;
        this.thisPtr ? this.func.apply(this.thisPtr, this.arg) : this.func.apply(this, this.arg);
    };
    SyncTask.doTask = function (taskName) {
        if (SyncTask.taskExecuteing[taskName])
            return;
        var taskList = SyncTask.taskLists[taskName];
        if (taskList && taskList.length > 0)
            taskList.shift().execute(taskName);
    };
    SyncTask.taskOver = function (taskName) {
        SyncTask.taskExecuteing[taskName] = false;
        SyncTask.doTask(taskName);
    };
    SyncTask.clear = function (taskName) {
        delete SyncTask.taskExecuteing[taskName];
        delete SyncTask.taskLists[taskName];
    };
    SyncTask.taskLists = {};
    SyncTask.taskExecuteing = [];
    return SyncTask;
}());
var MathUtils = (function () {
    function MathUtils() {
    }
    MathUtils.angle2Radian = function (angle) { return angle * Math.PI / 180; };
    ;
    MathUtils.radian2Angle = function (radian) { return 180 * radian / Math.PI; };
    ;
    MathUtils.rand = function (n) {
        return Math.floor(Math.random() * n);
    };
    MathUtils.direction_360 = function (x_x1, x_y1, x_x2, x_y2) {
        var n_r = Math.PI / 2;
        if (x_x1 != x_x2) {
            n_r = Math.atan((x_y1 - x_y2) / (x_x1 - x_x2));
        }
        var n_jiaodu = n_r * 180 / Math.PI;
        if (x_x2 > x_x1) {
            if (x_y2 > x_y1) {
                n_jiaodu = Math.abs(n_jiaodu) + 90;
            }
            else {
                n_jiaodu = 90 - Math.abs(n_jiaodu);
            }
        }
        else {
            if (x_y2 > x_y1) {
                n_jiaodu = 90 - Math.abs(n_jiaodu) + 180;
            }
            else {
                n_jiaodu = Math.abs(n_jiaodu) + 270;
            }
        }
        if (n_jiaodu == 360) {
            n_jiaodu = 0;
        }
        return n_jiaodu;
    };
    MathUtils.fixIntDigit = function (s, fixDigit) {
        if (fixDigit === void 0) { fixDigit = 4; }
        var ss = s.toString();
        while (ss.length < fixDigit) {
            ss = "0" + ss;
        }
        return ss;
    };
    MathUtils.int = function (v) {
        var a = parseInt(v);
        if (isNaN(a))
            return 0;
        return a;
    };
    MathUtils.float = function (v) {
        var a = parseFloat(v);
        if (isNaN(a))
            return 0;
        return a;
    };
    MathUtils.inAngleRange = function (limitMax, limitMin, angle) {
        limitMax = limitMax + 360;
        limitMin = limitMin + 360;
        var angles = [angle, angle - 360, angle + 360];
        for (var i in angles) {
            var angle = angles[i];
            if (angle > limitMin && angle < limitMax) {
                return true;
            }
        }
        return false;
    };
    return MathUtils;
}());
var Callback = (function () {
    function Callback(callbackFunc, caller, args) {
        if (args === void 0) { args = null; }
        this.delayRunSigns = [];
        this.callbackFunc = callbackFunc;
        this.caller = caller;
        this.args = args;
    }
    Callback.prototype.run = function () {
        var r = this.callbackFunc.apply(this.caller, this.args);
        return r;
    };
    Callback.prototype.runWith = function (addArgs) {
        var r = this.callbackFunc.apply(this.caller, this.args ? this.args.concat(addArgs) : addArgs);
        return r;
    };
    Callback.prototype.delayRun = function (delay, delayFunc, args) {
        if (delayFunc === void 0) { delayFunc = null; }
        if (args === void 0) { args = null; }
        var f = delayFunc ? delayFunc : setTimeout;
        this.delayRunSigns.push(f(function (callBack) {
            callBack.delayRunSigns.shift();
            args ? callBack.runWith(args) : callBack.run();
        }, delay, this));
        return this;
    };
    Callback.prototype.delayRunConver = function (delay, delayFunc, clearDelayFunc, args) {
        if (delayFunc === void 0) { delayFunc = null; }
        if (clearDelayFunc === void 0) { clearDelayFunc = null; }
        if (args === void 0) { args = null; }
        if (this.delayRunSign) {
            var f = clearDelayFunc ? clearDelayFunc : clearTimeout;
            f(this.delayRunSign);
        }
        this.delayRunSign = this.delayRun(delay, delayFunc, args);
        return this;
    };
    Callback.prototype.stopDealy = function (clearDelayFunc) {
        if (clearDelayFunc === void 0) { clearDelayFunc = null; }
        var f = clearDelayFunc ? clearDelayFunc : clearTimeout;
        if (this.delayRunSign) {
            f(this.delayRunSign);
            this.delayRunSign = null;
        }
        for (var i in this.delayRunSigns) {
            f(this.delayRunSigns[i]);
        }
        this.delayRunSigns.length = 0;
    };
    Callback.New = function (callbackFunc, caller, args) {
        if (args === void 0) { args = null; }
        var cb = new Callback(callbackFunc, caller, args);
        return cb;
    };
    Callback.CallLater = function (func, caller, args) {
        if (args === void 0) { args = null; }
        var f = typeof setFrameout != "undefined" ? setFrameout : setTimeout;
        var funccallLayerKey = func["_clk"];
        var callercallLayerKey = caller["_clk"];
        if (funccallLayerKey != null && callercallLayerKey != null) {
            var key = funccallLayerKey + callercallLayerKey * 100000000;
            var cb = Callback.callBacks[key];
            if (cb)
                return;
        }
        funccallLayerKey = func["_clk"] = ObjectUtils.getInstanceID();
        callercallLayerKey = caller["_clk"] = ObjectUtils.getInstanceID();
        var key = funccallLayerKey + callercallLayerKey * 100000000;
        var cb = Callback.New(function (func, caller, args, key) {
            if (args === void 0) { args = null; }
            delete Callback.callBacks[key];
            func.apply(caller, args);
        }, this).delayRun(0, null, [func, caller, args, key]);
        Callback.callBacks[key] = cb;
    };
    Callback.callBacks = [];
    return Callback;
}());
var PoolUtils = (function () {
    function PoolUtils(cls) {
        this.pools = [];
        this.cls = cls;
    }
    PoolUtils.prototype.free = function (obj) {
        this.pools.push(obj);
    };
    PoolUtils.prototype.takeout = function () {
        if (this.pools.length > 0) {
            return this.pools.shift();
        }
        return new this.cls();
    };
    return PoolUtils;
}());
var Scene = (function () {
    function Scene() {
        this.obstacleData = [];
        this.maskData = [];
        this.sceneObjects = [];
        this.gridSceneObjects = [];
        this.lastUpdateObsBridgeGrid = [];
        this.helpPoint = new Point();
    }
    Scene.parse = function (jsonObj, scene, gameData) {
        ObjectUtils.clone(jsonObj, scene);
        scene.sceneObjects = [];
        scene.gridWidth = Math.floor(scene.width / Config.SCENE_GRID_SIZE);
        scene.gridHeight = Math.floor(scene.height / Config.SCENE_GRID_SIZE);
        for (var x = 0; x < scene.gridWidth; x++) {
            scene.gridSceneObjects[x] = [];
            for (var y = 0; y < scene.gridHeight; y++) {
                scene.gridSceneObjects[x][y] = [];
            }
        }
        if (Config.EDIT_MODE) {
            scene.tileMaskData = [];
            scene.tileObstacleData = [];
        }
        var maskData = Config.EDIT_MODE ? scene.tileMaskData : scene.maskData;
        var obsData = Config.EDIT_MODE ? scene.tileObstacleData : scene.obstacleData;
        for (var i = 0; i < scene.LayerDatas.length; i++) {
            var layerData = scene.LayerDatas[i];
            if (layerData.p)
                continue;
            if (layerData.drawMode && layerData.dx == 0 && layerData.dy == 0 && layerData.xMove == 0 && layerData.yMove == 0
                && layerData.scaleX == 1 && layerData.scaleY == 1 && layerData.prospectsPerX == 1 && layerData.prospectsPerY == 1) {
                for (var x = 0; x < scene.gridWidth; x++) {
                    var tileDataW = layerData.tileData[x];
                    if (!tileDataW)
                        continue;
                    for (var y = 0; y < scene.gridHeight; y++) {
                        var layerTileData = tileDataW[y];
                        if (!layerTileData)
                            continue;
                        var tileData = gameData.tileList.data[layerTileData.texID];
                        if (!tileData)
                            continue;
                        var tileGridP = GameUtils.getGridPostion(new Point(layerTileData.x, layerTileData.y));
                        if (tileData.maskData[tileGridP.x] && tileData.maskData[tileGridP.x][tileGridP.y]) {
                            if (!maskData[x])
                                maskData[x] = [];
                            maskData[x][y] = true;
                        }
                        if (tileData.obstacleData[tileGridP.x] && tileData.obstacleData[tileGridP.x][tileGridP.y]) {
                            if (!obsData[x])
                                obsData[x] = [];
                            obsData[x][y] = true;
                        }
                    }
                }
            }
        }
    };
    Scene.getRealWidth = function (scene) {
        return { width: scene.gridWidth * Config.SCENE_GRID_SIZE, height: scene.gridHeight * Config.SCENE_GRID_SIZE };
    };
    Scene.prototype.getSceneObjectByID = function (soIndex) {
        var m = ArrayUtils.matchAttributes(this.sceneObjects, { index: soIndex }, true);
        return m[0];
    };
    Scene.prototype.isObstacle = function (p, except) {
        if (except === void 0) { except = null; }
        var map32 = GameUtils.getGridPostion(p);
        return this.isObstacleGrid(map32, except);
    };
    Scene.prototype.isObstacleGrid = function (gridP, except) {
        if (except === void 0) { except = null; }
        if (this.isOutsideByGrid(gridP)) {
            return true;
        }
        var gridStatus = this.gridDynamicObsStatus(gridP, except);
        if (gridStatus == 1) {
            return false;
        }
        else if (gridStatus == 2) {
            return true;
        }
        return this.isFixedObstacleGrid(gridP);
    };
    Scene.prototype.isFixedObstacleGrid = function (gridP) {
        if (this.obstacleData[gridP.x] && this.obstacleData[gridP.x][gridP.y]) {
            return true;
        }
        if (Config.EDIT_MODE && this.tileObstacleData[gridP.x] && this.tileObstacleData[gridP.x][gridP.y]) {
            return true;
        }
        return false;
    };
    Scene.prototype.isMask = function (p) {
        var map32 = GameUtils.getGridPostion(p);
        return this.isMaskGrid(map32);
    };
    Scene.prototype.isMaskGrid = function (gridP) {
        if (this.maskData[gridP.x] && this.maskData[gridP.x][gridP.y]) {
            return true;
        }
        return false;
    };
    Scene.prototype.isOutside = function (p) {
        if (p.x < 0 || p.x >= this.width || p.y < 0 || p.y >= this.height) {
            return true;
        }
        return false;
    };
    Scene.prototype.isOutsideByGrid = function (gridP) {
        if (gridP.x < 0 || gridP.x >= this.gridWidth || gridP.y < 0 || gridP.y >= this.gridHeight) {
            return true;
        }
        return false;
    };
    Scene.prototype.limitInside = function (p) {
        var wh = Scene.getRealWidth(this);
        wh.width -= 1;
        wh.height -= 1;
        if (p.x < 0) {
            p.x = 0;
        }
        else if (p.x > wh.width) {
            p.x = wh.width;
        }
        if (p.y < 0) {
            p.y = 0;
        }
        else if (p.y > wh.height) {
            p.y = wh.height;
        }
    };
    Scene.prototype.gridDynamicObsStatus = function (gridP, except) {
        if (except === void 0) { except = null; }
        if (!this.gridSceneObjects[gridP.x])
            return 0;
        var sos = this.gridSceneObjects[gridP.x][gridP.y];
        if (!sos)
            return 0;
        var len = sos.length;
        for (var i = 0; i < len; i++) {
            var so = sos[i];
            if (so == except)
                continue;
            if (so == null)
                continue;
            if (so.bridge)
                return 1;
            if (!so.bridge && !so.through && so.avatarID != 0)
                return 2;
        }
        return 0;
    };
    Scene.prototype.updateDynamicObsAndBridge = function (soc, inScene, posGrid) {
        if (posGrid === void 0) { posGrid = null; }
        if (Config.EDIT_MODE)
            return false;
        var nowGrid;
        if (posGrid != null) {
            nowGrid = new Point(posGrid.x, posGrid.y);
        }
        else {
            var nowP = new Point(soc.x, soc.y);
            nowGrid = GameUtils.getGridPostion(nowP, nowP);
        }
        var lastGrid = this.lastUpdateObsBridgeGrid[soc.index];
        if (lastGrid && nowGrid.x == lastGrid.x && nowGrid.y == lastGrid.y && inScene)
            return false;
        if (lastGrid) {
            var sos = this.gridSceneObjects[lastGrid.x][lastGrid.y];
            sos.splice(sos.indexOf(soc), 1);
            delete this.lastUpdateObsBridgeGrid[soc.index];
        }
        if (inScene) {
            var sos = this.gridSceneObjects[nowGrid.x][nowGrid.y];
            sos.push(soc);
            this.lastUpdateObsBridgeGrid[soc.index] = nowGrid;
            return true;
        }
        return false;
    };
    Scene.ignoreAttributes = ["gridSceneObjects", "lastUpdateObsBridgeGrid", "dynamiCalcLayer", "tileObstacleData", "tileMaskData"];
    return Scene;
}());
var Variable = (function () {
    function Variable(listener) {
        if (listener === void 0) { listener = null; }
        this.variables = [];
        this.switchs = [];
        this.strings = [];
        this.listener = listener;
    }
    Variable.prototype.getVariable = function (varID) {
        var v = this.variables[varID];
        return v == null ? 0 : v;
    };
    Variable.prototype.setVariable = function (varID, v) {
        this.variables[varID] = v;
        this.listener && this.listener.onVarChange(0, varID, v);
    };
    Variable.prototype.getSwitch = function (varID) {
        var v = this.switchs[varID];
        return v == null ? 0 : v;
    };
    Variable.prototype.setSwitch = function (varID, v) {
        this.switchs[varID] = v;
        this.listener && this.listener.onVarChange(1, varID, v);
    };
    Variable.prototype.getString = function (varID) {
        var v = this.strings[varID];
        return v == null ? "" : v;
    };
    Variable.prototype.setString = function (varID, v) {
        this.strings[varID] = v;
        this.listener && this.listener.onVarChange(2, varID, v);
    };
    Variable.splitDynamicText = function (str) {
        var reg = /\[\$(v|s|w)\d+\]|\[\@(v|s|w|p)\d+\]/g;
        var m = str.match(reg);
        if (!m)
            return [[0, str]];
        var startIndex = 0;
        var arr = [];
        for (var i = 0; i < m.length; i++) {
            var keyWord = m[i];
            var keyWordIndex = str.indexOf(keyWord, startIndex);
            if (startIndex != keyWordIndex) {
                arr.push([0, str.substr(startIndex, keyWordIndex - startIndex)]);
            }
            startIndex = keyWordIndex + keyWord.length;
            var firstKey = keyWord[1];
            var second = keyWord[2];
            var num = keyWord.substr(3, keyWord.length - 4);
            if (firstKey == "$") {
                if (second == "v") {
                    arr.push([1, num]);
                }
                else if (second == "w") {
                    arr.push([2, num]);
                }
                else {
                    arr.push([3, num]);
                }
            }
            else if (firstKey == "@") {
                if (second == "v") {
                    arr.push([4, num]);
                }
                else if (second == "w") {
                    arr.push([5, num]);
                }
                else if (second == "p") {
                    arr.push([7, num]);
                }
                else {
                    arr.push([6, num]);
                }
            }
        }
        if (startIndex != str.length) {
            arr.push([0, str.substr(startIndex)]);
        }
        return arr;
    };
    Variable.margeDynamicText = function (texts, player, trigger) {
        if (player === void 0) { player = null; }
        if (trigger === void 0) { trigger = null; }
        var len = texts.length;
        var str = "";
        for (var i = 0; i < len; i++) {
            var text = texts[i];
            var type = text[0];
            if (type >= 4 && !player)
                continue;
            if (type == 0) {
                str += text[1];
            }
            else if (type == 1) {
                str += ServerWorld.getWorldVariable(text[1]);
            }
            else if (type == 2) {
                str += ServerWorld.getWorldSwitch(text[1]);
            }
            else if (type == 3) {
                str += ServerWorld.getWorldString(text[1]);
            }
            else if (type == 4) {
                str += player.variable.getVariable(text[1]);
            }
            else if (type == 5) {
                str += player.variable.getSwitch(text[1]);
            }
            else if (type == 6) {
                str += player.variable.getString(text[1]);
            }
            else if (type == 7) {
                str += trigger.inputMessage[text[1]];
            }
        }
        return str;
    };
    Variable.prototype.getTransportableData = function () {
        var o = new Variable();
        o.variables = this.variables;
        o.switchs = this.switchs;
        o.strings = this.strings;
        return o;
    };
    return Variable;
}());
var OriginalData = (function () {
    function OriginalData() {
    }
    return OriginalData;
}());





var SceneLayerData = (function (_super) {
    __extends(SceneLayerData, _super);
    function SceneLayerData() {
        _super.apply(this, arguments);
        this.dx = 0;
        this.dy = 0;
        this.scaleX = 1;
        this.scaleY = 1;
        this.xMove = 0;
        this.yMove = 0;
        this.prospectsPerX = 1;
        this.prospectsPerY = 1;
        this.xLoop = false;
        this.yLoop = false;
        this.opacity = 1;
        this.blendMode = null;
        this.drawMode = false;
        this.tileData = [];
        this.img = null;
    }
    SceneLayerData.getTileData = function (layer, wGrid, hGrid) {
        var tileData = [];
        var tileTexIDs = {};
        for (var x = 0; x < wGrid; x++) {
            if (!layer.tileData[x])
                continue;
            if (!tileData[x])
                tileData[x] = [];
            for (var y = 0; y < hGrid; y++) {
                var oneTileData = layer.tileData[x][y];
                if (oneTileData) {
                    tileData[x][y] = {
                        texID: oneTileData.texID,
                        x: oneTileData.x,
                        y: oneTileData.y
                    };
                    if (oneTileData.texID && !tileTexIDs[oneTileData.texID]) {
                        tileTexIDs[oneTileData.texID] = true;
                    }
                }
            }
        }
        return [tileData, tileTexIDs];
    };
    SceneLayerData.clone = function () {
    };
    return SceneLayerData;
}(OriginalData));





var SceneObjectModelData = (function (_super) {
    __extends(SceneObjectModelData, _super);
    function SceneObjectModelData() {
        _super.apply(this, arguments);
        this.preLayer = [];
        this.varAttributes = [];
        this.serverInstanceClassName = SceneObjectModelData.SERVER_SCENE_OBJECT_CORE_CLASS;
        this.clientInstanceClassName = SceneObjectModelData.CLIENT_SCENE_OBJECT_CORE_CLASS;
    }
    SceneObjectModelData.getServerCode = function (modelData) {
        var serverVars = CustomAttributeSetting.getAPIRuntimes(modelData.varAttributes);
        var modelName = GameListData.getName(Common.sceneObjectModelList, modelData.id);
        var serverSoBaseCode = "/**\n * \u573A\u666F\u5BF9\u8C61\u6A21\u578B\uFF1A" + modelName + "\n */\nclass ServerSceneObject_" + modelData.id + " extends " + this.SERVER_SCENE_OBJECT_CORE_CLASS + " {\n" + serverVars + "    constructor(soData: SceneObject,presetCustomAttrs: { [varName: string]: { varType: number, value: any } } = null,player: ServerPlayer) {\n        super(soData,presetCustomAttrs,player);\n    }\n}";
        return { serverSoBaseCode: serverSoBaseCode };
    };
    SceneObjectModelData.getServerJsBaseCode = function (modelData) {
        return "var ServerSceneObject_" + modelData.id + " = (function (_super) {__extends(ServerSceneObject_" + modelData.id + ", _super);function ServerSceneObject_" + modelData.id + "(soData,presetCustomAttrs,player) {_super.apply(this, [soData,presetCustomAttrs,player]);}return ServerSceneObject_" + modelData.id + ";}(" + this.SERVER_SCENE_OBJECT_CORE_CLASS + "));";
    };
    SceneObjectModelData.getAllAPICodeInEditor = function (mode) {
        var list = Game.data.sceneObjectModelList;
        var codes = "";
        for (var i in list.data) {
            var model = list.data[i];
            if (!model)
                continue;
            if (EUIWindowSceneObjectModel.modelData && model.id == EUIWindowSceneObjectModel.modelData.id) {
                model = EUIWindowSceneObjectModel.modelData;
            }
            if (mode == 1) {
                var serverCode = this.getServerCode(model);
                codes += serverCode.serverSoBaseCode + "\n";
            }
            else if (mode == 2) {
                var clientCode = this.getClientCode(model);
                codes += clientCode.clientSoBaseCode + "\n";
            }
        }
        return codes;
    };
    SceneObjectModelData.getClientCode = function (modelData) {
        var clientVars = CustomAttributeSetting.getAPIRuntimes(modelData.varAttributes, true);
        var clientDisplayVars = "";
        for (var i in modelData.preLayer) {
            var preLayer = modelData.preLayer[i];
            if (preLayer.inEditorShowMode == 2)
                continue;
            var varTypeStr = null;
            if (preLayer.type <= 1) {
                continue;
            }
            else if (preLayer.type == 2) {
                var uiData = Common.uiList.data[preLayer.id];
                if (!uiData)
                    continue;
                if (uiData.uiDisplayData.instanceClassName) {
                    varTypeStr = uiData.uiDisplayData.instanceClassName + ";\n";
                }
                else {
                    varTypeStr = "GUI_" + preLayer.id + ";\n";
                }
            }
            else if (preLayer.type == 3) {
                varTypeStr = "UIRoot;\n";
            }
            else if (preLayer.type <= 5) {
                varTypeStr = "Animation;\n";
            }
            clientDisplayVars += "    " + preLayer.varName + ": " + varTypeStr;
        }
        var modelName = GameListData.getName(Common.sceneObjectModelList, modelData.id);
        var clientSoBaseCode = "/**\n * \u573A\u666F\u5BF9\u8C61\u6A21\u578B\uFF1A" + modelName + "\n */\nclass ClientSceneObject_" + modelData.id + " extends " + this.CLIENT_SCENE_OBJECT_CORE_CLASS + " {\n" + clientVars + clientDisplayVars + "    constructor(soData: SceneObject, scene: ClientScene) {\n        super(soData,scene);\n    }\n}";
        return { clientSoBaseCode: clientSoBaseCode };
    };
    SceneObjectModelData.getClientJsBaseCode = function (modelData) {
        return "var ClientSceneObject_" + modelData.id + " = (function (_super) {__extends(ClientSceneObject_" + modelData.id + ", _super);function ClientSceneObject_" + modelData.id + "(soData,scene) {_super.apply(this, [soData,scene]);}return ClientSceneObject_" + modelData.id + ";}(" + this.CLIENT_SCENE_OBJECT_CORE_CLASS + "));";
    };
    SceneObjectModelData.SERVER_SCENE_OBJECT_CORE_CLASS = "GameServerSceneObject_Core";
    SceneObjectModelData.CLIENT_SCENE_OBJECT_CORE_CLASS = "GameClientSceneObject_Core";
    SceneObjectModelData.TYPE_AVATAR_TYPE = 1;
    SceneObjectModelData.TYPE_UI_DESIGNATION = 2;
    SceneObjectModelData.TYPE_UI_TYPE = 3;
    SceneObjectModelData.TYPE_ANIMATION_DESIGNATION = 4;
    SceneObjectModelData.TYPE_ANIMATION_TYPE = 5;
    SceneObjectModelData.sceneObjectClass = {};
    return SceneObjectModelData;
}(OriginalData));





var TileData = (function (_super) {
    __extends(TileData, _super);
    function TileData() {
        _super.call(this);
        this.url = "";
        this.obstacleData = [];
        this.maskData = [];
        this.width = 0;
        this.height = 0;
    }
    return TileData;
}(OriginalData));





var UIData = (function (_super) {
    __extends(UIData, _super);
    function UIData() {
        _super.apply(this, arguments);
        this.uiDisplayData = new UIDisplayData();
        this.uiCommandData = new OriginalData();
    }
    UIData.init = function (item) {
        item.uiDisplayData.id = item.id;
    };
    return UIData;
}(OriginalData));
var GameListData = (function () {
    function GameListData(folder, listName, listData, listType, arrayModeIndex) {
        if (arrayModeIndex === void 0) { arrayModeIndex = null; }
        this.listData = {};
        this.data = [];
        this.folder = folder;
        this.listName = listName;
        this.listData = listData;
        this.listType = listType;
        this.arrayModeIndex = arrayModeIndex;
    }
    GameListData.getID = function (typeID, index) {
        return (typeID - 1) * 1000 + index;
    };
    GameListData.getType = function (id) {
        if (id == 0)
            return 1;
        return Math.floor((id - 1) / 1000) + 1;
    };
    GameListData.getLocalID = function (id) {
        return (id - 1) % 1000 + 1;
    };
    GameListData.getItem = function (gameListData, typeID, localID) {
        var id = GameListData.getID(typeID, localID);
        return gameListData.data[id];
    };
    GameListData.getItems = function (gameListData) {
        var arr = [];
        for (var i in gameListData.data) {
            var d = gameListData.data[i];
            if (d)
                arr.push(d);
        }
        return arr;
    };
    GameListData.getIDRange = function (typeID) {
        return { from: (typeID - 1) * 1000 + 1, to: (typeID - 1) * 1000 + 1000 };
    };
    GameListData.getName = function (gameListData, id) {
        if (!gameListData.listData)
            return null;
        var name;
        if (gameListData.hasType) {
            var typeID = GameListData.getType(id);
            var typeArr = gameListData.listData.list[typeID];
            if (!typeArr)
                return "";
            name = typeArr[GameListData.getLocalID(id)];
        }
        else {
            name = gameListData.listData.list[id];
        }
        return name != null ? name : "--/--";
    };
    GameListData.setName = function (gameListData, id, name) {
        if (!gameListData.listData)
            return null;
        if (gameListData.hasType) {
            var typeID = Math.floor((id - 1) / 1000) + 1;
            gameListData.listData.list[typeID][GameListData.getLocalID(id)] = name;
        }
        else {
            gameListData.listData.list[id] = name;
        }
    };
    GameListData.changeMaximum = function (cls, gameListData, typeID, currentListMaximum, setMaximum) {
        if (currentListMaximum < setMaximum) {
            if (gameListData.hasType) {
                if (!gameListData.listData.list[typeID])
                    gameListData.listData.list[typeID] = [];
            }
            var startID = GameListData.getID(typeID, currentListMaximum) + 1;
            var len = setMaximum - currentListMaximum;
            for (var i = 0; i < len; i++) {
                var itemData = new cls();
                var id = itemData.id = startID + i;
                gameListData.data[id] = itemData;
                if (gameListData.hasType) {
                    gameListData.listData.list[typeID][currentListMaximum + 1 + i] = "";
                }
                else {
                    gameListData.listData.list[currentListMaximum + 1 + i] = "";
                }
            }
        }
        else if (currentListMaximum > setMaximum) {
            var range = GameListData.getIDRange(typeID);
            var startID = range.from + setMaximum;
            for (var i = startID; i < range.to; i++) {
                gameListData.data[i] = null;
                if (gameListData.hasType) {
                    if (gameListData.listData.list[typeID]) {
                        gameListData.listData.list[typeID].length = setMaximum + 1;
                    }
                }
                else {
                    gameListData.listData.list.length = setMaximum + 1;
                }
            }
        }
    };
    GameListData.getLength = function (gameListData, typeID) {
        if (typeID === void 0) { typeID = null; }
        if (gameListData.hasType) {
            var list = gameListData.listData.list[typeID];
            return list ? list.length - 1 : 0;
        }
        else {
            return gameListData.listData.list.length - 1;
        }
    };
    GameListData.changeTypName = function (gameListData, typeID, name) {
        gameListData.listData.type[typeID] = name;
    };
    GameListData.getTypName = function (gameListData, typeID) {
        return gameListData.listData.type ? gameListData.listData.type[typeID] : null;
    };
    GameListData.setNewData = function (cls, gameListData, id, name) {
        if (id === void 0) { id = 0; }
        if (name === void 0) { name = ""; }
        var itemData = new cls();
        if (id == 0) {
            if (gameListData.hasType)
                return;
            var list = gameListData.listData.list;
            id = list.length;
        }
        itemData.id = id;
        this.setData(gameListData, id, itemData, name);
        return itemData;
    };
    GameListData.setData = function (gameListData, id, itemData, name) {
        if (id === void 0) { id = 0; }
        if (id == 0) {
            var list = gameListData.hasType ? gameListData.listData.list[typeID] : gameListData.listData.list;
            id = list.length;
        }
        if (gameListData.hasType) {
            var typeID = GameListData.getType(id);
            gameListData.listData.list[typeID][GameListData.getLocalID(id)] = name;
        }
        else {
            gameListData.listData.list[id] = name;
        }
        gameListData.data[id] = itemData;
    };
    GameListData.disposeData = function (gameListData, id) {
        if (gameListData.hasType) {
            var typeID = GameListData.getType(id);
            gameListData.listData.list[typeID][GameListData.getLocalID(id)] = null;
        }
        else {
            gameListData.listData.list[id] = null;
        }
        gameListData.data[id] = null;
    };
    GameListData.remove = function (gameListData, id, autoOrder) {
        if (autoOrder === void 0) { autoOrder = false; }
        var list;
        var index;
        if (gameListData.hasType) {
            var typeID = GameListData.getType(id);
            list = gameListData.listData.list[typeID];
            index = GameListData.getLocalID(id);
        }
        else {
            list = gameListData.listData.list;
            index = id;
        }
        list[index] = null;
        if (!autoOrder)
            return;
        list.splice(index, 1);
        gameListData.data.splice(index, 1);
        for (var i = id; i < gameListData.data.length; i++) {
            var data = gameListData.data[i];
            if (data)
                data.id = i;
        }
    };
    return GameListData;
}());
var GameData = (function () {
    function GameData() {
        this.customModuleDataList = [];
    }
    GameData.prototype.loadVariableList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_VARIABLE, OriginalData, [], "asset/json/variable/", "variable.json", onFin);
    };
    GameData.prototype.loadSwitchList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_SWITCH, OriginalData, [], "asset/json/variable/", "switch.json", onFin);
    };
    GameData.prototype.loadStringList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_STRING, OriginalData, [], "asset/json/variable/", "string.json", onFin);
    };
    GameData.prototype.loadPlayerVariableList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_PLAYER_VARIABLE, OriginalData, [], "asset/json/server/variable/", "variable.json", onFin);
    };
    GameData.prototype.loadPlayerSwitchList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_PLAYER_SWITCH, OriginalData, [], "asset/json/server/variable/", "switch.json", onFin);
    };
    GameData.prototype.loadPlayerStringList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_PLAYER_STRING, OriginalData, [], "asset/json/server/variable/", "string.json", onFin);
    };
    GameData.prototype.loadSceneList = function (onFin, itemNeedMethod) {
        if (itemNeedMethod === void 0) { itemNeedMethod = null; }
        this.onLoadList(GameData.LIST_TYPE_SCENE, SceneData, [
            { childAttribute: "mapData", path: "asset/json/scene/data/scene" },
            { childAttribute: "sceneObjectData", path: "asset/json/server/scene/s" }
        ], "asset/json/scene/", "sceneList.json", onFin, false, itemNeedMethod);
    };
    GameData.prototype.loadSceneObjectModelList = function (onFin, isServer) {
        if (isServer === void 0) { isServer = false; }
        this.onLoadList(GameData.LIST_TYPE_SCENE_OBJECT_MODEL, SceneObjectModelData, [
            { childAttribute: null, path: "asset/json/scene/model/som" }
        ], "asset/json/scene/", "sceneObjectModelList.json", onFin, false);
    };
    GameData.prototype.loadTileList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_TILE, TileData, [
            { childAttribute: null, path: "asset/json/scene/tile/tile" }
        ], "asset/json/scene/", "tileList.json", onFin, false);
    };
    GameData.prototype.loadAvatarList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_AVATAR, AvatarData, [
            { childAttribute: null, path: "asset/json/avatar/data/avatar" }
        ], "asset/json/avatar/", "avatarList.json", onFin, true, null, true);
    };
    GameData.prototype.loadAvatarActList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_AVATAR_ACT, OriginalData, [], "asset/json/avatar/", "avatarActList.json", onFin, false);
    };
    GameData.prototype.loadAvatarRefObjList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_AVATAR_REF_OBJ, AvatarRefObjData, [], "asset/json/avatar/", "avatarRefObjList.json", onFin, false);
    };
    GameData.prototype.loadCommonEventList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_COMMON_EVENT, CommonEventData, [
            { childAttribute: null, path: "asset/json/server/command/data/ws" }
        ], "asset/json/server/command/", "worldCommand.json", onFin);
    };
    GameData.prototype.loadDialogList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_DIALOG, DialogData, [
            { childAttribute: null, path: "asset/json/dialog/data/dialog" }
        ], "asset/json/dialog/", "dialogList.json", onFin, false);
    };
    GameData.prototype.loadAnimationList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_ANIMATION, AnimationData, [
            { childAttribute: null, path: "asset/json/animation/data/ani" }
        ], "asset/json/animation/", "animationList.json", onFin);
    };
    GameData.prototype.loadAnimationSignalList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_ANIMATION_SIGNAL, OriginalData, [], "asset/json/animation/", "animationSignalList.json", onFin, false);
    };
    GameData.prototype.loadUIList = function (onFin) {
        var childData = [{ childAttribute: "uiCommandData", path: "asset/json/server/ui/sui" }];
        childData.unshift({ childAttribute: "uiDisplayData", path: "asset/json/ui/data/ui" });
        this.onLoadList(GameData.LIST_TYPE_UI, UIData, childData, "asset/json/ui/", "uiList.json", onFin);
    };
    GameData.prototype.loadDataStructureList = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_DATA_STRUCTURE, CustomCompositeSetting, [], "asset/json/custom/", "dataStructure.json", onFin, true);
    };
    GameData.prototype.loadCustomModuleList = function (onFin) {
        var _this = this;
        this.onLoadList(GameData.LIST_TYPE_CUSTOM_MODULE, CustomCompositeSetting, [], "asset/json/custom/", "customModuleList.json", Callback.New(function () {
            var customSettingList = _this.customModuleList;
            var len = GameListData.getLength(customSettingList);
            var loadCount = len;
            if (loadCount == 0)
                onFin.run();
            for (var i = 1; i <= len; i++) {
                if (!customSettingList.data[i])
                    continue;
                _this.onLoadList(GameData.LIST_TYPE_CUSTOM_MODULE_DATA, CustomData, [
                    { childAttribute: null, path: "asset/json/custom/customModule/" + i + "/cm" }
                ], "asset/json/custom/customModule/", "customModuleDataList" + i + ".json", Callback.New(function () {
                    loadCount--;
                    if (loadCount == 0) {
                        onFin.run();
                    }
                }, _this), true, null, false, i);
            }
        }, this), false);
    };
    GameData.newCustomModuleDataList = function (index) {
        var gameListData = new GameListData("asset/json/custom/customModule/", "customModuleDataList" + index + ".json", { list: {}, type: {} }, GameData.LIST_TYPE_CUSTOM_MODULE_DATA, index);
        return gameListData;
    };
    GameData.prototype.loadGameAttributeConfig = function (onFin) {
        var _this = this;
        FileUtils.loadJsonFile("asset/json/custom/customGameAttribute.json", Callback.New(function (jsonObj) {
            _this.customGameAttribute = new CustomGameAttribute();
            ObjectUtils.clone(jsonObj, _this.customGameAttribute);
            onFin.run();
        }, this));
    };
    GameData.prototype.loadScript = function (mode, onFin, needSrc) {
        var _this = this;
        var urls = ["asset/json/server/script/script.json", "asset/json/script/script.json", "asset/json/script/scriptCommon.json"];
        var url = urls[mode];
        FileUtils.loadJsonFile(url, Callback.New(function (jsonObj) {
            if (mode == 0) {
                _this.serverScript = jsonObj;
            }
            else if (mode == 1) {
                _this.clientScript = jsonObj;
            }
            else {
                _this.commonScript = jsonObj;
            }
            if (!needSrc) {
                jsonObj.src = null;
            }
            onFin.run();
        }, this));
    };
    GameData.prototype.loadCustomEventType = function (onFin) {
        var _this = this;
        this.onLoadList(GameData.LIST_TYPE_CUSTOM_OBJECT_EVENT_TYPE, CustomEventType, [], "asset/json/custom/", "customObjectEventType.json", Callback.New(function () {
            _this.onLoadList(GameData.LIST_TYPE_CUSTOM_UI_EVENT_TYPE, CustomEventType, [], "asset/json/custom/", "customUIEventType.json", Callback.New(function () {
                this.onLoadList(GameData.LIST_TYPE_CUSTOM_SCENE_EVENT_TYPE, CustomEventType, [], "asset/json/custom/", "customSceneEventType.json", onFin, false);
            }, _this), false);
        }, this), false);
    };
    GameData.prototype.loadCustomCommandType = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_CUSTOM_COMMAND_TYPE, CustomCompositeSetting, [], "asset/json/custom/", "customCommandType.json", onFin, true);
    };
    GameData.prototype.loadCustomBehaviorType = function (onFin) {
        this.onLoadList(GameData.LIST_TYPE_CUSTOM_BEHAVIOR_TYPE, CustomCompositeSetting, [], "asset/json/custom/", "customBehaviorType.json", onFin, false);
    };
    GameData.prototype.loadScene = function (id, onFin) {
        this.onLoadOne(id, "sceneList", SceneData, [
            { childAttribute: "mapData", path: "asset/json/scene/data/scene" },
            { childAttribute: "sceneObjectData", path: "asset/json/server/scene/s" }
        ], "asset/json/scene/", "sceneList.json", false);
        this.onLoadOneOver(id, onFin, "sceneList");
    };
    GameData.prototype.loadTile = function (id, onFin) {
        this.onLoadOne(id, "tileList", TileData, [
            { childAttribute: null, path: "asset/json/scene/tile/tile" }
        ], "asset/json/scene/", "tileList.json");
        this.onLoadOneOver(id, onFin, "tileList");
    };
    GameData.prototype.loadAvatar = function (id, onFin) {
        this.onLoadOne(id, "avatarList", AvatarData, [
            { childAttribute: null, path: "asset/json/avatar/data/avatar" }
        ], "asset/json/avatar/", "avatarList.json");
        this.onLoadOneOver(id, onFin, "avatarList");
    };
    GameData.prototype.onLoadList = function (saveAttribute, childCls, childItems, folder, listName, onFin, hasType, itemNeedMethod, loadZero, arrayModeIndex) {
        var _this = this;
        if (hasType === void 0) { hasType = true; }
        if (itemNeedMethod === void 0) { itemNeedMethod = null; }
        if (loadZero === void 0) { loadZero = false; }
        if (arrayModeIndex === void 0) { arrayModeIndex = null; }
        FileUtils.loadJsonFile(folder + listName, new Callback(function (listData) {
            var gameListData = new GameListData(folder, listName, listData, saveAttribute, arrayModeIndex);
            if (arrayModeIndex == null) {
                _this[saveAttribute] = gameListData;
            }
            else {
                _this[saveAttribute][arrayModeIndex] = gameListData;
            }
            gameListData.hasType = hasType;
            var typeList = hasType ? listData.list : { 1: listData.list };
            for (var typeID in typeList) {
                var typeDatas = typeList[typeID];
                for (var i = 0; i < typeDatas.length; i++) {
                    var dataName = typeDatas[i];
                    if (loadZero && i == 0 && typeID == "1") { }
                    else if (dataName == null) {
                        continue;
                    }
                    var id = GameListData.getID(parseInt(typeID), i);
                    if (itemNeedMethod && !itemNeedMethod(id))
                        continue;
                    _this.onLoadOne(id, saveAttribute, childCls, childItems, folder, listName, hasType, listData, arrayModeIndex);
                }
            }
            new SyncTask(GameData.loadDataTask, function () {
                onFin.run();
                SyncTask.taskOver(GameData.loadDataTask);
            });
        }, this));
    };
    GameData.prototype.onLoadOne = function (id, saveAttribute, childCls, childItems, folder, listName, hasType, listData, arrayModeIndex) {
        if (hasType === void 0) { hasType = true; }
        if (listData === void 0) { listData = null; }
        if (arrayModeIndex === void 0) { arrayModeIndex = null; }
        var gameListData = this[saveAttribute];
        if (arrayModeIndex == null) {
            gameListData = this[saveAttribute];
        }
        else {
            gameListData = this[saveAttribute][arrayModeIndex];
        }
        if (gameListData == null) {
            if (hasType) {
                gameListData = new GameListData(folder, listName, { list: {}, type: {} }, saveAttribute, arrayModeIndex);
            }
            else {
                gameListData = new GameListData(folder, listName, { list: {} }, saveAttribute, arrayModeIndex);
            }
            gameListData.hasType = hasType;
            if (arrayModeIndex == null) {
                this[saveAttribute] = gameListData;
            }
            else {
                this[saveAttribute][arrayModeIndex] = gameListData;
            }
        }
        var gameData = gameListData.data[id] = new childCls();
        gameData.id = id;
        if (listData.data) {
            var attrData = listData.data[id];
            ObjectUtils.clone(attrData, gameData);
        }
        for (var c = 0; c < childItems.length; c++) {
            var childItem = childItems[c];
            new SyncTask(GameData.loadDataTask);
            FileUtils.loadJsonFile(childItem.path + id + ".json", new Callback(function (gameData, id, childAttribute, itemData) {
                if (!itemData) {
                    delete gameListData.data[id];
                    if (gameListData.hasType) {
                        gameListData.listData.list[GameListData.getType(id)][GameListData.getLocalID(id)] = null;
                    }
                    else {
                        gameListData.listData.list[id] = null;
                    }
                }
                else {
                    ObjectUtils.clone(itemData, childAttribute ? gameData[childAttribute] : gameData);
                    childAttribute ? gameData[childAttribute].id = id : gameData.id = id;
                }
                SyncTask.taskOver(GameData.loadDataTask);
            }, this, [gameData, id, childItem.childAttribute]));
        }
    };
    GameData.prototype.onLoadOneOver = function (id, onFin, saveAttribute) {
        new SyncTask(GameData.loadDataTask, function () {
            onFin.runWith([this[saveAttribute].data[id]]);
            SyncTask.taskOver(GameData.loadDataTask);
        }, [], this);
    };
    GameData.LIST_TYPE_VARIABLE = "variableNameList";
    GameData.LIST_TYPE_SWITCH = "switchNameList";
    GameData.LIST_TYPE_STRING = "stringNameList";
    GameData.LIST_TYPE_PLAYER_VARIABLE = "playerVariableNameList";
    GameData.LIST_TYPE_PLAYER_SWITCH = "playerSwitchNameList";
    GameData.LIST_TYPE_PLAYER_STRING = "playerStringNameList";
    GameData.LIST_TYPE_SCENE = "sceneList";
    GameData.LIST_TYPE_SCENE_OBJECT_MODEL = "sceneObjectModelList";
    GameData.LIST_TYPE_TILE = "tileList";
    GameData.LIST_TYPE_AVATAR = "avatarList";
    GameData.LIST_TYPE_AVATAR_ACT = "avatarActList";
    GameData.LIST_TYPE_AVATAR_REF_OBJ = "avatarRefObjList";
    GameData.LIST_TYPE_COMMON_EVENT = "commonEventList";
    GameData.LIST_TYPE_DIALOG = "dialogList";
    GameData.LIST_TYPE_ANIMATION = "animationList";
    GameData.LIST_TYPE_ANIMATION_SIGNAL = "animationSignalList";
    GameData.LIST_TYPE_UI = "uiList";
    GameData.LIST_TYPE_DATA_STRUCTURE = "dataStructureList";
    GameData.LIST_TYPE_CUSTOM_MODULE = "customModuleList";
    GameData.LIST_TYPE_CUSTOM_MODULE_DATA = "customModuleDataList";
    GameData.LIST_TYPE_CUSTOM_OBJECT_EVENT_TYPE = "customObjectEventTypeList";
    GameData.LIST_TYPE_CUSTOM_UI_EVENT_TYPE = "customUIEventTypeList";
    GameData.LIST_TYPE_CUSTOM_SCENE_EVENT_TYPE = "customSceneEventTypeList";
    GameData.LIST_TYPE_CUSTOM_COMMAND_TYPE = "customCommandTypeList";
    GameData.LIST_TYPE_CUSTOM_BEHAVIOR_TYPE = "customBehaviorTypeList";
    GameData.CUSTOM_ATTR_WORLD_DATA = 0;
    GameData.CUSTOM_ATTR_PLAYER_DATA = 1;
    GameData.CUSTOM_ATTR_SCENE_DATA = 2;
    GameData.CUSTOM_ATTR_SCENE_OBJECT_DATA = 3;
    GameData.loadDataTask = "GameData_loadDataTask";
    GameData.customModulePresetDatas = [];
    return GameData;
}());
var FileUtils = (function () {
    function FileUtils() {
    }
    FileUtils.init = function () {
        if (typeof window != "undefined") {
            FileUtils.loader = window["loader"];
            FileUtils.Handler = window["Handler"];
        }
        else {
            FileUtils.readFile = eval("readFile");
            FileUtils.nativePath = eval("nativePath");
        }
    };
    FileUtils.loadJsonFile = function (localURL, onFin) {
        var tail = (typeof window != "undefined") ? "?r=" + Math.random() : "";
        FileUtils.loadFile(localURL + tail, new Callback(function (text) {
            if (!text) {
                onFin.runWith([null]);
                return;
            }
            try {
                text = text.replace(/(\n|^)[ \t]*\/\/.*/g, "");
                var jsonObj = JSON.parse(text);
                if (typeof window != "undefined") {
                    loader.cacheRes(localURL, jsonObj);
                }
            }
            catch (e) {
                trace(localURL + " parse error.");
                jsonObj = null;
            }
            onFin.runWith([jsonObj]);
        }, this), true);
    };
    FileUtils.loadFile = function (localURL, onFin, isJson) {
        if (isJson === void 0) { isJson = false; }
        function onloaded(onFin, txt, localURL) {
            if (!txt) {
                trace(localURL + " not exist2.");
            }
            onFin.runWith([txt]);
        }
        if (typeof window != "undefined") {
            loader.load(localURL, this.Handler.create(this, function (onFin, localURL, txt) {
                onloaded(onFin, txt, localURL);
            }, [onFin, localURL]), null, Loader.TEXT, 0, isJson ? false : true);
        }
        else {
            var txt = this.readFile(this.nativePath + localURL);
            if (txt == "[no exist]")
                txt = null;
            onloaded(onFin, txt, localURL);
        }
    };
    FileUtils.save = function (dataObject, localURL, onFin, format) {
        if (format === void 0) { format = true; }
        var dataString = format ? JSON.stringify(dataObject, null, 4) : JSON.stringify(dataObject);
        new FileObject(localURL, function (fo) {
            fo[fo.exists ? "saveFile" : "createFile"](dataString, function () {
                onFin && onFin.runWith([true, fo.path]);
            }, function () {
                onFin && onFin.runWith([false, fo.path]);
            }, this);
        }, this, function () {
            onFin && onFin.runWith([false, localURL]);
        });
    };
    return FileUtils;
}());
var Common = (function () {
    function Common() {
    }
    Object.defineProperty(Common, "newestDBData", {
        get: function () {
            if (Config.EDIT_MODE) {
                return Editor.data.dbData ? Editor.data.dbData : Game.data;
            }
            else if (Config.IS_SERVER) {
                return ServerWorld.gameData;
            }
            else {
                return Game.data;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "gameData", {
        get: function () {
            if (Config.IS_SERVER) {
                return ServerWorld.gameData;
            }
            else {
                return Game.data;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "variableNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_VARIABLE);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "switchNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_SWITCH);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "stringNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_STRING);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "playerVariableNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_PLAYER_VARIABLE);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "playerSwitchNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_PLAYER_SWITCH);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "playerStringNameList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_PLAYER_STRING);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "sceneList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_SCENE);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "sceneObjectModelList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_SCENE_OBJECT_MODEL);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "tileList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_TILE);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "avatarActList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_AVATAR_ACT);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "avatarRefObjList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_AVATAR_REF_OBJ);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "animationSignalList", {
        get: function () {
            return this.getGameDataAttrValue(GameData.LIST_TYPE_ANIMATION_SIGNAL);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "dataStructureList", {
        get: function () {
            if (Config.EDIT_MODE) {
                return EUIWindowDataStructureConfig.dataStructureClone ? EUIWindowDataStructureConfig.dataStructureClone : Game.data.dataStructureList;
            }
            else if (Config.IS_SERVER) {
                return ServerWorld.gameData.dataStructureList;
            }
            else {
                return Game.data.dataStructureList;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "customModuleList", {
        get: function () {
            if (Config.EDIT_MODE) {
                return EUIWindowDataStructureConfig.customModuleClone ? EUIWindowDataStructureConfig.customModuleClone : Game.data.customModuleList;
            }
            else if (Config.IS_SERVER) {
                return ServerWorld.gameData.customModuleList;
            }
            else {
                return Game.data.customModuleList;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "customModuleDataList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_CUSTOM_MODULE_DATA);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "customSceneModelList", {
        get: function () {
            return null;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "customGameAttribute", {
        get: function () {
            if (Config.EDIT_MODE) {
                return Editor.data.dbData ? Editor.data.dbData.customGameAttribute : Game.data.customGameAttribute;
            }
            else if (Config.IS_SERVER) {
                return ServerWorld.gameData.customGameAttribute;
            }
            else {
                return Game.data.customGameAttribute;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "avatarList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_AVATAR);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "commonEventList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_COMMON_EVENT);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "dialogList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_DIALOG);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "animationList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_ANIMATION);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(Common, "uiList", {
        get: function () {
            return this.getNewestDBData(GameData.LIST_TYPE_UI);
        },
        enumerable: true,
        configurable: true
    });
    Common.getGameDataAttrValue = function (attr) {
        if (Config.IS_SERVER) {
            return ServerWorld.gameData[attr];
        }
        else {
            return Game.data[attr];
        }
    };
    Common.getNewestDBData = function (attr) {
        if (Config.EDIT_MODE) {
            return Editor.data && Editor.data.dbData ? Editor.data.dbData[attr] : Game.data[attr];
        }
        else if (Config.IS_SERVER) {
            return ServerWorld.gameData[attr];
        }
        else {
            return Game.data[attr];
        }
    };
    return Common;
}());
var Const = (function () {
    function Const() {
    }
    Const.COMMAND_TRIGGER_TYPE_CONTINUE = 0;
    Const.COMMAND_TRIGGER_TYPE_SCENE_OBJECT_CLICK = 1;
    Const.COMMAND_TRIGGER_TYPE_SCENE_OBJECT_COLLIED = 2;
    Const.COMMAND_TRIGGER_TYPE_SCENE_OBJECT_UPDATE = 3;
    Const.COMMAND_TRIGGER_TYPE_IN_SCENE = 4;
    Const.COMMAND_TRIGGER_TYPE_UI_CLICK = 5;
    Const.COMMAND_TRIGGER_TYPE_CALL_COMMON_COMMAND = 6;
    return Const;
}());
var Player = (function () {
    function Player(dataCls) {
        if (dataCls === void 0) { dataCls = null; }
        if (dataCls)
            this.data = new dataCls();
        else {
            this.data = {};
        }
        ;
        if (Config.IS_SERVER) {
            this.variable = new Variable(this);
        }
    }
    return Player;
}());
var Condition = (function () {
    function Condition() {
    }
    return Condition;
}());





var AnimationData = (function (_super) {
    __extends(AnimationData, _super);
    function AnimationData() {
        _super.apply(this, arguments);
        this.loop = false;
        this.showHitEffect = false;
        this.fps = 20;
        this.totalFrame = 0;
        this.imageSources = [null];
        this.layers = [];
        this.isParticle = false;
    }
    AnimationData.getAllLayers = function (data) {
        var layers = data.layers.concat();
        var index = 0;
        while (index < layers.length) {
            layers = layers.concat(layers[index].children);
            index++;
        }
        return layers;
    };
    return AnimationData;
}(OriginalData));
var AnimationItemType;
(function (AnimationItemType) {
    AnimationItemType[AnimationItemType["Target"] = 0] = "Target";
    AnimationItemType[AnimationItemType["Image"] = 1] = "Image";
    AnimationItemType[AnimationItemType["Animation"] = 2] = "Animation";
    AnimationItemType[AnimationItemType["Audio"] = 3] = "Audio";
})(AnimationItemType || (AnimationItemType = {}));
var CustomAttributeSetting = (function () {
    function CustomAttributeSetting() {
    }
    CustomAttributeSetting.init = function (data) {
        data.id = ObjectUtils.getRandID();
        data.varName = "未命名变量";
        data.varType = 0;
        data.compData = { compType: 0, compParam: {} };
        data.defaultValue = "";
        data.hideMode = false;
        data.useCommand = false;
        data.onlyPointTo = false;
        data.moduleID = 1;
        data.dataStructureID = 1;
        data.arrayMode = false;
        data.arrayLength = 100;
        data.arrayAllowDelete = false;
        data.arrayAllowSwap = false;
        data.arrayAllowUpdate = false;
        data.accessMode = 0;
        data.syncMode = 0;
        data.attrTips = "";
        data.preview = false;
    };
    CustomAttributeSetting.getAPIRuntimes = function (varAttrs, jurisdictionRestriction, indent) {
        if (jurisdictionRestriction === void 0) { jurisdictionRestriction = false; }
        if (indent === void 0) { indent = "    "; }
        var code = "";
        for (var i in varAttrs) {
            var attr = varAttrs[i];
            if (jurisdictionRestriction && attr.accessMode == 0)
                continue;
            code += indent + this.getAPIRuntime(attr) + "\n";
        }
        return code;
    };
    CustomAttributeSetting.getAPIRuntime = function (attr, isStatic) {
        if (isStatic === void 0) { isStatic = false; }
        var varTypeStr = "";
        switch (attr.varType) {
            case 0:
                varTypeStr = "number";
                break;
            case 1:
                varTypeStr = "string";
                break;
            case 2:
                varTypeStr = "boolean";
                break;
            case 3:
                varTypeStr = CustomCompositeSetting.getVarTypeInEditorCode(0, attr.dataStructureID);
                break;
            case 4:
                varTypeStr = CustomCompositeSetting.getVarTypeInEditorCode(1, attr.moduleID);
                break;
        }
        if (attr.arrayMode) {
            varTypeStr += "[] = [];";
        }
        else {
            if (attr.varType == 0) {
                varTypeStr += " = " + MathUtils.float(attr.defaultValue) + ";";
            }
            else if (attr.varType == 1) {
                varTypeStr += " = \"" + attr.defaultValue + "\";";
            }
            else if (attr.varType == 2) {
                varTypeStr += " = " + (attr.defaultValue ? "true" : "false") + ";";
            }
            else {
                varTypeStr += ";";
            }
        }
        return "" + (isStatic ? "static " : "") + attr.varName + ": " + varTypeStr;
    };
    CustomAttributeSetting.getTypeName = function (data) {
        var arr = ["数值", "字符串", "布尔值", "{自定义数据结构}", "{自定义模块}"];
        var str = arr[data.varType];
        if (data.varType == 3) {
            var name = GameListData.getName(Common.dataStructureList, data.dataStructureID);
            str = "<" + data.dataStructureID + "-" + name + ">";
        }
        else if (data.varType == 4) {
            var name = GameListData.getName(Common.customModuleList, data.moduleID);
            str = "\u3010" + data.moduleID + "-" + name + "\u3011";
        }
        if (data.arrayMode) {
            str += "[]";
        }
        return str;
    };
    CustomAttributeSetting.getSerializeAttrType = function (data, arrayEnabled) {
        if (arrayEnabled === void 0) { arrayEnabled = true; }
        var serializeAttrType = data.varType;
        if (serializeAttrType == 4 && !data.onlyPointTo)
            serializeAttrType += 1;
        if (data.arrayMode && arrayEnabled)
            serializeAttrType += 6;
        return serializeAttrType;
    };
    CustomAttributeSetting.formatCustomData = function (myCustomAttributes, attrPerSettings) {
        if (!(attrPerSettings instanceof Array)) {
            attrPerSettings = CustomCompositeSetting.getAllAttributes(attrPerSettings, false);
        }
        var newestDataStructureList = Common.dataStructureList;
        var newestCustomModuleList = Common.customModuleList;
        var customModuleDataList = Common.customModuleDataList;
        if (!myCustomAttributes)
            myCustomAttributes = {};
        for (var i in attrPerSettings) {
            var attrPerSetting = attrPerSettings[i];
            var perVarName = attrPerSetting.varName;
            if (myCustomAttributes[perVarName] == null) {
                myCustomAttributes[perVarName] = CustomAttributeSetting.formatCustomDefaultValue(attrPerSetting, true);
            }
        }
        for (var myVarName in myCustomAttributes) {
            var m = ArrayUtils.matchAttributes(attrPerSettings, { varName: myVarName }, true);
            var perAttr = m[0];
            if (!perAttr) {
                delete myCustomAttributes[myVarName];
                continue;
            }
            var myAttr = myCustomAttributes[myVarName];
            if (!myAttr) {
                continue;
            }
            var mySerializeAttrType = myAttr.varType;
            var perSerializeAttrType = CustomAttributeSetting.getSerializeAttrType(perAttr);
            if (perSerializeAttrType != mySerializeAttrType) {
                myCustomAttributes[myVarName] = CustomAttributeSetting.formatCustomDefaultValue(perAttr, true);
            }
            else {
                if (mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE || mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE_ID_ARRAY) {
                    var dataStructure = newestDataStructureList.data[perAttr.dataStructureID];
                    if (!dataStructure) {
                        delete myCustomAttributes[myVarName];
                        continue;
                    }
                    var _attrPerSettings = CustomCompositeSetting.getAllAttributes(dataStructure, false);
                    var myAttrValue;
                    if (mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE_ID_ARRAY) {
                        var valueArr = myAttr.value;
                        for (var i in valueArr) {
                            myAttrValue = valueArr[i];
                            CustomAttributeSetting.formatCustomData(myAttrValue, _attrPerSettings);
                        }
                    }
                    else {
                        myAttrValue = myAttr.value;
                        CustomAttributeSetting.formatCustomData(myAttrValue, _attrPerSettings);
                    }
                }
                else if (mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE || mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE_ARRAY) {
                    var customModule = newestCustomModuleList.data[perAttr.moduleID];
                    if (!customModule) {
                        delete myCustomAttributes[myVarName];
                        continue;
                    }
                    var _attrPerSettings = CustomCompositeSetting.getAllAttributes(customModule, false);
                    var myAttrValue;
                    if (mySerializeAttrType == CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE_ARRAY) {
                        var valueDataArr = myAttr.value;
                        for (var i in valueDataArr) {
                            myAttrValue = valueDataArr[i].data;
                            CustomAttributeSetting.formatCustomData(myAttrValue, _attrPerSettings);
                        }
                    }
                    else {
                        myAttrValue = myAttr.value.data;
                        CustomAttributeSetting.formatCustomData(myAttrValue, _attrPerSettings);
                    }
                }
            }
        }
        return myCustomAttributes;
    };
    CustomAttributeSetting.formatCustomDefaultValue = function (varAttrSetting, arrayEnabled) {
        var newestDataStructureList = Common.dataStructureList;
        var newestCustomModuleList = Common.customModuleList;
        var customModuleDataList = Common.customModuleDataList;
        var perSerializeAttrType = CustomAttributeSetting.getSerializeAttrType(varAttrSetting, arrayEnabled);
        if (perSerializeAttrType >= CustomAttributeSetting.ATTR_TYPE_NUMBER_ARRAY) {
            return { varType: perSerializeAttrType, value: [] };
        }
        else {
            if (perSerializeAttrType == CustomAttributeSetting.ATTR_TYPE_NUMBER || perSerializeAttrType == CustomAttributeSetting.ATTR_TYPE_MODULE_ID) {
                return { varType: perSerializeAttrType, value: MathUtils.float(varAttrSetting.defaultValue) };
            }
            else if (perSerializeAttrType == CustomAttributeSetting.ATTR_TYPE_STRING) {
                return { varType: perSerializeAttrType, value: varAttrSetting.defaultValue };
            }
            else if (perSerializeAttrType == CustomAttributeSetting.ATTR_TYPE_BOOLEAN) {
                return { varType: perSerializeAttrType, value: (MathUtils.int(varAttrSetting.defaultValue)) ? true : false };
            }
            else if (perSerializeAttrType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE) {
                var dataStructureID = varAttrSetting.dataStructureID;
                if (dataStructureID > 0) {
                    var dataSreucture = newestDataStructureList.data[dataStructureID];
                    if (dataSreucture) {
                        var attrObjs = {};
                        var dsAttrs = CustomCompositeSetting.getAllAttributes(dataSreucture);
                        for (var i in dsAttrs) {
                            var dsAttr = dsAttrs[i];
                            var typeValue = CustomAttributeSetting.formatCustomDefaultValue(dsAttr.attr, true);
                            if (typeValue) {
                                attrObjs[dsAttr.attr.varName] = typeValue;
                            }
                        }
                        return { varType: perSerializeAttrType, value: attrObjs };
                    }
                }
                return null;
            }
            else {
                if (varAttrSetting.onlyPointTo) {
                    return { varType: perSerializeAttrType, value: varAttrSetting.defaultValue };
                }
                else {
                    var moduleID = varAttrSetting.moduleID;
                    if (moduleID > 0) {
                        var moduleSetting = newestCustomModuleList.data[moduleID];
                        if (moduleSetting) {
                            var mAttrObjs = { varType: perSerializeAttrType, value: { id: varAttrSetting.moduleID, data: {} } };
                            var dsAttrs = CustomCompositeSetting.getAllAttributes(moduleSetting);
                            for (var i in dsAttrs) {
                                var dsAttr = dsAttrs[i];
                                var moduleDataID = MathUtils.int(varAttrSetting.defaultValue);
                                if (moduleDataID == 0)
                                    moduleDataID = 1;
                                mAttrObjs.value.id = moduleDataID;
                                var moduleData = customModuleDataList[moduleID].data[moduleDataID];
                                if (moduleData) {
                                    CustomAttributeSetting.formatCustomModuleFromDataBasePereset(moduleData, mAttrObjs.value);
                                }
                                else {
                                    var typeValue = CustomAttributeSetting.formatCustomDefaultValue(dsAttr.attr, true);
                                    if (typeValue) {
                                        mAttrObjs.value.data[dsAttr.attr.varName] = typeValue;
                                    }
                                }
                            }
                            return mAttrObjs;
                        }
                    }
                    return null;
                }
            }
        }
    };
    CustomAttributeSetting.formatCustomModuleFromDataBasePereset = function (moduleData, myValue) {
        if (!moduleData) {
            myValue.data = null;
            return;
        }
        myValue.data = ObjectUtils.depthClone(moduleData.attrs);
    };
    CustomAttributeSetting.serializeCustomData = function (typeValue, attrPerSettings) {
        if (!typeValue)
            typeValue = {};
        this.formatCustomData(typeValue, attrPerSettings);
        if (!(attrPerSettings instanceof Array)) {
            attrPerSettings = CustomCompositeSetting.getAllAttributes(attrPerSettings, false);
        }
        var attrSettings = attrPerSettings;
        var target = {};
        this.installAttributeFromEditorSet(target, typeValue, attrSettings);
        var arr = [];
        for (var i in attrSettings) {
            var varName = attrSettings[i].varName;
            arr.push(target[varName]);
        }
        return arr;
    };
    CustomAttributeSetting.installAttributeFromEditorSet = function (target, editorSetAttrs, attrSettings, readOnly, jurisdictionRestriction, customAttrMode) {
        if (readOnly === void 0) { readOnly = false; }
        if (jurisdictionRestriction === void 0) { jurisdictionRestriction = false; }
        if (customAttrMode === void 0) { customAttrMode = -1; }
        var customModuleList = Common.customModuleList;
        for (var s in attrSettings) {
            var attrSetting = attrSettings[s];
            var varName = attrSetting.varName;
            var editorSetAttr = editorSetAttrs[varName];
            if (jurisdictionRestriction && attrSetting.accessMode == 0) {
                continue;
            }
            if (!editorSetAttr) {
                trace("error " + varName + " installAttributeFromEditorSet!!! 一般不应该存在没有编辑器预设的数据，在保存时就全部格式化了。");
                continue;
            }
            var value = attrSetting.arrayMode && Array.isArray(editorSetAttr.value) ? editorSetAttr.value.concat() : editorSetAttr.value;
            if (attrSetting.varType == 0) {
                setTargetAttr(target, varName, value, attrSetting);
            }
            else if (attrSetting.varType == 1) {
                setTargetAttr(target, varName, value, attrSetting);
            }
            else if (attrSetting.varType == 2) {
                setTargetAttr(target, varName, value, attrSetting);
            }
            else if (attrSetting.varType == 3) {
                var ds = Common.dataStructureList.data[attrSetting.dataStructureID];
                if (ds) {
                    var dsAttrSettings = CustomCompositeSetting.getAllAttributes(ds, false);
                    if (attrSetting.arrayMode) {
                        var dsArrObj = [];
                        setTargetAttr(target, varName, dsArrObj, attrSetting, true);
                        for (var i = 0; i < value.length; i++) {
                            var dsObj = {};
                            dsArrObj[i] = dsObj;
                            this.installAttributeFromEditorSet(dsObj, value[i], dsAttrSettings, readOnly, jurisdictionRestriction, customAttrMode);
                        }
                    }
                    else {
                        var dsObj = {};
                        setTargetAttr(target, varName, dsObj, attrSetting, true);
                        this.installAttributeFromEditorSet(dsObj, editorSetAttr.value, dsAttrSettings, readOnly, jurisdictionRestriction, customAttrMode);
                    }
                }
            }
            else if (attrSetting.varType == 4) {
                var customModuleSetting = customModuleList.data[attrSetting.moduleID];
                var customModule = Common.customModuleDataList[attrSetting.moduleID];
                if (customModuleSetting && customModule) {
                    if (attrSetting.onlyPointTo) {
                        var moduleDatas = GameData.customModulePresetDatas[attrSetting.moduleID];
                        if (moduleDatas) {
                            if (attrSetting.arrayMode) {
                                var mdArrObj = [];
                                setTargetAttr(target, varName, mdArrObj, attrSetting, true);
                                for (var i = 0; i < value.length; i++) {
                                    var dataModel = moduleDatas[value[i]];
                                    mdArrObj[i] = dataModel;
                                }
                            }
                            else {
                                var dataModel = moduleDatas[editorSetAttr.value];
                                target[varName] = dataModel;
                            }
                        }
                    }
                    else {
                        var mdAttrSettings = CustomCompositeSetting.getAllAttributes(customModuleSetting, false);
                        if (attrSetting.arrayMode) {
                            var mdArrObj = [];
                            setTargetAttr(target, varName, mdArrObj, attrSetting, true);
                            for (var i = 0; i < value.length; i++) {
                                var preSetValue = value[i];
                                var moduleData = customModule.data[preSetValue.id];
                                if (moduleData) {
                                    var mdObj = {};
                                    mdArrObj[i] = mdObj;
                                    mdObj.id = preSetValue.id;
                                    this.installAttributeFromEditorSet(mdObj, preSetValue.data, mdAttrSettings, readOnly, jurisdictionRestriction, customAttrMode);
                                }
                            }
                        }
                        else {
                            var moduleData = customModule.data[editorSetAttr.value.id];
                            if (moduleData) {
                                var mdObj = {};
                                setTargetAttr(target, varName, mdObj, attrSetting, true);
                                mdObj.id = editorSetAttr.value.id;
                                this.installAttributeFromEditorSet(mdObj, editorSetAttr.value.data, mdAttrSettings, readOnly, jurisdictionRestriction, customAttrMode);
                            }
                        }
                    }
                }
            }
        }
        function setTargetAttr(target, varName, value, attrSetting, dataStructorMode) {
            if (dataStructorMode === void 0) { dataStructorMode = false; }
            target[varName] = value;
        }
    };
    CustomAttributeSetting.installAttributeFromRecordData = function (target, recordDataAttrs, attrSettings) {
        if (recordDataAttrs == null)
            return;
        var varTypeMapping = ["number", "string", "boolean"];
        for (var i in attrSettings) {
            var attrSetting = attrSettings[i];
            var varName = attrSetting.varName;
            var recordValue = recordDataAttrs[varName];
            var recordValueType = typeof recordValue;
            if (recordValue == null) {
                continue;
            }
            if (attrSetting.varType <= 2) {
                var varTypeOf = varTypeMapping[attrSetting.varType];
                if (attrSetting.arrayMode) {
                    if (recordValue instanceof Array) {
                        var targetArr = target[varName];
                        for (var s in recordValue) {
                            var recordArrValue = recordValue[s];
                            if (recordArrValue == null)
                                continue;
                            if (typeof recordArrValue == varTypeOf) {
                                targetArr[s] = recordValue[s];
                            }
                        }
                    }
                }
                else {
                    if (recordValueType == varTypeOf) {
                        target[varName] = recordValue;
                    }
                }
            }
            else if (attrSetting.varType == 3) {
                var ds = Common.dataStructureList.data[attrSetting.dataStructureID];
                if (ds) {
                    var dsAttrSettings = CustomCompositeSetting.getAllAttributes(ds, false);
                    if (attrSetting.arrayMode) {
                        if (recordValue instanceof Array) {
                            var targetArr = target[varName];
                            for (var s in recordValue) {
                                var recordArrValue = recordValue[s];
                                if (recordArrValue == null) {
                                    targetArr[s] = null;
                                }
                                else if (!(recordArrValue instanceof Array || !(recordArrValue instanceof Object))) {
                                    var newObj = targetArr[s] = {};
                                    this.installAttributeFromRecordData(newObj, recordArrValue, dsAttrSettings);
                                }
                            }
                        }
                    }
                    else {
                        if (!(recordValue instanceof Array || !(recordValue instanceof Object))) {
                            this.installAttributeFromRecordData(target[varName], recordValue, dsAttrSettings);
                        }
                    }
                }
            }
            else if (attrSetting.varType == 4) {
                var customModuleSetting = Common.customModuleList.data[attrSetting.moduleID];
                var customModule = Common.customModuleDataList[attrSetting.moduleID];
                if (customModuleSetting && customModule) {
                    if (attrSetting.onlyPointTo) {
                        var moduleDatas = GameData.customModulePresetDatas[attrSetting.moduleID];
                        if (moduleDatas) {
                            if (attrSetting.arrayMode) {
                            }
                            else {
                            }
                        }
                    }
                    else {
                        var mdAttrSettings = CustomCompositeSetting.getAllAttributes(customModuleSetting, false);
                        if (attrSetting.arrayMode) {
                            if (recordValue instanceof Array) {
                                var targetArr = target[varName];
                                for (var s in recordValue) {
                                    var recordArrValue = recordValue[s];
                                    if (recordArrValue == null) {
                                        targetArr[s] = null;
                                    }
                                    else {
                                        var moduleData = customModule.data[recordArrValue.id];
                                        if (moduleData) {
                                            var mdObj = targetArr[s] = { id: recordArrValue.id };
                                            this.installAttributeFromRecordData(mdObj, recordArrValue, mdAttrSettings);
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            var moduleData = customModule.data[recordValue.id];
                            if (moduleData) {
                                this.installAttributeFromRecordData(target[varName], recordValue, mdAttrSettings);
                            }
                        }
                    }
                }
            }
        }
    };
    CustomAttributeSetting.createVarTypeAttrsByValue = function (attrSetting, values) {
        var editAttrSetting = {};
        CustomAttributeSetting.formatCustomData(editAttrSetting, attrSetting);
        docreateVarTypeAttrsByValue(editAttrSetting, values, attrSetting);
        function docreateVarTypeAttrsByValue(editAttrSetting, values, attrSetting) {
            var orderAttrs = CustomCompositeSetting.getAllAttributes(attrSetting, false);
            for (var i = 0; i < orderAttrs.length; i++) {
                var cusAttr = orderAttrs[i];
                var varName = cusAttr.varName;
                var value = values[i];
                if (value == null)
                    continue;
                var typeValue = editAttrSetting[varName];
                if (typeValue.varType >= CustomAttributeSetting.ATTR_TYPE_NUMBER_ARRAY && !Array.isArray(value))
                    continue;
                if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_NUMBER) {
                    typeValue.value = MathUtils.float(value);
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_STRING) {
                    typeValue.value = String(value);
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_BOOLEAN) {
                    typeValue.value = value ? true : false;
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE) {
                    var typeValueV = typeValue.value;
                    var ds = Common.dataStructureList.data[cusAttr.dataStructureID];
                    if (ds)
                        docreateVarTypeAttrsByValue(typeValueV, value, ds);
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_MODULE_ID) {
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE) {
                    var typeValueV = typeValue.value ? typeValue.value.data : null;
                    var customModuleSetting = Common.customModuleList.data[cusAttr.moduleID];
                    var customModule = Common.customModuleDataList[cusAttr.moduleID];
                    if (customModuleSetting && customModule) {
                        docreateVarTypeAttrsByValue(typeValueV, value, customModuleSetting);
                    }
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_NUMBER_ARRAY) {
                    for (var s in typeValue.value) {
                        typeValue.value[s].value = MathUtils.float(value[s]);
                    }
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_STRING_ARRAY) {
                    for (var s in typeValue.value) {
                        typeValue.value[s].value = String(value[s]);
                    }
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_BOOLEAN_ARRAY) {
                    for (var s in typeValue.value) {
                        typeValue.value[s].value = value[s] ? true : false;
                    }
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_STRUCTURE_ID_ARRAY) {
                    var typeArr = typeValue.value;
                    var ds = Common.dataStructureList.data[cusAttr.dataStructureID];
                    if (ds) {
                        for (var s in typeArr) {
                            var typeValueV = typeArr[s].value;
                            docreateVarTypeAttrsByValue(typeValueV, value[s], ds);
                        }
                    }
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_MODULE_ID_ARRAY) {
                }
                else if (typeValue.varType == CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE_ARRAY) {
                    var typeArr = typeValue.value;
                    var customModuleSetting = Common.customModuleList.data[cusAttr.moduleID];
                    var customModule = Common.customModuleDataList[cusAttr.moduleID];
                    if (customModuleSetting && customModule) {
                        for (var s in typeArr) {
                            var typeValueV = typeArr[s].value ? typeValue.value[s].value.data : null;
                            docreateVarTypeAttrsByValue(typeValueV, value[s], customModuleSetting);
                        }
                    }
                }
            }
        }
        return editAttrSetting;
    };
    CustomAttributeSetting.ATTR_TYPE_NUMBER = 0;
    CustomAttributeSetting.ATTR_TYPE_STRING = 1;
    CustomAttributeSetting.ATTR_TYPE_BOOLEAN = 2;
    CustomAttributeSetting.ATTR_TYPE_STRUCTURE = 3;
    CustomAttributeSetting.ATTR_TYPE_MODULE_ID = 4;
    CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE = 5;
    CustomAttributeSetting.ATTR_TYPE_NUMBER_ARRAY = 6;
    CustomAttributeSetting.ATTR_TYPE_STRING_ARRAY = 7;
    CustomAttributeSetting.ATTR_TYPE_BOOLEAN_ARRAY = 8;
    CustomAttributeSetting.ATTR_TYPE_STRUCTURE_ID_ARRAY = 9;
    CustomAttributeSetting.ATTR_TYPE_MODULE_ID_ARRAY = 10;
    CustomAttributeSetting.ATTR_TYPE_MODULE_CLONE_ARRAY = 11;
    return CustomAttributeSetting;
}());
var CustomGameAttribute = (function () {
    function CustomGameAttribute() {
    }
    CustomGameAttribute.getAPIRuntime = function (gameAttr) {
    };
    return CustomGameAttribute;
}());





var SceneData = (function (_super) {
    __extends(SceneData, _super);
    function SceneData() {
        _super.apply(this, arguments);
        this.mapData = new MapData();
        this.sceneObjectData = new SceneObjectData();
    }
    return SceneData;
}(OriginalData));





var ScriptData = (function (_super) {
    __extends(ScriptData, _super);
    function ScriptData() {
        _super.apply(this, arguments);
    }
    ScriptData.getAllGameScriptSourceInEditor = function (mode) {
        var arr = [Game.data.commonScript, Game.data.serverScript, Game.data.clientScript];
        var scriptData = arr[mode];
        var codes = "";
        for (var i in scriptData.src) {
            var classCode = scriptData.src[i];
            if (classCode) {
                codes += classCode + "\n";
            }
        }
        return codes;
    };
    return ScriptData;
}(OriginalData));





var UIDisplayData = (function (_super) {
    __extends(UIDisplayData, _super);
    function UIDisplayData() {
        _super.apply(this, arguments);
        this.root = {
            children: []
        };
    }
    UIDisplayData.init = function (data, runScriptDomain) {
        if (!data)
            return;
        var baseCode = "var GUI_" + data.id + " = (function (_super) {__extends(GUI_" + data.id + ", _super);function GUI_" + data.id + "(isRoot) {if (isRoot === void 0) { isRoot = true; };_super.apply(this, [isRoot," + data.id + "]);\n        var data = Game.data.uiList.data[" + data.id + "];if(!data)return;GameUI.parse(data.uiDisplayData,false,null," + data.id + ",this);}return GUI_" + data.id + ";}(UIComponent.UIRoot));";
        baseCode += "var ListItem_" + data.id + " = (function (_super) {__extends(ListItem_" + data.id + ", _super);function ListItem_" + data.id + "() {_super.apply(this);}return ListItem_" + data.id + ";}(UIListItemData));";
        try {
            runScriptDomain.eval(baseCode);
        }
        catch (e) {
            alert("Initialization ui-" + data.id + " base code error!");
        }
    };
    UIDisplayData.getAllBaseCode = function (uiList) {
        var runtimeCode = "";
        for (var typeID = 1; typeID <= 16; typeID++) {
            var len = GameListData.getLength(uiList, typeID);
            for (var s = 1; s <= len; s++) {
                var uiData = GameListData.getItem(uiList, typeID, s);
                if (!uiData)
                    continue;
                uiData.uiDisplayData.id = GameListData.getID(typeID, s);
                runtimeCode += UIDisplayData.getBaseCode(uiData.uiDisplayData, uiList) + "\n";
            }
        }
        return runtimeCode;
    };
    UIDisplayData.getBaseCode = function (data, uiList) {
        var varAttributes = "";
        var listItemVarAttributes = "";
        var nameMapping = {};
        var compItemList = ArrayUtils.getTreeNodeArray(data.root, "children");
        compItemList.shift();
        var listItemTypeMapping = {
            UIBitmap: "string",
            UIString: "string",
            UIVariable: "number",
            UIAvatar: "number",
            UIAnimation: "number",
            UIInput: "string",
            UICheckBox: "boolean",
            UISwitch: "number",
            UITabBox: "string",
            UISlider: "number",
            UIGUI: "number",
            UIList: "UIListItemData[]"
        };
        for (var i = 0; i < compItemList.length; i++) {
            var compItem = compItemList[i];
            if (nameMapping[compItem.name])
                continue;
            nameMapping[compItem.name] = true;
            var type = compItem.type;
            if (type == "UIGUI") {
                if (!uiList.data[compItem.guiID])
                    continue;
                if (compItem.instanceClassName) {
                    type = compItem.instanceClassName;
                }
                else {
                    type = "GUI_" + compItem.guiID;
                }
            }
            else {
                type = "" + type;
            }
            varAttributes += "   " + compItem.name + ":" + type + ";";
            var listItemType = listItemTypeMapping[compItem.type];
            if (listItemType) {
                listItemVarAttributes += "   " + compItem.name + ":" + listItemType + ";";
                if (i != compItemList.length - 1)
                    listItemVarAttributes += "\n";
            }
            if (i != compItemList.length - 1)
                varAttributes += "\n";
        }
        var name = GameListData.getName(uiList, data.id);
        var runtimeCode = "\n/**\n * " + data.id + "-" + name + " [BASE]\n */\nclass GUI_" + data.id + " extends UIRoot {\n" + varAttributes + "\n}";
        runtimeCode += "\nclass ListItem_" + data.id + " extends UIListItemData {\n" + listItemVarAttributes + "\n}";
        return runtimeCode;
    };
    return UIDisplayData;
}(OriginalData));
var AstarUtils = (function () {
    function AstarUtils() {
        this.openList = new Array();
        this.closeList = new Array();
        this.roadArr = new Array();
    }
    AstarUtils.moveTo = function (x_x1, x_y1, x_x2, x_y2, gridW, gridH, scene) {
        var GRID_SIZE = Config.SCENE_GRID_SIZE;
        var GRID_SIZE_HALF = Math.floor(Config.SCENE_GRID_SIZE / 2) - 1;
        var x_mapw = gridW;
        var x_maph = gridH;
        var n_fanwei_W = Math.floor(Config.WINDOW_WIDTH / GRID_SIZE) + 1;
        var n_fanwei_H = Math.floor(Config.WINDOW_HEIGHT / GRID_SIZE) + 1;
        var n_f_x1 = Math.floor(x_x1 / GRID_SIZE) - n_fanwei_W;
        var n_f_y1 = Math.floor(x_y1 / GRID_SIZE) - n_fanwei_H;
        var n_f_x2 = Math.floor(x_x1 / GRID_SIZE) + n_fanwei_W;
        var n_f_y2 = Math.floor(x_y1 / GRID_SIZE) + n_fanwei_H;
        if (Math.abs(x_x2 - x_x1) > n_fanwei_W * GRID_SIZE || Math.abs(x_y2 - x_y1) > n_fanwei_H * GRID_SIZE) {
            return null;
        }
        var mapmapmap = [];
        var this_kuai;
        n_f_x1 = n_f_x1 < 0 ? 0 : n_f_x1;
        n_f_y1 = n_f_y1 < 0 ? 0 : n_f_y1;
        n_f_x2 = n_f_x2 > x_mapw ? x_mapw : n_f_x2;
        n_f_y2 = n_f_y2 > x_maph ? x_maph : n_f_y2;
        var n_pianyi_X = n_f_x1 - 0;
        var n_pianyi_Y = n_f_y1 - 0;
        var yLen = (n_f_y2 - n_f_y1);
        var xLen = (n_f_x2 - n_f_x1);
        for (var y = 0; y < yLen; y++) {
            mapmapmap[y] = [];
            for (var x = 0; x < xLen; x++) {
                this_kuai = new AstarBox();
                mapmapmap[y].push(this_kuai);
                mapmapmap[y][x].px = x;
                mapmapmap[y][x].py = y;
                mapmapmap[y][x].go = 0;
            }
        }
        var n_obx, n_oby, i;
        var helpP = new Point();
        for (var _x = n_f_x1; _x < n_f_x2; _x++) {
            for (var _y = n_f_y1; _y < n_f_y2; _y++) {
                helpP.x = _x;
                helpP.y = _y;
                if (scene.isObstacleGrid(helpP)) {
                    mapmapmap[_y - n_pianyi_Y][_x - n_pianyi_X].go = 1;
                }
            }
        }
        var actor_go = mapmapmap[Math.floor(x_y1 / GRID_SIZE) - n_pianyi_Y][Math.floor(x_x1 / GRID_SIZE) - n_pianyi_X];
        var actor_to = mapmapmap[Math.floor(x_y2 / GRID_SIZE) - n_pianyi_Y][Math.floor(x_x2 / GRID_SIZE) - n_pianyi_X];
        var _ARoad = new AstarUtils();
        var roadList = _ARoad.searchRoad(actor_go, actor_to, mapmapmap);
        if (roadList.length < 1) {
            return null;
        }
        var roadLines = [];
        for (i = roadList.length - 1; i > 0; i--) {
            var n_px_real = roadList[i].px + n_pianyi_X;
            var n_py_real = roadList[i].py + n_pianyi_Y;
            roadLines.push([n_px_real * GRID_SIZE + GRID_SIZE_HALF, n_py_real * GRID_SIZE + GRID_SIZE_HALF]);
        }
        roadLines.push([x_x2, x_y2]);
        return roadLines;
    };
    AstarUtils.def_bigMoveTo = function (gridW, gridH, obsArr) {
        var n_f_x1 = 0;
        var n_f_y1 = 0;
        var n_f_x2 = gridW;
        var n_f_y2 = gridH;
        var mapmapmap = [];
        var this_kuai;
        var n_pianyi_X = n_f_x1 - 0;
        var n_pianyi_Y = n_f_y1 - 0;
        var yLen = (n_f_y2 - n_f_y1);
        var xLen = (n_f_x2 - n_f_x1);
        for (var y = 0; y <= yLen; y++) {
            mapmapmap[y] = [];
            for (var x = 0; x <= xLen; x++) {
                this_kuai = new AstarBox();
                mapmapmap[y].push(this_kuai);
                mapmapmap[y][x].px = x;
                mapmapmap[y][x].py = y;
                mapmapmap[y][x].go = 0;
            }
        }
        var n_obx, n_oby, i;
        for (var _x = n_f_x1; _x < n_f_x2; _x++) {
            for (var _y = n_f_y1; _y < n_f_y2; _y++) {
                if (obsArr[_x][_y]) {
                    mapmapmap[_y - n_pianyi_Y][_x - n_pianyi_X].go = 1;
                }
            }
        }
        this.big_mapmapmap = mapmapmap;
    };
    AstarUtils.bigMoveTo = function (x_x1, x_y1, x_x2, x_y2) {
        var GRID_SIZE = Config.SCENE_GRID_SIZE;
        var GRID_SIZE_HALF = Math.floor(Config.SCENE_GRID_SIZE / 2) - 1;
        var mapmapmap = this.big_mapmapmap;
        var actor_go = mapmapmap[Math.floor(x_y1 / GRID_SIZE)][Math.floor(x_x1 / GRID_SIZE)];
        var actor_to = mapmapmap[Math.floor(x_y2 / GRID_SIZE)][Math.floor(x_x2 / GRID_SIZE)];
        var _ARoad = new AstarUtils();
        var roadList = _ARoad.searchRoad(actor_go, actor_to, mapmapmap);
        if (roadList.length < 1) {
            return null;
        }
        var roadLines = [];
        for (var i = roadList.length - 1; i > 0; i--) {
            var n_px_real = roadList[i].px;
            var n_py_real = roadList[i].py;
            roadLines.push([n_px_real * GRID_SIZE + GRID_SIZE_HALF, n_py_real * GRID_SIZE + GRID_SIZE_HALF]);
        }
        roadLines.push([x_x2, x_y2]);
        return roadLines;
    };
    AstarUtils.prototype.searchRoad = function (start, end, map) {
        this.startPoint = start;
        this.endPoint = end;
        this.mapArr = map;
        this.w = this.mapArr[0].length - 1;
        this.h = this.mapArr.length - 1;
        this.openList.push(this.startPoint);
        var ix = 0;
        while (true) {
            ix++;
            if (this.openList.length < 1 || ix >= AstarUtils.ROAD_FIND_MAX) {
                return this.roadArr;
            }
            var thisPoint = this.openList.splice(this.getMinF(), 1)[0];
            if (thisPoint == this.endPoint) {
                while (thisPoint.father != this.startPoint.father) {
                    this.roadArr.push(thisPoint);
                    thisPoint = thisPoint.father;
                }
                return this.roadArr;
            }
            this.closeList.push(thisPoint);
            this.addAroundPoint(thisPoint);
        }
    };
    AstarUtils.prototype.addAroundPoint = function (thisPoint) {
        var thisPx = thisPoint.px;
        var thisPy = thisPoint.py;
        if (thisPx > 0 && this.mapArr[thisPy][thisPx - 1].go == 0) {
            if (!this.inArr(this.mapArr[thisPy][thisPx - 1], this.closeList)) {
                if (!this.inArr(this.mapArr[thisPy][thisPx - 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy][thisPx - 1], thisPoint, 10);
                    this.openList.push(this.mapArr[thisPy][thisPx - 1]);
                }
                else {
                    this.checkG(this.mapArr[thisPy][thisPx - 1], thisPoint);
                }
            }
            if (!Config.MOVE_4_ORI && thisPy > 0 && this.mapArr[thisPy - 1][thisPx - 1].go == 0 && this.mapArr[thisPy - 1][thisPx].go == 0) {
                if (!this.inArr(this.mapArr[thisPy - 1][thisPx - 1], this.closeList) && !this.inArr(this.mapArr[thisPy - 1][thisPx - 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy - 1][thisPx - 1], thisPoint, 14);
                    this.openList.push(this.mapArr[thisPy - 1][thisPx - 1]);
                }
            }
            if (!Config.MOVE_4_ORI && thisPy < this.h && this.mapArr[thisPy + 1][thisPx - 1].go == 0 && this.mapArr[thisPy + 1][thisPx].go == 0) {
                if (!this.inArr(this.mapArr[thisPy + 1][thisPx - 1], this.closeList) && !this.inArr(this.mapArr[thisPy + 1][thisPx - 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy + 1][thisPx - 1], thisPoint, 14);
                    this.openList.push(this.mapArr[thisPy + 1][thisPx - 1]);
                }
            }
        }
        if (thisPx < this.w && this.mapArr[thisPy][thisPx + 1].go == 0) {
            if (!this.inArr(this.mapArr[thisPy][thisPx + 1], this.closeList)) {
                if (!this.inArr(this.mapArr[thisPy][thisPx + 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy][thisPx + 1], thisPoint, 10);
                    this.openList.push(this.mapArr[thisPy][thisPx + 1]);
                }
                else {
                    this.checkG(this.mapArr[thisPy][thisPx + 1], thisPoint);
                }
            }
            if (!Config.MOVE_4_ORI && thisPy > 0 && this.mapArr[thisPy - 1][thisPx + 1].go == 0 && this.mapArr[thisPy - 1][thisPx].go == 0) {
                if (!this.inArr(this.mapArr[thisPy - 1][thisPx + 1], this.closeList) && !this.inArr(this.mapArr[thisPy - 1][thisPx + 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy - 1][thisPx + 1], thisPoint, 14);
                    this.openList.push(this.mapArr[thisPy - 1][thisPx + 1]);
                }
            }
            if (!Config.MOVE_4_ORI && thisPy < this.h && this.mapArr[thisPy + 1][thisPx + 1].go == 0 && this.mapArr[thisPy + 1][thisPx].go == 0) {
                if (!this.inArr(this.mapArr[thisPy + 1][thisPx + 1], this.closeList) && !this.inArr(this.mapArr[thisPy + 1][thisPx + 1], this.openList)) {
                    this.setGHF(this.mapArr[thisPy + 1][thisPx + 1], thisPoint, 14);
                    this.openList.push(this.mapArr[thisPy + 1][thisPx + 1]);
                }
            }
        }
        if (thisPy > 0 && this.mapArr[thisPy - 1][thisPx].go == 0) {
            if (!this.inArr(this.mapArr[thisPy - 1][thisPx], this.closeList)) {
                if (!this.inArr(this.mapArr[thisPy - 1][thisPx], this.openList)) {
                    this.setGHF(this.mapArr[thisPy - 1][thisPx], thisPoint, 10);
                    this.openList.push(this.mapArr[thisPy - 1][thisPx]);
                }
                else {
                    this.checkG(this.mapArr[thisPy - 1][thisPx], thisPoint);
                }
            }
        }
        if (thisPy < this.h && this.mapArr[thisPy + 1][thisPx].go == 0) {
            if (!this.inArr(this.mapArr[thisPy + 1][thisPx], this.closeList)) {
                if (!this.inArr(this.mapArr[thisPy + 1][thisPx], this.openList)) {
                    this.setGHF(this.mapArr[thisPy + 1][thisPx], thisPoint, 10);
                    this.openList.push(this.mapArr[thisPy + 1][thisPx]);
                }
                else {
                    this.checkG(this.mapArr[thisPy + 1][thisPx], thisPoint);
                }
            }
        }
    };
    AstarUtils.prototype.inArr = function (obj, arr) {
        for (var m in arr) {
            var mc = arr[m];
            if (obj == mc) {
                return true;
            }
        }
        return false;
    };
    AstarUtils.prototype.setGHF = function (point, thisPoint, G) {
        if (!thisPoint.G) {
            thisPoint.G = 0;
        }
        point.G = thisPoint.G + G;
        point.H = (Math.abs(point.px - this.endPoint.px) + Math.abs(point.py - this.endPoint.py)) * 10;
        point.F = point.H + point.G;
        point.father = thisPoint;
    };
    AstarUtils.prototype.checkG = function (chkPoint, thisPoint) {
        var newG = thisPoint.G + 10;
        if (newG <= chkPoint.G) {
            chkPoint.G = newG;
            chkPoint.F = chkPoint.H + newG;
            chkPoint.father = thisPoint;
        }
    };
    AstarUtils.prototype.getMinF = function () {
        var tmpF = 100000000;
        var id = 0;
        var rid;
        for (var m in this.openList) {
            var mc = this.openList[m];
            if (mc.F < tmpF) {
                tmpF = mc.F;
                rid = id;
            }
            id++;
        }
        return rid;
    };
    AstarUtils.ROAD_FIND_MAX = 200;
    return AstarUtils;
}());
var AstarBox = (function () {
    function AstarBox() {
    }
    return AstarBox;
}());
var Config = (function () {
    function Config() {
        this.customConfig = {};
    }
    Config.init = function () {
        Config.IS_SERVER = typeof window == "undefined";
        Config.SCENE_GRID_SIZE = Math.min(512, Config.SCENE_GRID_SIZE);
        if (!Config.IS_SERVER) {
            Config.TILE_SPLIT_SIZE = Math.floor(512 / Config.SCENE_GRID_SIZE) * Config.SCENE_GRID_SIZE;
            var per = GameUtils.getAutoFitSizePre(new Rectangle(0, 0, Config.WINDOW_WIDTH, Config.WINDOW_HEIGHT), new Rectangle(0, 0, stage.width, stage.height));
            var displayWidth = Math.floor(Config.WINDOW_WIDTH * per);
            var displayHeight = Math.floor(Config.WINDOW_HEIGHT * per);
            if (Config.TILE_SPLIT_SIZE > displayWidth || Config.TILE_SPLIT_SIZE > displayHeight) {
                Config.TILE_SPLIT_SIZE = Math.min(displayWidth, displayHeight);
            }
            var p = 2;
            while (1) {
                p *= 2;
                if (p > Config.TILE_SPLIT_SIZE) {
                    break;
                }
            }
            Config.TILE_SPLIT_SIZE = p / 2;
        }
    };
    Config.saveAttrs = [];
    Config.DEBUG_OBSTACLE = false;
    Config.JSON_PATH = "asset/json";
    Config.JSON_CONFIG = Config.JSON_PATH + "/config.json";
    Config.SCENE_BY_DRAWLINES_MAX = 500;
    return Config;
}());
var SceneObject = (function () {
    function SceneObject() {
        this.modelID = 1;
        this.index = 0;
        this.name = "";
        this.x = 0;
        this.y = 0;
        this.z = 0;
        this.avatarID = 1;
        this.avatarOri = 2;
        this.avatarAct = 1;
        this.avatarPlayInterval = 5;
        this.avatarFrame = 0;
        this.avatarAlpha = 1;
        this.avatarHue = 0;
        this.shadowEnable = false;
        this.shadowWidth = 30;
        this.shadowHeight = 15;
        this.shadowAlpha = 0.5;
        this.displayList = {};
        this.selectEnabled = true;
        this.fixedOrientation = false;
        this.onTop = 1;
        this.through = false;
        this.bridge = false;
        this.autoPlayEnable = true;
        this.scale = 1;
        this.speed = 200;
        this.touchType = 0;
        this.playerUID = 0;
        this.hasCommand = [];
    }
    SceneObject.EVENT_MOVE_OVER = "SceneObject_EVENT_MOVE_OVER";
    SceneObject.EVENT_JUMP_OVER = "SceneObject_EVENT_JUMP_OVER";
    SceneObject.compoundAttributes = ["displayList"];
    return SceneObject;
}());





var CustomData = (function (_super) {
    __extends(CustomData, _super);
    function CustomData() {
        _super.apply(this, arguments);
        this.attrs = {};
    }
    return CustomData;
}(OriginalData));
var SceneObjectData = (function () {
    function SceneObjectData() {
        this.sceneObjects = [];
        this.customCommands = [];
        this.behaviors = [];
        this.customAttributes = [];
        this.events = [];
    }
    SceneObjectData.clone = function (so, sceneSoData) {
        var newData = {
            so: new SceneObject(),
            behavior: null,
            event: null,
            customAttribute: null
        };
        for (var i in newData.so) {
            newData.so[i] = so[i];
        }
        for (var i in SceneObject.compoundAttributes) {
            var attrName = SceneObject.compoundAttributes[i];
            newData.so[attrName] = ObjectUtils.depthClone(so[attrName]);
        }
        newData.event = ObjectUtils.depthClone(sceneSoData.events[so.index]);
        newData.behavior = ObjectUtils.depthClone(sceneSoData.behaviors[so.index]);
        newData.customAttribute = ObjectUtils.depthClone(sceneSoData.customAttributes[so.index]);
        return newData;
    };
    SceneObjectData.init = function (sceneObjectData, index) {
        sceneObjectData.behaviors[index] = [-1, 0, []];
        sceneObjectData.events[index] = {
            condition: [],
            customCommands: []
        };
        sceneObjectData.customAttributes[index] = {};
    };
    return SceneObjectData;
}());
var UIListItemData = (function () {
    function UIListItemData() {
        this._children = [];
        this._isOpen = true;
    }
    UIListItemData.prototype.getSaveData = function (includeData) {
        if (includeData === void 0) { includeData = false; }
        var dData = {};
        for (var i in this.uiNames) {
            dData[i] = this[i];
        }
        if (includeData)
            dData.data = this.data;
        var len = this._children.length;
        if (len > 0) {
            dData.children = [];
            for (var s = 0; s < this._children.length; s++) {
                var item = this._children[s];
                dData.children.push(item.getSaveData(includeData));
            }
        }
        dData.isOpen = this.isOpen;
        return dData;
    };
    UIListItemData.recoverySaveData = function (saveData) {
        var d = new UIListItemData();
        for (var i in saveData) {
            if (i == "children")
                continue;
            d[i] = saveData[i];
        }
        for (var i in saveData.children) {
            var saveDataChild = saveData.children[i];
            var dChild = UIListItemData.recoverySaveData(saveDataChild);
            d.addChild(dChild);
        }
        return d;
    };
    Object.defineProperty(UIListItemData.prototype, "isOpen", {
        get: function () { return this._isOpen; },
        set: function (v) {
            if (v != this._isOpen) {
                this._isOpen = v;
                EventUtils.happen(this, UIListItemData.EVENT_OPEN_CHANGE);
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(UIListItemData.prototype, "uiNames", {
        get: function () {
            var _uiNames = [];
            var _attrs = [];
            for (var s in UIListItemData.uiListItemDataHelper) {
                _attrs.push(s);
            }
            for (var i in this) {
                if (_attrs.indexOf(i) != -1)
                    continue;
                _uiNames.push(i);
            }
            return _uiNames;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(UIListItemData.prototype, "parent", {
        get: function () { return this._parent; },
        enumerable: true,
        configurable: true
    });
    UIListItemData.prototype.addChild = function (item) { this._children.push(item); item._parent = this; };
    UIListItemData.prototype.addChildAt = function (item, index) { this._children.splice(index, 0, item); item._parent = this; };
    UIListItemData.prototype.removeChild = function (item) { this._children.splice(this._children.indexOf(item), 1); item._parent = null; };
    UIListItemData.prototype.removeChildAt = function (index) { var item = this._children.splice(index, 1)[0]; item._parent = null; };
    UIListItemData.prototype.removeAll = function () { for (var i in this._children) {
        this._children[i]._parent = null;
    } ; this._children.length = 0; };
    UIListItemData.prototype.getChildAt = function (index) { return this._children[index]; };
    UIListItemData.prototype.getChildIndex = function (item) { return this._children.indexOf(item); };
    Object.defineProperty(UIListItemData.prototype, "numChildren", {
        get: function () { return this._children.length; },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(UIListItemData.prototype, "children", {
        get: function () { return this._children; },
        enumerable: true,
        configurable: true
    });
    UIListItemData.prototype.isInherit = function (data) {
        var p = this.parent;
        while (p) {
            if (p == data)
                return true;
            p = p._parent;
        }
        return false;
    };
    UIListItemData.prototype.getList = function (arr) {
        if (arr === void 0) { arr = null; }
        return ArrayUtils.getTreeNodeArray(this, "_children", arr);
    };
    Object.defineProperty(UIListItemData.prototype, "root", {
        get: function () {
            var p = this;
            while (true) {
                if (p._parent) {
                    p = p._parent;
                }
                else {
                    break;
                }
            }
            return p;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(UIListItemData.prototype, "depth", {
        get: function () {
            var p = this;
            var d = 0;
            while (1) {
                if (!p.parent)
                    break;
                d++;
                p = p.parent;
            }
            return d;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(UIListItemData.prototype, "isHideNode", {
        get: function () {
            var p = this.parent;
            while (1) {
                if (!p)
                    break;
                if (!p.isOpen)
                    return true;
                p = p.parent;
            }
            return false;
        },
        enumerable: true,
        configurable: true
    });
    UIListItemData.EVENT_SELECT_CHANGE = "UIListItemDataEVENT_SELECT_CHANGE";
    UIListItemData.EVENT_OPEN_CHANGE = "UIListItemDataEVENT_OPEN_CHANGE";
    UIListItemData.uiListItemDataHelper = new UIListItemData();
    return UIListItemData;
}());
var IdentityObject = (function () {
    function IdentityObject() {
        this.id = ++IdentityObject.idCount;
    }
    IdentityObject.idCount = 0;
    return IdentityObject;
}());





var AvatarRefObjData = (function (_super) {
    __extends(AvatarRefObjData, _super);
    function AvatarRefObjData() {
        _super.apply(this, arguments);
        this.color = "#FFFFFF";
        this.line = false;
    }
    return AvatarRefObjData;
}(OriginalData));





var MapData = (function (_super) {
    __extends(MapData, _super);
    function MapData() {
        _super.apply(this, arguments);
        this.serverInstanceClassName = MapData.SERVER_SCENE_CORE_CLASS;
        this.clientInstanceClassName = MapData.CLIENT_SCENE_CORE_CLASS;
    }
    MapData.SERVER_SCENE_CORE_CLASS = "GameServerScene";
    MapData.CLIENT_SCENE_CORE_CLASS = "GameClientScene";
    return MapData;
}(Scene));
var GameUtils = (function () {
    function GameUtils() {
    }
    GameUtils.getOriByIndex = function (index, oriMode) {
        if (oriMode === void 0) { oriMode = 8; }
        var oriMapping;
        switch (oriMode) {
            case 1:
                oriMapping = { 0: 4 };
                break;
            case 2:
                oriMapping = { 0: 4, 1: 6 };
                break;
            case 3:
                oriMapping = { 0: 4, 1: 2, 2: 8 };
                break;
            case 4:
                oriMapping = { 0: 2, 1: 4, 2: 6, 3: 8 };
                break;
            case 5:
                oriMapping = { 0: 2, 1: 1, 2: 4, 3: 7, 4: 8 };
                break;
            case 8:
                oriMapping = { 0: 4, 1: 7, 2: 8, 3: 9, 4: 6, 5: 3, 6: 2, 7: 1 };
                break;
        }
        return oriMapping[index];
    };
    GameUtils.getIndexByOri = function (ori, oriMode) {
        if (oriMode === void 0) { oriMode = 8; }
        var oriMapping;
        switch (oriMode) {
            case 1:
                oriMapping = { 1: 0, 2: 0, 3: 0, 4: 0, 6: 0, 7: 0, 8: 0, 9: 0 };
                break;
            case 2:
                oriMapping = { 1: 0, 2: 1, 3: 1, 4: 0, 6: 1, 7: 0, 8: 1, 9: 1 };
                break;
            case 3:
                oriMapping = { 1: 4, 2: 1, 3: 4, 4: 0, 6: 0, 7: 0, 8: 2, 9: 0 };
                break;
            case 4:
                oriMapping = { 1: 1, 2: 0, 3: 2, 4: 1, 6: 2, 7: 1, 8: 3, 9: 2 };
                break;
            case 5:
                oriMapping = { 1: 1, 2: 0, 3: 1, 4: 2, 6: 2, 7: 3, 8: 4, 9: 3 };
                break;
            case 8:
                oriMapping = { 1: 7, 2: 6, 3: 5, 4: 0, 6: 4, 7: 1, 8: 2, 9: 3 };
                break;
        }
        return oriMapping[ori];
    };
    GameUtils.getAssetOri = function (ori, oriMode) {
        if (oriMode === void 0) { oriMode = 8; }
        var oriMapping;
        switch (oriMode) {
            case 1:
                oriMapping = { 1: 4, 2: 4, 3: 4, 4: 4, 6: 4, 7: 4, 8: 4, 9: 4 };
                break;
            case 2:
                oriMapping = { 1: 4, 2: 6, 3: 6, 4: 4, 6: 6, 7: 4, 8: 6, 9: 6 };
                break;
            case 3:
                oriMapping = { 1: 4, 2: 2, 3: 4, 4: 4, 6: 4, 7: 4, 8: 8, 9: 4 };
                break;
            case 4:
                oriMapping = { 1: 4, 2: 2, 3: 6, 4: 4, 6: 6, 7: 4, 8: 8, 9: 6 };
                break;
            case 5:
                oriMapping = { 1: 1, 2: 2, 3: 1, 4: 4, 6: 4, 7: 7, 8: 8, 9: 7 };
                break;
            case 8:
                oriMapping = { 1: 1, 2: 2, 3: 3, 4: 4, 6: 6, 7: 7, 8: 8, 9: 9 };
                break;
        }
        return oriMapping[ori];
    };
    GameUtils.getOriByAngle = function (angle) {
        if (angle >= 337.5 || angle < 22.5) {
            return 8;
        }
        else if (angle >= 22.5 && angle < 67.5) {
            return 9;
        }
        else if (angle >= 67.5 && angle < 112.5) {
            return 6;
        }
        else if (angle >= 112.5 && angle < 157.5) {
            return 3;
        }
        else if (angle >= 157.5 && angle < 202.5) {
            return 2;
        }
        else if (angle >= 202.5 && angle < 247.5) {
            return 1;
        }
        else if (angle >= 247.5 && angle < 292.5) {
            return 4;
        }
        else if (angle >= 292.5 && angle < 337.5) {
            return 7;
        }
        return 2;
    };
    GameUtils.getAngleByOri = function (ori) {
        switch (ori) {
            case 1:
                return 225;
            case 2:
                return 180;
            case 3:
                return 145;
            case 4:
                return 270;
            case 6:
                return 90;
            case 7:
                return 315;
            case 8:
                return 0;
            case 9:
                return 45;
        }
    };
    GameUtils.getFlipOri = function (ori) {
        var mapping = { 1: 9, 2: 8, 3: 7, 4: 6, 6: 4, 7: 3, 8: 2, 9: 1 };
        return mapping[ori];
    };
    GameUtils.getGridPostion = function (p, helpP) {
        if (helpP === void 0) { helpP = null; }
        var rp = helpP;
        var s = Config.SCENE_GRID_SIZE;
        if (rp) {
            rp.x = Math.floor(p.x / s);
            rp.y = Math.floor(p.y / s);
        }
        else {
            rp = new Point(Math.floor(p.x / s), Math.floor(p.y / s));
        }
        return rp;
    };
    GameUtils.getGridCenter = function (p, helpP) {
        if (helpP === void 0) { helpP = null; }
        var rp = helpP;
        var s = Config.SCENE_GRID_SIZE;
        var h = Math.floor(Config.SCENE_GRID_SIZE / 2);
        if (rp) {
            rp.x = Math.floor(p.x / s) * s + h;
            rp.y = Math.floor(p.y / s) * s + h;
        }
        else {
            rp = new Point(Math.floor(p.x / s) * s + h, Math.floor(p.y / s) * s + h);
        }
        return rp;
    };
    GameUtils.twoPointHasObstacle = function (x_x1, x_y1, x_x2, x_y2, scene, except) {
        if (except === void 0) { except = null; }
        var actor_p1 = new Point(x_x1, x_y1);
        var actor_p2 = new Point(x_x2, x_y2);
        var n_jieduan = 16;
        var n_s_p1p2 = Point.distance(actor_p1, actor_p2);
        var n_s_xiang = [];
        var len = Math.floor(n_s_p1p2 / n_jieduan);
        for (var i = 1; i <= len; i++) {
            var n_new_x = (actor_p2.x - actor_p1.x) / (n_s_p1p2 / n_jieduan) * i + actor_p1.x;
            var n_new_y = (actor_p2.y - actor_p1.y) / (n_s_p1p2 / n_jieduan) * i + actor_p1.y;
            n_s_xiang.push(new Point(n_new_x, n_new_y));
        }
        n_s_xiang.push(new Point(x_x2, x_y2));
        for (var s in n_s_xiang) {
            if (scene.isObstacle(n_s_xiang[s], except)) {
                return true;
            }
        }
        return false;
    };
    GameUtils.getSameStateGrid = function (mapData, gridX, gridY, width, height, attributes, limit) {
        if (limit === void 0) { limit = 100; }
        var limit = 100;
        var limitRect = new Rectangle(Math.max(gridX - limit, 0), Math.max(gridY - limit, 0), Math.min(width, gridX + limit), Math.min(height, gridY + limit));
        var points = [];
        var firstGrid = mapData[gridX] ? mapData[gridX][gridY] : null;
        var gridHelpArr = [];
        for (var x = 0; x < width; x++) {
            gridHelpArr[x] = [];
        }
        var dir = [null, null, [8, 0, 1], null, [6, -1, 0], null, [4, 1, 0], null, [2, 0, -1]];
        var dirIndexes = [2, 4, 6, 8];
        var needSearchGrid = [];
        needSearchGrid.push({ gridX: gridX, gridY: gridY, from: 0 });
        var from = 0;
        while (1) {
            if (needSearchGrid.length == 0)
                break;
            var currentGridData = needSearchGrid.shift();
            gridX = currentGridData.gridX;
            gridY = currentGridData.gridY;
            if (gridHelpArr[gridX][gridY])
                continue;
            gridHelpArr[gridX][gridY] = true;
            var currentGrid = mapData[gridX] ? mapData[gridX][gridY] : null;
            if (currentGrid == firstGrid) { }
            else if (currentGrid && firstGrid) {
                var isSame;
                if (attributes) {
                    isSame = true;
                    for (var attr in attributes) {
                        var attribute = attributes[attr];
                        if (currentGrid[attribute] != firstGrid[attribute]) {
                            isSame = false;
                            break;
                        }
                    }
                }
                else {
                    isSame = currentGrid === firstGrid;
                }
                if (!isSame)
                    continue;
            }
            else {
                continue;
            }
            points.push(new Point(gridX, gridY));
            for (var d = 0; d < 4; d++) {
                var toDir = dirIndexes[d];
                var toDirData = dir[toDir];
                if (toDirData[0] == currentGridData.from)
                    continue;
                var toX = gridX + toDirData[1];
                var toY = gridY + toDirData[2];
                if (toX < limitRect.x || toX >= limitRect.width || toY < limitRect.y || toY >= limitRect.height)
                    continue;
                needSearchGrid.push({ gridX: toX, gridY: toY, from: toDir });
            }
        }
        return points;
    };
    GameUtils.getMendingGrids = function (grid1, grid2, per) {
        if (per === void 0) { per = 0.1; }
        var gridDetermine = [];
        var grids = [];
        for (var i = 0; i <= 1; i += 0.1) {
            var p = Point.interpolate(grid1, grid2, i);
            p.x = Math.floor(p.x);
            p.y = Math.floor(p.y);
            var xArr = gridDetermine[p.x];
            if (!xArr)
                xArr = gridDetermine[p.x] = [];
            if (xArr[p.y])
                continue;
            xArr[p.y] = true;
            if (grid1.x == p.x && grid1.y == p.y)
                continue;
            grids.push(p);
        }
        return grids;
    };
    GameUtils.getAutoFitSizePre = function (rect, canvasRect) {
        var xPer = canvasRect.width / rect.width;
        var yPer = canvasRect.height / rect.height;
        var per = Math.min(xPer, yPer);
        return per;
    };
    GameUtils.isInheritNode = function (node, parentNode) {
        var p = node.parent;
        while (p) {
            if (p == parentNode)
                return true;
            p = p.parent;
        }
        return false;
    };
    GameUtils.getAllChildren = function (node, arr) {
        if (arr === void 0) { arr = null; }
        if (!arr)
            arr = [];
        arr.push(node);
        var len = node.numChildren;
        for (var i = 0; i < len; i++) {
            this.getAllChildren(node.getChildAt(i), arr);
        }
        return arr;
    };
    GameUtils.getVarID = function (value) {
        if (value && value.toString().search(/\$[0-9]*/g) == 0) {
            var id = parseInt(value.toString().substr(1));
            return id;
        }
        return 0;
    };
    GameUtils.getTween = function (tweenID) {
        if (!tweenID)
            return [Ease.linearNone, "linearNone"];
        var arr = ["linearNone", "bounceIn", "bounceInOut", "bounceOut", "backIn",
            "backInOut", "backOut", "elasticIn", "elasticInOut", "elasticOut", "strongIn",
            "strongInOut", "strongOut", "sineIn", "sineInOut", "sineOut", "quintIn",
            "quintInOut", "quintOut", "quartIn", "quartInOut", "quartOut", "cubicIn",
            "cubicInOut", "cubicOut", "quadIn", "quadInOut", "quadOut", "expoIn", "expoInOut",
            "expoOut", "circIn", "circInOut", "circOut"];
        return [Ease[arr[tweenID]], arr[tweenID]];
    };
    GameUtils.getTweenLabels = function () {
        var tweenLabel = "无";
        for (var i = 1; i < GameUtils.tweenCount; i++) {
            var tweenData = GameUtils.getTween(i);
            tweenLabel += "," + tweenData[1];
        }
        return tweenLabel;
    };
    GameUtils.isLegalVarName = function (varName, headFont) {
        if (headFont === void 0) { headFont = true; }
        var reg = /([\$_a-zA-Z]|[\u4e00-\u9fa50-9a-zA-Z_$]){1,255}/g;
        var m = varName.match(reg);
        if (headFont && !isNaN(parseInt(varName[0])))
            return false;
        return m != null && m[0] == varName;
    };
    GameUtils.tweenCount = 34;
    return GameUtils;
}());





var UICommandData = (function (_super) {
    __extends(UICommandData, _super);
    function UICommandData() {
        _super.apply(this, arguments);
        this.condition = [];
        this.click = [];
    }
    return UICommandData;
}(OriginalData));





var AvatarData = (function (_super) {
    __extends(AvatarData, _super);
    function AvatarData() {
        _super.apply(this, arguments);
        this.picUrls = ["asset/editor/image/empty.png"];
        this.oriMode = 4;
        this.refObjs = {};
        this.parts = [{ id: 0, showOnEditor: true, mouseEventEnabledInEditor: true }];
        this.actionListArr = [{
                id: 1,
                frameImageInfo: []
            }];
    }
    return AvatarData;
}(OriginalData));





var CommonEventData = (function (_super) {
    __extends(CommonEventData, _super);
    function CommonEventData() {
        _super.apply(this, arguments);
        this.allowClient = false;
        this.conditionSwitch = 1;
        this.updateMode = false;
        this.commands = [];
    }
    return CommonEventData;
}(OriginalData));





var CustomCompositeSetting = (function (_super) {
    __extends(CustomCompositeSetting, _super);
    function CustomCompositeSetting() {
        _super.apply(this, arguments);
    }
    CustomCompositeSetting.init = function (data) {
        var block = new CustomCompositeBlock();
        CustomCompositeBlock.init(block);
        data.blockList = [block];
    };
    CustomCompositeSetting.runCode = function (gameData) {
        CustomCompositeSetting.runCodeByList(gameData.dataStructureList, 0, gameData);
        CustomCompositeSetting.runCodeByList(gameData.customModuleList, 1, gameData);
        CustomCompositeSetting.runWorldData();
        CustomCompositeSetting.runCodeByItem(gameData.customGameAttribute.playerAttributeSetting, 3, gameData);
        CustomCompositeSetting.createPresetCustomModuleDatas();
    };
    CustomCompositeSetting.runCodeByList = function (list, mode, gameData) {
        var dsItems = GameListData.getItems(list);
        for (var i in dsItems) {
            var dsItem = dsItems[i];
            CustomCompositeSetting.runCodeByItem(dsItem, mode, gameData);
        }
    };
    CustomCompositeSetting.createPresetCustomModuleDatas = function () {
        var customModuleList = Common.customModuleList;
        var customModuleDataList = Common.customModuleDataList;
        for (var i in customModuleList.data) {
            var moduleIndex = parseInt(i);
            var cmSetting = customModuleList.data[moduleIndex];
            if (cmSetting) {
                var singleModuleDataArr = GameData.customModulePresetDatas[moduleIndex] = [];
                var cmDatas = customModuleDataList[moduleIndex].data;
                var attrSettings = CustomCompositeSetting.getAllAttributes(cmSetting, false);
                for (var s in cmDatas) {
                    var dataID = parseInt(s);
                    var cmData = cmDatas[dataID];
                    if (cmData) {
                        var cmObj = {};
                        cmObj.id = dataID;
                        singleModuleDataArr[dataID] = cmObj;
                        CustomAttributeSetting.installAttributeFromEditorSet(cmObj, cmData.attrs, attrSettings, true, !Config.IS_SERVER);
                    }
                }
            }
        }
    };
    CustomCompositeSetting.runCodeByItem = function (dsItem, mode, gameData) {
        var attrs = CustomCompositeSetting.getAllAttributes(dsItem, false);
        var classVarName = this.getVarTypeInEditorCode(mode, dsItem.id);
        if (classVarName == "any")
            return;
        var vars = "";
        var dsCls = "var " + classVarName + " = function(){" + vars;
        for (var i in attrs) {
            var attr = attrs[i];
            if (!Config.IS_SERVER && attr.accessMode == 0)
                continue;
            if (attr.arrayMode) {
                dsCls += "this." + attr.varName + " = [];";
            }
            else {
                if (attr.defaultValue) {
                    if (attr.varType == 0) {
                        dsCls += "this." + attr.varName + " = " + MathUtils.float(attr.defaultValue) + ";";
                    }
                    else if (attr.varType == 1) {
                        if (attr.defaultValue.length >= 2 && attr.defaultValue[0] == "\"" && attr.defaultValue[attr.defaultValue.length - 1] == "\"") {
                            dsCls += "this." + attr.varName + " = " + attr.defaultValue + ";";
                        }
                        else {
                            dsCls += "this." + attr.varName + " = \"" + attr.defaultValue + "\";";
                        }
                    }
                    else if (attr.varType == 2) {
                        dsCls += "this." + attr.varName + " = " + (attr.defaultValue ? "true" : "false") + ";";
                    }
                }
                if (attr.varType == 3) {
                    if (gameData.dataStructureList.data[attr.dataStructureID]) {
                        var dataStructureCls = this.getVarTypeInEditorCode(0, attr.dataStructureID);
                        if (dataStructureCls != "any")
                            dsCls += "this." + attr.varName + " = new " + dataStructureCls + ";";
                    }
                }
                else if (attr.varType == 4) {
                    if (gameData.customModuleList.data[attr.moduleID]) {
                        var customCls = this.getVarTypeInEditorCode(1, attr.moduleID);
                        if (customCls != "any")
                            dsCls += "this." + attr.varName + " = new " + customCls + ";";
                    }
                }
            }
        }
        dsCls += "}";
        globalThis.eval(dsCls);
    };
    CustomCompositeSetting.runWorldData = function () {
        var customGameAttribute = Common.customGameAttribute;
        globalThis.WorldData = {};
        var attrSettings = CustomCompositeSetting.getAllAttributes(customGameAttribute.worldAttributeSetting, false);
        CustomAttributeSetting.installAttributeFromEditorSet(globalThis.WorldData, customGameAttribute.worldAttributeConfig.attrs, attrSettings, false, !Config.IS_SERVER, GameData.CUSTOM_ATTR_WORLD_DATA);
        if (!Config.EDIT_MODE) {
            if (Config.IS_SERVER) {
                ServerWorld.data = globalThis.WorldData;
                CustomAttributeSetting.installAttributeFromRecordData(ServerWorld.data, ServerSql.recordWorldData, attrSettings);
                ServerSql.recordWorldData = null;
            }
            else {
                ClientWorld.data = globalThis.WorldData;
            }
        }
    };
    CustomCompositeSetting.getAllAttributes = function (data, dsAttrMode) {
        if (dsAttrMode === void 0) { dsAttrMode = true; }
        var len = data.blockList.length;
        var arr = [];
        for (var i = 0; i < len; i++) {
            var block = data.blockList[i];
            var aLen = block.blockAttrs.length;
            for (var s = 0; s < aLen; s++) {
                if (dsAttrMode) {
                    arr.push(block.blockAttrs[s]);
                }
                else {
                    arr.push(block.blockAttrs[s].attr);
                }
            }
        }
        return arr;
    };
    CustomCompositeSetting.getAllAPIRunetime = function (mode, limitJurisdiction) {
        if (limitJurisdiction === void 0) { limitJurisdiction = false; }
        if (mode == 0 || mode == 1 || mode == 4) {
            var lists = [Common.dataStructureList, Common.customModuleList, null, null, null];
            var nameHeads = ["DataStructure", "Module", null, null, "SceneModel"];
            var list = lists[mode];
            var datas = GameListData.getItems(list);
            var runtimeStr = "";
            var len = datas.length;
            for (var i = 0; i < len; i++) {
                var data = datas[i];
                runtimeStr += this.getAPIRuntime(mode, data, limitJurisdiction);
                if (i != len - 1)
                    runtimeStr += "\n";
            }
            return runtimeStr;
        }
        else if (mode == 2) {
            return this.getAPIRuntime(mode, Common.customGameAttribute.worldAttributeSetting, limitJurisdiction, true);
        }
        else if (mode == 3) {
            return this.getAPIRuntime(mode, Common.customGameAttribute.playerAttributeSetting, limitJurisdiction);
        }
        return "";
    };
    CustomCompositeSetting.getAPIRuntime = function (mode, cSetting, limitJurisdiction, isStatic) {
        if (limitJurisdiction === void 0) { limitJurisdiction = false; }
        if (isStatic === void 0) { isStatic = false; }
        var attrs = CustomCompositeSetting.getAllAttributes(cSetting, false);
        var len = attrs.length;
        var className = this.getVarTypeInEditorCode(mode, cSetting.id);
        if (className == "any")
            return "";
        var runtimeStr = (cSetting.id ? "/**\n * #" + cSetting.id + "\n */\n" : "") + "class " + className + " {\n";
        if (mode == 1) {
            runtimeStr += "    id:number;\n";
        }
        for (var i = 0; i < len; i++) {
            var attr = attrs[i];
            if (!limitJurisdiction || attr.accessMode != 0) {
                var varStr = CustomAttributeSetting.getAPIRuntime(attr, isStatic);
                runtimeStr += "    " + varStr;
                runtimeStr += "\n";
            }
        }
        runtimeStr += "}";
        return runtimeStr;
    };
    CustomCompositeSetting.getVarTypeInEditorCode = function (mode, id) {
        if (mode == 0 || mode == 1 || mode == 4) {
            var lists = [Common.dataStructureList, Common.customModuleList, null, null, null];
            var nameHeads = ["DataStructure", "Module", null, null, "SceneModel"];
            if (id == -1)
                return nameHeads[mode];
            var list = lists[mode];
            var cSetting = list.data[id];
            if (cSetting) {
                var settingName = GameListData.getName(list, id);
                return nameHeads[mode] + "_" + settingName;
            }
            else {
                return "any";
            }
        }
        else if (mode == 2) {
            return "WorldData";
        }
        else if (mode == 3) {
            return "PlayerData";
        }
    };
    return CustomCompositeSetting;
}(OriginalData));
var CustomCompositeBlock = (function () {
    function CustomCompositeBlock() {
    }
    CustomCompositeBlock.init = function (data) {
        data.name = "未命名块";
        data.blockAttrs = [];
        data.blockCondition = [];
        data.blockHeight = 300;
        data.autoOrder = true;
    };
    return CustomCompositeBlock;
}());
var CustomCompositeAttributeSetting = (function () {
    function CustomCompositeAttributeSetting() {
    }
    CustomCompositeAttributeSetting.init = function (data) {
        data.attr = new CustomAttributeSetting();
        CustomAttributeSetting.init(data.attr);
        data.attrConditions = [];
        data.x = data.y = 0;
        data.width = 200;
        data.height = 32;
    };
    return CustomCompositeAttributeSetting;
}());





var CustomEventType = (function (_super) {
    __extends(CustomEventType, _super);
    function CustomEventType() {
        _super.apply(this, arguments);
    }
    return CustomEventType;
}(OriginalData));





var DialogData = (function (_super) {
    __extends(DialogData, _super);
    function DialogData() {
        _super.call(this);
        this.option = {
            x: 132,
            y: 189,
            width: 310,
            height: 40,
            color: "#FFFFFF",
            fontSize: 24,
            leading: 3,
            align: "1",
            valign: "top"
        };
        this.optionBox = {
            x: 100,
            y: 161,
            width: 375,
            height: 87,
            column: 2,
            columnSpaceing: 5,
            rowSpaceing: 5,
            image1: "asset/image/ui/Kelvin 287_3.png",
            image2: "asset/image/ui/Kelvin 285_3.png",
            overSe: "asset/audio/se/btn.mp3,1,1",
            overVolume: 1,
            overPitch: 1,
            clickSe: "asset/audio/se/over_btn.mp3,1,1",
            clickVolume: 1,
            clikcPitch: 1
        };
        this.dialogBox = {
            x: 39,
            y: 492,
            width: 926,
            height: 193,
            skin: "asset/image/ui/Kelvin 70_1.png"
        };
        this.headBox = {
            x: 51,
            y: 512,
            width: 142,
            height: 142,
            skin: Config.EDIT_MODE ? Editor.URL_UNKNOW_IMAGE : ""
        };
        this.dialog = {
            x: 207,
            y: 559,
            width: 726,
            height: 125,
            color: "#FFFFFF",
            fontSize: 24,
            leading: 6,
            align: "0",
        };
        this.nameBox = {
            x: 208,
            y: 515,
            width: 123,
            height: 28,
            color: "#FFFF00",
            fontSize: 24,
            leading: 3,
            align: "1",
        };
    }
    return DialogData;
}(OriginalData));
var CommandExecute;
(function (CommandExecute) {
    function command_1003(commandPage, cmd, trigger, triggerPlayer) {
        var info = getNeoInfo(cmd.params[1], cmd.params[2], cmd.params[3], cmd.params[4], triggerPlayer);
        var varID = cmd.params[6];
        if (cmd.params[5]) {
            if (triggerPlayer) {
                switch (cmd.params[4]) {
                    case 0:
                        triggerPlayer.variable.setString(varID, info ? info : "");
                        break;
                    case 1:
                        triggerPlayer.variable.setVariable(varID, info ? MathUtils.int(info) : 0);
                        break;
                    case 2:
                        triggerPlayer.variable.setSwitch(varID, info ? 1 : 0);
                        break;
                }
            }
        }
        else {
            switch (cmd.params[4]) {
                case 0:
                    ServerWorld.setWorldString(varID, info ? info : "");
                    break;
                case 1:
                    ServerWorld.setWorldVariable(varID, info ? MathUtils.int(info) : 0);
                    break;
                case 2:
                    ServerWorld.setWorldSwitch(varID, info ? 1 : 0);
                    break;
            }
        }
    }
    CommandExecute.command_1003 = command_1003;
    function getNeoInfo(contract, operation, params, typeNum, triggerPlayer) {
        var list = createParams(operation, params, triggerPlayer);
        var res = getInvokescript(contract, list);
        if (res && res.value) {
            var result;
            if (res.type == "ByteArray") {
                switch (typeNum) {
                    case 0:
                        result = Tool.hexToString(res.value);
                        break;
                    case 1:
                        result = Tool.hexToNumber(res.value);
                        break;
                    case 2:
                        result = Tool.hexToString(res.value);
                        break;
                }
            }
            else {
                result = res.value;
            }
            return result;
        }
        return null;
    }
    CommandExecute.getNeoInfo = getNeoInfo;
    function createParams(operation, params, triggerPlayer) {
        var arg0 = "(str)" + operation;
        var list = [];
        for (var i = 0; i < params.length; i++) {
            var item = params[i];
            var data;
            if (item.inputType == 1) {
                if (triggerPlayer) {
                    data = triggerPlayer.variable.getString(item.varID);
                }
            }
            else {
                data = item.value;
            }
            if (item.typeNum == 0) {
                list.push("(str)" + data);
            }
            else if (item.typeNum == 1) {
                list.push("(int)" + data);
            }
            else if (item.typeNum == 2) {
                list.push("(addr)" + data);
            }
            else if (item.typeNum == 3) {
                list.push("(bytes)" + data);
            }
            else if (item.typeNum == 4) {
                list.push("(hex256)" + data);
            }
            else if (item.typeNum == 5) {
                list.push("(hex160)" + data);
            }
        }
        return [arg0, list];
    }
    CommandExecute.createParams = createParams;
    function getInvokescript(scripthash, args) {
        try {
            var str = scripthash.substr(0, 2);
            if (str == "0x")
                scripthash = scripthash.substring(2);
            var script = Tool.paresInvokeJson(scripthash, args);
            var api = Tool.makeRpcUrl(Tool.api_net, "invokescript", script.toHexString());
            var result = http_get(api);
            var json = JSON.parse(result);
            return json.result[0].stack[0];
        }
        catch (e) {
            trace("服务器读取neo合约数据出错！");
            return null;
        }
    }
    CommandExecute.getInvokescript = getInvokescript;
    function invokescript(scripthash, args) {
        try {
            var script = Tool.paresInvokeJson(scripthash, args);
            var data = Tool.buildInvokeTransData_attributes(script);
            var api = Tool.makeRpcUrl(Tool.api_net, "sendrawtransaction", data.toHexString());
            var result = http_get(api);
            var json = JSON.parse(result);
            trace(json.result[0].txid);
            return json.result[0].txid;
        }
        catch (e) {
            trace("服务器调用neo合约出错！");
            return null;
        }
    }
    CommandExecute.invokescript = invokescript;
    function messageTitle1003(cmd) {
        return "<span style='color:#0070BB;'>服务器获取合约数据：</span>";
    }
    CommandExecute.messageTitle1003 = messageTitle1003;
    function message1003(cmd) {
        return "<span style='color:#0070BB;'>\u540D\u79F0:" + cmd.params[0] + ",\u5408\u7EA6\u5730\u5740:" + cmd.params[1] + ",\u8C03\u7528\u65B9\u6CD5:" + cmd.params[2] + ",\u8FD4\u56DE\u503C\u7C7B\u578B:" + cmd.params[4] + ",\u7ED1\u5B9A\u7684\u53D8\u91CF:" + cmd.params[5] + "</span>";
    }
    CommandExecute.message1003 = message1003;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_11(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            var cmdIndex = commandPage.commands.indexOf(cmd);
            var nextCmd = commandPage.commands[cmdIndex + 1];
            if (nextCmd && nextCmd.type == 3 && (nextCmd.params[0] == 0 || nextCmd.params[0] == cmd.params[0])) {
            }
            else {
                trigger.pause = true;
                trigger.offset(1);
            }
            EventUtils.happen(triggerPlayer.sceneObject, ServerSceneObject.EVENT_NEED_STOP_BEHAVIOR, [0]);
            var name = Variable.margeDynamicText(cmd.paramsCompiled[0], triggerPlayer, trigger);
            var content = Variable.margeDynamicText(cmd.paramsCompiled[1], triggerPlayer, trigger);
            cmd.callClient(trigger.id, trigger.triggerPlayer, [cmd.params[0], cmd.params[1], name, cmd.params[3], cmd.params[4], content]);
        }
    }
    CommandExecute.command_11 = command_11;
    function precompile_11(commandPage, cmd, index) {
        cmd.paramsCompiled = [];
        cmd.paramsCompiled[0] = Variable.splitDynamicText(cmd.params[2]);
        cmd.paramsCompiled[1] = Variable.splitDynamicText(cmd.params[5]);
    }
    CommandExecute.precompile_11 = precompile_11;
    function messageTitle11(cmd) {
        if (cmd.params[1]) {
            return "<span style='color:#cccccc;'>文本：</span><span><img src='" + cmd.params[1] + "' style='width:13px;height:13px' /></span>";
        }
        else {
            return "<span style='color:#cccccc;'>文本：</span>";
        }
    }
    CommandExecute.messageTitle11 = messageTitle11;
    function message11(cmd) {
        return "<span style='color:#cccccc;'><span>" + StringUtils.toHtmlEscape(StringUtils.clearHtmlTag(cmd.params[5])).replace(/\n/g, "</span><span>&nbsp;</span><br><span>      ") + "</span></span>";
    }
    CommandExecute.message11 = message11;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_12(commandPage, cmd, trigger, triggerPlayer, playerInput) {
        trigger.pause = true;
        trigger.offset(1);
        cmd.callClient(trigger.id, trigger.triggerPlayer, []);
    }
    CommandExecute.command_12 = command_12;
    function messageTitle12(cmd) {
        return "<span style='color:#008aff;'>等待玩家输入信息</span>";
    }
    CommandExecute.messageTitle12 = messageTitle12;
    function message12(cmd) {
        return "<span style='color:#cccccc;'></span>";
    }
    CommandExecute.message12 = message12;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_13(commandPage, cmd, trigger, triggerPlayer) {
        cmd.paramsCompiled[0].apply(this, arguments);
    }
    CommandExecute.command_13 = command_13;
    function precompile_13(commandPage, cmd, index) {
        var symbols = [null, "+", "-", "*", "/", "%"];
        var symbolsForArr = ["=", "+=", "-=", "*=", "/=", "%="];
        var resultSetTypes = [[0, "ServerWorld.setWorldVariable"], [0, "ServerWorld.setWorldSwitch"], [0, "ServerWorld.setWorldString"],
            [0, "triggerPlayer.variable.setVariable"], [0, "triggerPlayer.variable.setSwitch"], [0, "triggerPlayer.variable.setString"], [0, "CommandExecute.setSwitchs"]];
        var resultGetTypes = [[0, "ServerWorld.getWorldVariable"], [0, "ServerWorld.getWorldSwitch"], [0, "ServerWorld.getWorldString"],
            [0, "triggerPlayer.variable.getVariable"], [0, "triggerPlayer.variable.getSwitch"], [0, "triggerPlayer.variable.getString"], [0, "CommandExecute.getSwitchs"]];
        var resultType = cmd.params[0];
        var varID = cmd.params[1];
        var resultVar = resultSetTypes[resultType];
        var symbolType = symbols[cmd.params[2]];
        var valueType = cmd.params[3];
        var valueExpression;
        var value;
        var finalExpression;
        var secondParamCompiled = "";
        if (valueType == 0) {
            if (resultType == 2 || resultType == 5) {
                value = "Variable.margeDynamicText(cmd.paramsCompiled[1],triggerPlayer,trigger)";
                secondParamCompiled = ",Variable.splitDynamicText(cmd.params[4])";
            }
            else {
                value = cmd.params[4];
            }
        }
        else if (valueType == 1) {
            value = "ServerWorld.getWorldVariable(" + cmd.params[5] + ")";
        }
        else if (valueType == 2) {
            value = "triggerPlayer.variable.variables[" + cmd.params[6] + "]";
        }
        else if (valueType == 3) {
            value = "(MathUtils.rand(" + (cmd.params[7][1] - cmd.params[7][0]) + ")+" + cmd.params[7][0] + ")";
        }
        else {
            value = "CommandExecute.get_CommonlyUsed" + cmd.params[8] + "(commandPage,cmd,trigger,triggerPlayer)";
        }
        if (resultVar[0] == 0) {
            if (symbolType) {
                valueExpression = resultGetTypes[resultType][1] + ("(" + varID + ")") + symbolType + value;
            }
            else {
                valueExpression = value;
            }
            if (resultType == 6) {
                finalExpression = resultVar[1] + ("(" + varID + "," + valueExpression + "," + cmd.params[9] + ",trigger,triggerPlayer)");
            }
            else {
                finalExpression = resultVar[1] + ("(" + varID + "," + valueExpression + ")");
            }
        }
        else {
            if (symbolType) {
                valueExpression = value;
            }
            else {
                valueExpression = value;
            }
            finalExpression = resultVar[1] + ("[" + varID + "]" + symbolsForArr[cmd.params[2]] + valueExpression);
            if (cmd.params[2] == 4) {
                finalExpression += ";" + resultVar[1] + "[" + varID + "]=Math.floor(" + resultVar[1] + "[" + varID + "]);";
            }
        }
        var evalStr;
        evalStr = "cmd.paramsCompiled = [function(commandPage,cmd,trigger,triggerPlayer){" + finalExpression + ";}" + secondParamCompiled + "]";
        eval(evalStr);
    }
    CommandExecute.precompile_13 = precompile_13;
    function setSwitchs(index, value, id, trigger, triggerPlayer) {
        var targetSo = CommandExecute.getSceneObject(id, trigger, triggerPlayer);
        if (targetSo) {
            targetSo.setSwitchs(index, value);
        }
    }
    CommandExecute.setSwitchs = setSwitchs;
    function getSwitchs(index, id, trigger, triggerPlayer) {
        var targetSo = CommandExecute.getSceneObject(id, trigger, triggerPlayer);
        if (targetSo) {
            return targetSo.getSwitchs(index);
        }
        return null;
    }
    CommandExecute.getSwitchs = getSwitchs;
    function get_CommonlyUsed0(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getTime();
    }
    CommandExecute.get_CommonlyUsed0 = get_CommonlyUsed0;
    function get_CommonlyUsed1(commandPage, cmd, trigger, triggerPlayer) {
        return Math.floor(new Date().getTime() / 1000);
    }
    CommandExecute.get_CommonlyUsed1 = get_CommonlyUsed1;
    function get_CommonlyUsed2(commandPage, cmd, trigger, triggerPlayer) {
        return Math.floor(new Date().getTime() / 60000);
    }
    CommandExecute.get_CommonlyUsed2 = get_CommonlyUsed2;
    function get_CommonlyUsed3(commandPage, cmd, trigger, triggerPlayer) {
        return Math.floor(new Date().getTime() / 3600000);
    }
    CommandExecute.get_CommonlyUsed3 = get_CommonlyUsed3;
    function get_CommonlyUsed4(commandPage, cmd, trigger, triggerPlayer) {
        return Math.floor(new Date().getTime() / 86400000);
    }
    CommandExecute.get_CommonlyUsed4 = get_CommonlyUsed4;
    function get_CommonlyUsed5(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getSeconds();
    }
    CommandExecute.get_CommonlyUsed5 = get_CommonlyUsed5;
    function get_CommonlyUsed6(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getMinutes();
    }
    CommandExecute.get_CommonlyUsed6 = get_CommonlyUsed6;
    function get_CommonlyUsed7(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getHours();
    }
    CommandExecute.get_CommonlyUsed7 = get_CommonlyUsed7;
    function get_CommonlyUsed8(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getDay();
    }
    CommandExecute.get_CommonlyUsed8 = get_CommonlyUsed8;
    function get_CommonlyUsed9(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getDate();
    }
    CommandExecute.get_CommonlyUsed9 = get_CommonlyUsed9;
    function get_CommonlyUsed10(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getMonth() + 1;
    }
    CommandExecute.get_CommonlyUsed10 = get_CommonlyUsed10;
    function get_CommonlyUsed11(commandPage, cmd, trigger, triggerPlayer) {
        return new Date().getFullYear();
    }
    CommandExecute.get_CommonlyUsed11 = get_CommonlyUsed11;
    function get_CommonlyUsed12(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.scene.id;
    }
    CommandExecute.get_CommonlyUsed12 = get_CommonlyUsed12;
    function get_CommonlyUsed13(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.scene.sceneObjectCount;
    }
    CommandExecute.get_CommonlyUsed13 = get_CommonlyUsed13;
    function get_CommonlyUsed14(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.scene.playerCount;
    }
    CommandExecute.get_CommonlyUsed14 = get_CommonlyUsed14;
    function get_CommonlyUsed15(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.uid : -1;
    }
    CommandExecute.get_CommonlyUsed15 = get_CommonlyUsed15;
    function get_CommonlyUsed16(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.sceneObject.x : -1;
    }
    CommandExecute.get_CommonlyUsed16 = get_CommonlyUsed16;
    function get_CommonlyUsed17(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.sceneObject.y : -1;
    }
    CommandExecute.get_CommonlyUsed17 = get_CommonlyUsed17;
    function get_CommonlyUsed18(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? Math.floor(triggerPlayer.sceneObject.x / Config.SCENE_GRID_SIZE) : -1;
    }
    CommandExecute.get_CommonlyUsed18 = get_CommonlyUsed18;
    function get_CommonlyUsed19(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? Math.floor(triggerPlayer.sceneObject.y / Config.SCENE_GRID_SIZE) : -1;
    }
    CommandExecute.get_CommonlyUsed19 = get_CommonlyUsed19;
    function get_CommonlyUsed20(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.sceneObject.avatarID : 0;
    }
    CommandExecute.get_CommonlyUsed20 = get_CommonlyUsed20;
    function get_CommonlyUsed21(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.sceneObject.avatarOri : 0;
    }
    CommandExecute.get_CommonlyUsed21 = get_CommonlyUsed21;
    function get_CommonlyUsed22(commandPage, cmd, trigger, triggerPlayer) {
        return triggerPlayer ? triggerPlayer.sceneObject.speed : 0;
    }
    CommandExecute.get_CommonlyUsed22 = get_CommonlyUsed22;
    function get_CommonlyUsed23(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.inputMessage[0];
    }
    CommandExecute.get_CommonlyUsed23 = get_CommonlyUsed23;
    function get_CommonlyUsed24(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.inputMessage[1];
    }
    CommandExecute.get_CommonlyUsed24 = get_CommonlyUsed24;
    function get_CommonlyUsed25(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.inputMessage[2];
    }
    CommandExecute.get_CommonlyUsed25 = get_CommonlyUsed25;
    function get_CommonlyUsed26(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.inputMessage[3];
    }
    CommandExecute.get_CommonlyUsed26 = get_CommonlyUsed26;
    function get_CommonlyUsed27(commandPage, cmd, trigger, triggerPlayer) {
        return trigger.inputMessage[4];
    }
    CommandExecute.get_CommonlyUsed27 = get_CommonlyUsed27;
    function elseSetList() {
        return ["当前累计毫秒数", "当前累计秒数", "当前累计分钟数", "当前累计时数", "当前累计天数", "当前的秒(0~59)", "当前的分(0~59)", "当前的时(0~23)", "当前星期的天数(1~7)", "当前月的天数(1~N)", "当前的月份(1~12)", "当前的年份", "当前地图ID", "当前地图总场景对象数", "当前地图总玩家数", "玩家ID", "玩家对象的坐标x", "玩家对象的坐标y", "玩家对象的格子坐标x", "玩家对象的格子坐标y", "玩家对象的行走图ID", "玩家对象的面向", "玩家对象的移动速度", "玩家输入值-0", "玩家输入值-1", "玩家输入值-2", "玩家输入值-3", "玩家输入值-4"];
    }
    CommandExecute.elseSetList = elseSetList;
    function messageTitle13(cmd) {
        var varType = cmd.params[0];
        var varTypeNames = ["全局变量", "全局开关", "全局字符串", "玩家变量", "玩家开关", "玩家字符串", "NPC独立开关"];
        return "<span style='color:#da0808;'>" + varTypeNames[varType] + "操作：</span>";
    }
    CommandExecute.messageTitle13 = messageTitle13;
    function message13(cmd) {
        var varType = cmd.params[0];
        var typeDatas = [GameData.LIST_TYPE_VARIABLE, GameData.LIST_TYPE_SWITCH, GameData.LIST_TYPE_STRING, GameData.LIST_TYPE_PLAYER_VARIABLE, GameData.LIST_TYPE_PLAYER_SWITCH, GameData.LIST_TYPE_PLAYER_STRING];
        if (varType == 6) {
            return "<span style='color:#da0808;'>[" + String.fromCharCode(cmd.params[1] + 65) + "]=" + (cmd.params[4] == 1) + ",\u573A\u666F\u5BF9\u8C61id:" + cmd.params[9] + "</span>";
        }
        else {
            var valueType = cmd.params[3];
            var symbolType = [" = ", " += ", " -= ", " *= ", " /= ", " %= "][cmd.params[2]];
            var resName = "[" + (varType < 3 ? "G" : "") + MathUtils.fixIntDigit(cmd.params[1], 4) + "-" + GameListData.getName(Game.data[typeDatas[varType]], cmd.params[1]) + "]";
            if (valueType == 0) {
                var fixValue;
                if (varType == 1 || varType == 4 || varType == 6) {
                    fixValue = cmd.params[4] == 1 ? "ON" : "OFF";
                }
                else if (varType == 2 || varType == 5) {
                    fixValue = "\"" + StringUtils.toHtmlEscape(cmd.params[4]).replace(/\n/g, "↓") + "\"";
                }
                else {
                    fixValue = cmd.params[4];
                }
                return "<span style='color:#da0808;'>" + resName + symbolType + fixValue + "</span>";
            }
            else if (valueType == 1) {
                var valueName = "[G" + MathUtils.fixIntDigit(cmd.params[5], 4) + "-" + GameListData.getName(Game.data[typeDatas[0]], cmd.params[5]) + "]";
                return "<span style='color:#da0808;'>" + resName + symbolType + valueName + "</span>";
            }
            else if (valueType == 2) {
                var valueName = "[" + MathUtils.fixIntDigit(cmd.params[6], 4) + "-" + GameListData.getName(Game.data[typeDatas[3]], cmd.params[6]) + "]";
                return "<span style='color:#da0808;'>" + resName + symbolType + valueName + "</span>";
            }
            else if (valueType == 3) {
                return "<span style='color:#da0808;'>" + resName + symbolType + "[\u968F\u673A\u6570 " + cmd.params[7][0] + "~" + cmd.params[7][1] + "]</span>";
            }
            else {
                var sysArr = CommandExecute.elseSetList();
                return "<span style='color:#da0808;'>" + resName + symbolType + "[" + sysArr[cmd.params[8]] + "]</span>";
            }
        }
    }
    CommandExecute.message13 = message13;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_14(commandPage, cmd, trigger, triggerPlayer) {
        trigger.cmdReturn = true;
    }
    CommandExecute.command_14 = command_14;
    function messageTitle14(cmd) {
        return "<span style='color:#008aff;'>中断命令</span>";
    }
    CommandExecute.messageTitle14 = messageTitle14;
    function message14(cmd) {
        return "";
    }
    CommandExecute.message14 = message14;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_15(commandPage, cmd, trigger, triggerPlayer) {
    }
    CommandExecute.command_15 = command_15;
    function messageTitle15(cmd) {
        return "<span style='color:#008aff;'>消除对象</span>";
    }
    CommandExecute.messageTitle15 = messageTitle15;
    function message15(cmd) {
        return "";
    }
    CommandExecute.message15 = message15;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_16(commandPage, cmd, trigger, triggerPlayer) {
        var cmdPage = ServerWorld.commonEventPages[cmd.params[0]];
        if (!cmdPage)
            return;
        trigger.commandScope.push({ cmdPage: cmdPage, index: 0 });
    }
    CommandExecute.command_16 = command_16;
    function messageTitle16(cmd) {
        return "<span style='color:#008aff;'>\u8C03\u7528\u516C\u5171\u4E8B\u4EF6\uFF1A</span>";
    }
    CommandExecute.messageTitle16 = messageTitle16;
    function message16(cmd) {
        return "<span style='color:#008aff;'>[" + MathUtils.fixIntDigit(cmd.params[0], 4) + "\uFF1A" + GameListData.getName(Common.commonEventList, cmd.params[0]) + "]</span>";
    }
    CommandExecute.message16 = message16;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_17(commandPage, cmd, trigger, triggerPlayer) {
        if (cmd.params[2]) {
            cmd.callClient(trigger.id, triggerPlayer, cmd.params);
        }
        else {
            trigger.pause = true;
            trigger.offset(1);
            if (cmd.params[1] == 1) {
                setTimeout(CommandPage.executeEvent, cmd.params[0], trigger);
            }
            else {
                setFrameout(CommandPage.executeEvent, cmd.params[0], trigger);
            }
        }
    }
    CommandExecute.command_17 = command_17;
    function messageTitle17(cmd) {
        return "<span style='color:#008aff;'>\u7B49\u5F85\uFF1A</span>";
    }
    CommandExecute.messageTitle17 = messageTitle17;
    function message17(cmd) {
        var unit;
        if (cmd.params[1] == 1) {
            unit = "ms";
        }
        else {
            unit = "\u5E27\uFF0C\u7EA6" + Math.round(cmd.params[0] * 1000 / 60) + " ms";
        }
        return "<span style='color:#008aff;'>" + cmd.params[0] + " " + unit + (cmd.params[2] ? "（客户端模式）" : "") + "</span>";
    }
    CommandExecute.message17 = message17;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_18(commandPage, cmd, trigger, triggerPlayer) {
    }
    CommandExecute.command_18 = command_18;
    function messageTitle18(cmd) {
        return "<span style='color:#41ff33;'>注释：</span>";
    }
    CommandExecute.messageTitle18 = messageTitle18;
    function message18(cmd) {
        return "<span style='color:#41ff33;'>" + cmd.params[0].replace(/\n/g, "</span><span>&nbsp;</span><br><span></span><span style='color:#41ff33'>      ") + "</span>";
    }
    CommandExecute.message18 = message18;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_19(commandPage, cmd, trigger, triggerPlayer) {
        cmd.paramsCompiled[0].apply(this, arguments);
    }
    CommandExecute.command_19 = command_19;
    function precompile_19(commandPage, cmd, index) {
        if (Config.EDIT_MODE)
            return;
        var evalStr = "cmd.paramsCompiled = [function(commandPage,cmd,trigger,triggerPlayer){" + cmd.params[2] + ";}]";
        eval(evalStr);
    }
    CommandExecute.precompile_19 = precompile_19;
    function messageTitle19(cmd) {
        return "<span style='color:#8c8c8c;'>服务器脚本：</span>";
    }
    CommandExecute.messageTitle19 = messageTitle19;
    function message19(cmd) {
        return "<span style='color:#8c8c8c;'>" + (cmd.params[0] ? cmd.params[0] : "未命名脚本") + "</span>";
    }
    CommandExecute.message19 = message19;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_1(commandPage, cmd, trigger, triggerPlayer) {
        trigger.goto(cmd.gotoLine[0]);
    }
    CommandExecute.command_1 = command_1;
    function messageTitle1(cmd) {
        return "<span style='color:#008aff;'>否则</span>";
    }
    CommandExecute.messageTitle1 = messageTitle1;
    function message1(cmd) {
        return "";
    }
    CommandExecute.message1 = message1;
    function indentStart1() {
        return -1;
    }
    CommandExecute.indentStart1 = indentStart1;
    function indentEnd1() {
        return 1;
    }
    CommandExecute.indentEnd1 = indentEnd1;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_20(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer)
            cmd.callClient(trigger.id, triggerPlayer, [cmd.params[2]], "executeScript");
    }
    CommandExecute.command_20 = command_20;
    function messageTitle20(cmd) {
        return "<span style='color:#8c8c8c;'>客户端脚本：</span>";
    }
    CommandExecute.messageTitle20 = messageTitle20;
    function message20(cmd) {
        return "<span style='color:#8c8c8c;'>" + (cmd.params[0] ? cmd.params[0] : "未命名脚本") + "</span>";
    }
    CommandExecute.message20 = message20;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_21(commandPage, cmd, trigger, triggerPlayer) {
        trigger.cmdReturn = true;
        EventUtils.happen(triggerPlayer.sceneObject, ServerSceneObject.EVENT_NEED_STOP_BEHAVIOR, [2]);
        if (cmd.params[0]) {
            ServerGate.requestInScene(triggerPlayer.uid, triggerPlayer.variable.getVariable(cmd.params[1]), triggerPlayer.variable.getVariable(cmd.params[2]), triggerPlayer.variable.getVariable(cmd.params[3]), 0, triggerPlayer.loginSign);
        }
        else {
            ServerGate.requestInScene(triggerPlayer.uid, cmd.params[1], cmd.params[2], cmd.params[3], 0, triggerPlayer.loginSign);
        }
    }
    CommandExecute.command_21 = command_21;
    function messageTitle21(cmd) {
        return "<span style='color:#bd2c4b;'>场所移动：</span>";
    }
    CommandExecute.messageTitle21 = messageTitle21;
    function message21(cmd) {
        var sceneName = GameListData.getName(Game.data.sceneList, cmd.params[1]);
        return "<span style='color:#bd2c4b;'>[" + MathUtils.fixIntDigit(cmd.params[1].toString(), 3) + ":" + sceneName + "]:" + cmd.params[2] + "," + cmd.params[3] + "</span>";
    }
    CommandExecute.message21 = message21;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_22(commandPage, cmd, trigger, triggerPlayer) {
        var targetSo = CommandExecute.getSceneObject(cmd.params[0], trigger, triggerPlayer);
        if (!targetSo)
            return;
        var loop = cmd.params[1] == 1;
        var triggerPlayerSo;
        if (triggerPlayer) {
            triggerPlayerSo = triggerPlayer.sceneObject;
        }
        var cover = cmd.params[3] ? true : false;
        targetSo.addBehavior(cmd.params[2], loop, triggerPlayerSo, Callback.New(function (trigger, size) {
            trigger.removeBehaviorCount();
        }, this, [trigger, cmd.params[2].length]), cover);
        if (cover)
            trigger.clearBehaviorCount();
        trigger.addBehaviorCount();
    }
    CommandExecute.command_22 = command_22;
    function messageTitle22(cmd, sceneID, soNames) {
        return "<span style='color:#bd2c4b;'>对象行为：</span>";
    }
    CommandExecute.messageTitle22 = messageTitle22;
    function message22(cmd, sceneID, soNames) {
        var soName = CommandExecute.getSceneObjectNameInfo(cmd.params[0], sceneID, soNames);
        var loop = cmd.params[1] ? ",循环播放行为" : "";
        var cover = cmd.params[3] ? ",覆盖旧的行为" : "";
        var behaviorList = [];
        var behaviors = cmd.params[2];
        var behaviorInfos = "";
        var customBehaviorTypeList = Game.data.customBehaviorTypeList;
        for (var i in behaviors) {
            var behavior = behaviors[i];
            var behaviorText = CommandExecute.getBehaviorDescribe(behavior);
            behaviorInfos += "</span><span>&nbsp;</span><br><span></span><span style='color:#bd2c4b;'>&nbsp;--&nbsp;" + behaviorText;
        }
        return "<span style='color:#bd2c4b;'>" + soName + loop + cover + behaviorInfos + "</span>";
    }
    CommandExecute.message22 = message22;
    function getBehaviorDescribe(behavior) {
        var behaviorID = behavior[0];
        var customBehaviorTypeList = Game.data.customBehaviorTypeList;
        if (CommandExecute.behaviorInfo[behaviorID]) {
            var info = CommandExecute.behaviorInfo[behaviorID][0];
            if (CommandExecute.behaviorInfo[behaviorID][1]) {
                info += "：" + CommandExecute.behaviorInfo[behaviorID][1].apply(this, [behavior, behaviorID]);
            }
            return info;
        }
        else {
            var customBehaviorData = customBehaviorTypeList.data[behaviorID];
            if (!customBehaviorData) {
                return "--/--";
            }
            var name = GameListData.getName(customBehaviorTypeList, behaviorID);
            var behaviorText = name + ":";
            var attrs = CustomCompositeSetting.getAllAttributes(customBehaviorData, false);
            for (var s = 0; s < attrs.length; s++) {
                var varName = attrs[s].varName;
                behaviorText += varName + "=" + behavior[s + 1] + " ";
            }
            return behaviorText;
        }
    }
    CommandExecute.getBehaviorDescribe = getBehaviorDescribe;
    CommandExecute.behaviorInfo = {
        0: ["更换行走图", function (params) {
                var avatarID = params[1];
                var actID = params[2];
                var avatarName = GameListData.getName(Game.data.avatarList, avatarID);
                var actionName = GameListData.getName(Game.data.avatarActList, actID);
                return "\u3010" + avatarID + "-" + avatarName + "\u3011 \u3010" + actID + "-" + actionName + "\u3011 \u3010\u7B2C " + params[3] + " \u5E27\u3011";
            }]
    };
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_23(commandPage, cmd, trigger, triggerPlayer) {
        if (trigger.hasBehavior) {
            trigger.pause = true;
            trigger.offset(1);
            trigger.behaviorOverCallback = Callback.New(function (trigger) {
                CommandPage.executeEvent(trigger);
            }, CommandPage, [trigger]);
        }
    }
    CommandExecute.command_23 = command_23;
    function messageTitle23(cmd) {
        return "<span style='color:#bd2c4b;'>等待行为结束</span>";
    }
    CommandExecute.messageTitle23 = messageTitle23;
    function message23(cmd) {
        return "";
    }
    CommandExecute.message23 = message23;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function messageTitle2(cmd) {
        return "<span style='color:#008aff;'>分歧结束</span>";
    }
    CommandExecute.messageTitle2 = messageTitle2;
    function message2(cmd) {
        return "";
    }
    CommandExecute.message2 = message2;
    function indentStart2() {
        return -1;
    }
    CommandExecute.indentStart2 = indentStart2;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_31(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "shake");
        }
    }
    CommandExecute.command_31 = command_31;
    function messageTitle31(cmd) {
        if (cmd.params[1] == 0)
            return "<span style='color:#0070BB;'>停止画面震动</span>";
        return "<span style='color:#0070BB;'>画面震动：</span>";
    }
    CommandExecute.messageTitle31 = messageTitle31;
    function message31(cmd) {
        if (cmd.params[1] == 0)
            return "";
        return "<span style='color:#0070BB;'>\u9707\u52A8\u5F3A\u5EA6:" + cmd.params[0] + ",\u6301\u7EED\u65F6\u95F4:" + cmd.params[1] + "\u5E27</span>";
    }
    CommandExecute.message31 = message31;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_32(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "tonal");
        }
    }
    CommandExecute.command_32 = command_32;
    function messageTitle32(cmd) {
        if (cmd.params[0] == 0 && cmd.params[1] == 0 && cmd.params[2] == 0 && cmd.params[3] == 0 && cmd.params[5] == 1 && cmd.params[6] == 1 && cmd.params[7] == 1)
            return "<span style='color:#b97627;'>\u573A\u666F\u8272\u8C03\u6062\u590D\u6B63\u5E38\uFF1A" + cmd.params[4] + "\u5E27</span>";
        return "<span style='color:#b97627;'>更改画面色调：</span>";
    }
    CommandExecute.messageTitle32 = messageTitle32;
    function message32(cmd) {
        if (cmd.params[0] == 0 && cmd.params[1] == 0 && cmd.params[2] == 0 && cmd.params[3] == 0 && cmd.params[5] == 1 && cmd.params[6] == 1 && cmd.params[7] == 1)
            return "";
        return "<span style='color:#b97627;'>\u7EA2\u8272:" + cmd.params[0] + " \u7EFF\u8272:" + cmd.params[1] + " \u84DD\u8272:" + cmd.params[2] + " \u7070\u5EA6:" + cmd.params[3] + " \u66DD\u5149\uFF08" + Math.floor(cmd.params[5] * 100) + "% " + Math.floor(cmd.params[6] * 100) + "% " + Math.floor(cmd.params[7] * 100) + "%\uFF09 \u65F6\u95F4:" + cmd.params[4] + "\u5E27</span>";
    }
    CommandExecute.message32 = message32;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_35(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            var targetSo;
            if (cmd.params[0] == 1) {
                targetSo = CommandExecute.getSceneObject(cmd.params[3], trigger, triggerPlayer);
                if (!targetSo)
                    return;
            }
            var newParams = [cmd.params[0], cmd.params[1], cmd.params[2], targetSo ? targetSo.index : -3, cmd.params[4], cmd.params[5]];
            cmd.callClient(trigger.id, trigger.triggerPlayer, newParams, "cameraMove");
        }
    }
    CommandExecute.command_35 = command_35;
    function messageTitle35(cmd) {
        return "<span style='color:#b97627;'>移动镜头：</span>";
    }
    CommandExecute.messageTitle35 = messageTitle35;
    function message35(cmd, sceneID, soNames) {
        var str;
        if (cmd.params[0] == 1) {
            var soName = CommandExecute.getSceneObjectNameInfo(cmd.params[3], sceneID, soNames);
            str = "<span style='color:#b97627;'>\u9501\u5B9A\u5BF9\u8C61:" + soName;
        }
        else {
            str = "<span style='color:#b97627;'>\u79FB\u52A8\u81F3\u5750\u6807:" + cmd.params[1] + "," + cmd.params[2];
        }
        if (cmd.params[4]) {
            str += " 缓动模式";
        }
        str += " 时间:" + cmd.params[5] + "帧</span>";
        return str;
    }
    CommandExecute.message35 = message35;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_36(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "fogSet");
        }
    }
    CommandExecute.command_36 = command_36;
    function messageTitle36(cmd) {
        return "<span style='color:#b97627;'>变更雾显示：</span>";
    }
    CommandExecute.messageTitle36 = messageTitle36;
    function message36(cmd, sceneID, soNames) {
        return "<span style='color:#b97627;'>" + cmd.params[0].split("/").pop() + " " + cmd.params[1] * 100 + "% " + cmd.params[2] * 100 + "% \u6EDA\u52A8:" + cmd.params[3] + "," + cmd.params[4] + " \u900F\u660E\u5EA6:" + cmd.params[5] + " " + (cmd.params[6] == 1 ? "加法混合" : "") + "</span>";
    }
    CommandExecute.message36 = message36;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_37(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params);
        }
    }
    CommandExecute.command_37 = command_37;
    CommandExecute.imageInfo = {
        0: ["显示图片", function (param) {
                var url = param[2].split("/").pop();
                if (url == Editor.URL_UNKNOW_IMAGE)
                    url = "";
                var p = param.concat();
                p = p.splice(4, 5);
                return "\u3010" + param[1] + "\u3011 \"" + url + "\" " + (param[3] == 0 ? "左上角" : "中心点") + " (" + p + ") " + param[9] * 100 + "% " + (param[10] ? "加法" : "普通");
            }],
        1: ["移动图片", function (param) {
                var p = param.concat();
                p = p.splice(4, 5);
                return "\u3010" + param[1] + "\u3011 " + param[2] + "\u5E27 " + (param[3] == 0 ? "左上角" : "中心点") + " (" + p + ") " + param[9] * 100 + "% " + (param[10] ? "加法" : "普通") + " " + (!param[11] ? "" : "[" + GameUtils.getTween(param[11])[1] + "]");
            }],
        2: ["自动旋转", function (param) {
                return "\u3010" + param[1] + "\u3011 " + param[2] + " \u5EA6/\u5E27";
            }],
        3: ["更改色调", function (param) {
                var p = param.concat();
                p = p.splice(2, 4);
                return "\u3010" + param[1] + "\u3011" + param[6] + "\u5E27 \u7EA2=" + p[0] + " \u7EFF=" + p[1] + " \u84DD=" + p[2] + " \u7070=" + p[3] + " " + (!param[10] ? "" : "[" + GameUtils.getTween(param[10])[1] + "]");
            }],
        4: ["消除图片和动画", function (param) {
                return "\u3010" + param[1] + "\u3011";
            }],
        5: ["显示动画", function (param) {
                var id = param[2];
                var name = GameListData.getName(Common.animationList, id);
                var p = param.concat();
                p = p.splice(3, 5);
                return "\u3010" + param[1] + "\u3011 \"" + id + "-" + name + "\" (" + p + ") " + param[8] * 100 + "% " + (param[9] ? "[循环播放]" : "") + " \"[\u64AD\u653E\u5E27\u7387]-" + param[10] + "\" ";
            }],
        6: ["移动动画", function (param) {
                var p = param.concat();
                p = p.splice(3, 5);
                return "\u3010" + param[1] + "\u3011 " + param[2] + "\u5E27 (" + p + ") " + param[8] * 100 + "% " + (!param[9] ? "" : "[" + GameUtils.getTween(param[9])[1] + "]");
            }],
        7: null,
        8: ["等待", function (param) {
                return param[1] + " \u5E27";
            }],
    };
    function messageTitle37(cmd) {
        return "<span style='color:#bd2c4b;'>图像系统</span>";
    }
    CommandExecute.messageTitle37 = messageTitle37;
    function message37(cmd, sceneID, soNames) {
        var infos = "";
        var imageCmds = cmd.params[0];
        for (var i = 0; i < imageCmds.length; i++) {
            var imageCmd = imageCmds[i];
            var type = imageCmd[0];
            var info = "&nbsp;--&nbsp;" + CommandExecute.imageInfo[type][0] + "：" + CommandExecute.imageInfo[type][1](imageCmd);
            infos += "</span><span>&nbsp;</span><br><span></span><span style='color:#bd2c4b;'>" + info;
        }
        return "<span style='color:#b97627;'>" + infos + "</span>";
    }
    CommandExecute.message37 = message37;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_3(commandPage, cmd, trigger, triggerPlayer, playerInput) {
        if (!triggerPlayer)
            return;
        var params = cmd.params;
        if (playerInput.length == 0) {
            var selLen = params.length;
            var selContents = [];
            for (var i = 0; i < cmd.gotoLine.length; i++) {
                var selCmd = commandPage.commands[cmd.gotoLine[i] - 1];
                selContents.push(selCmd.params[0]);
            }
            cmd.callClient(trigger.id, trigger.triggerPlayer, [cmd.params[0], selContents]);
            EventUtils.happen(triggerPlayer.sceneObject, ServerSceneObject.EVENT_NEED_STOP_BEHAVIOR, [1]);
            trigger.pause = true;
        }
        else {
            var selIndex = playerInput[0];
            if (selIndex < 0 || selIndex >= cmd.gotoLine.length)
                return;
            trigger.goto(cmd.gotoLine[selIndex]);
        }
    }
    CommandExecute.command_3 = command_3;
    function precompile_3(commandPage, cmd, index) {
        var len = commandPage.commands.length;
        var indent = 0;
        var selArr = [];
        var firstSel = true;
        for (var i = index + 1; i < len; i++) {
            var targetCmd = commandPage.commands[i];
            if (!targetCmd)
                continue;
            if (targetCmd.type == 3) {
                indent++;
            }
            else if (indent == 0 && targetCmd.type == 4) {
                cmd.gotoLine.push(i + 1);
                selArr.push(targetCmd);
                targetCmd.link = targetCmd;
                if (!firstSel) {
                    targetCmd.insertable = true;
                }
                firstSel = false;
            }
            else if (targetCmd.type == 10) {
                if (indent == 0) {
                    for (var s = 0; s < selArr.length; s++) {
                        selArr[s].gotoLine.push(i + 1);
                    }
                    cmd.link = targetCmd;
                    targetCmd.link = targetCmd;
                    targetCmd.insertable = true;
                    break;
                }
                else {
                    indent--;
                }
            }
        }
    }
    CommandExecute.precompile_3 = precompile_3;
    function messageTitle3(cmd) {
        return "<span style='color:#bd2c85;'>显示对话选项</span>";
    }
    CommandExecute.messageTitle3 = messageTitle3;
    function message3(cmd) {
        return "";
    }
    CommandExecute.message3 = message3;
    function indentEnd3() {
        return 2;
    }
    CommandExecute.indentEnd3 = indentEnd3;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_4(commandPage, cmd, trigger, triggerPlayer) {
        trigger.goto(cmd.gotoLine[0]);
    }
    CommandExecute.command_4 = command_4;
    function messageTitle4(cmd) {
        return "<span style='color:#bd2c85;'></span>";
    }
    CommandExecute.messageTitle4 = messageTitle4;
    function message4(cmd) {
        return "<span style='color:#bd2c85;'>[" + cmd.params[0] + "] 的场合</span>";
    }
    CommandExecute.message4 = message4;
    function indentStart4() {
        return -1;
    }
    CommandExecute.indentStart4 = indentStart4;
    function indentEnd4() {
        return 1;
    }
    CommandExecute.indentEnd4 = indentEnd4;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function messageTitle5(cmd) {
        return "<span style='color:#008aff;'>循环</span>";
    }
    CommandExecute.messageTitle5 = messageTitle5;
    function message5(cmd) {
        return "";
    }
    CommandExecute.message5 = message5;
    function indentEnd5() {
        return 1;
    }
    CommandExecute.indentEnd5 = indentEnd5;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_63(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "playBGM");
        }
    }
    CommandExecute.command_63 = command_63;
    function messageTitle63(cmd) {
        return "<span style='color:#279cb9;'>播放背景音乐：</span>";
    }
    CommandExecute.messageTitle63 = messageTitle63;
    function message63(cmd) {
        var filename = cmd.params[0].split("/").pop();
        var fadeInStr = "";
        if (cmd.params[3] != 0) {
            fadeInStr = " 淡入:" + cmd.params[3] + "秒";
        }
        return "<span style='color:#279cb9;'>" + filename + " \u97F3\u91CF:" + cmd.params[1] + " \u97F3\u8C03:" + cmd.params[2] + fadeInStr + "</span>";
    }
    CommandExecute.message63 = message63;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_64(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "stopBGM");
        }
    }
    CommandExecute.command_64 = command_64;
    function messageTitle64(cmd) {
        return "<span style='color:#279cb9;'>停止播放背景音乐</span>";
    }
    CommandExecute.messageTitle64 = messageTitle64;
    function message64(cmd) {
        if (cmd.params[0] != 0) {
            return "<span style='color:#279cb9;'>：淡出" + cmd.params[0] + "秒</span>";
        }
        return "";
    }
    CommandExecute.message64 = message64;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_0(commandPage, cmd, trigger, triggerPlayer) {
        var bool;
        var params = cmd.params;
        switch (params[0]) {
            case 0:
                var value1 = getValue(params[1], params[2]);
                var value2 = getValue(params[4], params[5]);
                switch (params[3]) {
                    case 0:
                        bool = value1 === value2;
                        break;
                    case 1:
                        bool = value1 >= value2;
                        break;
                    case 2:
                        bool = (value1 > value2);
                        break;
                    case 3:
                        bool = (value1 <= value2);
                        break;
                    case 4:
                        bool = (value1 < value2);
                        break;
                    case 5:
                        bool = (value1 !== value2);
                        break;
                }
                break;
            case 1:
                switch (params[6]) {
                    case 0:
                        bool = ServerWorld.getWorldSwitch(params[7][0]) == (params[8] == 0 ? 1 : 0);
                        break;
                    case 1:
                        bool = trigger.triggerPlayer ? trigger.triggerPlayer.variable.getSwitch(params[7][1]) === (params[8] == 0 ? 1 : 0) : false;
                        break;
                    case 2:
                        var targetSo = CommandExecute.getSceneObject(params[7][2][0], trigger, triggerPlayer);
                        bool = targetSo ? (targetSo.getSwitchs(params[7][2][1]) === (params[8] == 0 ? 1 : 0)) : false;
                        break;
                }
                break;
            case 2:
                switch (params[9]) {
                    case 0:
                        bool = ServerWorld.getWorldString(params[10][0]) === params[11];
                        break;
                    case 1:
                        bool = trigger.triggerPlayer ? trigger.triggerPlayer.variable.getString(params[10][1]) === params[11] : false;
                        break;
                }
                break;
            case 3:
                bool = !!eval(params[14]);
                break;
        }
        if (!bool) {
            if (cmd.gotoLine[0] != null) {
                trigger.goto(cmd.gotoLine[0]);
            }
            else {
                trigger.goto(cmd.gotoLine[1]);
            }
        }
        return;
        function getValue(valueType, param) {
            switch (valueType) {
                case 0:
                    return param[0];
                case 1:
                    return ServerWorld.getWorldVariable(param[1]);
                case 2:
                    if (!trigger || !trigger.triggerPlayer)
                        return 0;
                    return trigger.triggerPlayer.variable.getVariable(param[2]);
                case 3:
                    return CommandExecute["get_CommonlyUsed" + param[3]](commandPage, cmd, trigger, triggerPlayer);
            }
        }
    }
    CommandExecute.command_0 = command_0;
    function precompile_0(commandPage, cmd, index) {
        var len = commandPage.commands.length;
        var indent = 0;
        var elseCmd;
        for (var i = index + 1; i < len; i++) {
            var targetCmd = commandPage.commands[i];
            if (!targetCmd)
                continue;
            if (targetCmd.type == 0) {
                indent++;
            }
            else if (indent == 0 && targetCmd.type == 1) {
                cmd.gotoLine[0] = (i + 1);
                elseCmd = targetCmd;
                elseCmd.link = elseCmd;
                elseCmd.insertable = true;
            }
            else if (targetCmd.type == 2) {
                if (indent == 0) {
                    if (elseCmd) {
                        elseCmd.gotoLine[0] = (i + 1);
                    }
                    cmd.gotoLine[1] = (i + 1);
                    cmd.link = targetCmd;
                    targetCmd.link = targetCmd;
                    targetCmd.insertable = true;
                    break;
                }
                else {
                    indent--;
                }
            }
        }
    }
    CommandExecute.precompile_0 = precompile_0;
    function messageTitle0(cmd) {
        return "<span style='color:#008aff;'>条件分歧：</span>";
    }
    CommandExecute.messageTitle0 = messageTitle0;
    function message0(cmd) {
        var str = "";
        switch (cmd.params[0]) {
            case 0:
                var types = [1, 4];
                var values = [2, 5];
                var varNames = [];
                for (var i = 0; i < types.length; i++) {
                    var varType = types[i];
                    var valueIndex = values[i];
                    switch (cmd.params[varType]) {
                        case 0:
                            varNames[i] = cmd.params[valueIndex][0];
                            break;
                        case 1:
                            varNames[i] = "[G" + MathUtils.fixIntDigit(cmd.params[valueIndex][1], 4) + "-" + GameListData.getName(Game.data.variableNameList, cmd.params[valueIndex][1]) + "]";
                            break;
                        case 2:
                            varNames[i] = "[" + MathUtils.fixIntDigit(cmd.params[valueIndex][2], 4) + "-" + GameListData.getName(Game.data.playerVariableNameList, cmd.params[valueIndex][2]) + "]";
                            break;
                        case 3:
                            var sysArr = CommandExecute.elseSetList();
                            varNames[i] = "[" + sysArr[cmd.params[valueIndex][3]] + "]";
                            break;
                    }
                }
                var symbolStr = ["==", "&#62;=", "&#62;", "&#60;=", "&#60;", "!="][cmd.params[3]];
                str = "变量比较：" + varNames[0] + " " + symbolStr + " " + varNames[1];
                break;
            case 1:
                var switchName;
                switch (cmd.params[6]) {
                    case 0:
                        switchName = "[G" + MathUtils.fixIntDigit(cmd.params[7][0], 4) + "-" + GameListData.getName(Game.data.switchNameList, cmd.params[7][0]) + "]";
                        break;
                    case 1:
                        switchName = "[" + MathUtils.fixIntDigit(cmd.params[7][1], 4) + "-" + GameListData.getName(Game.data.playerSwitchNameList, cmd.params[7][1]) + "]";
                        break;
                    case 2:
                        switchName = '对象' + cmd.params[7][2][0] + '开关' + ("[" + String.fromCharCode(cmd.params[7][2][1] + 65) + "]");
                        break;
                }
                str = "开关比较：" + switchName + " == " + (cmd.params[8] == 0 ? "ON" : "OFF");
                break;
            case 2:
                var stringName;
                switch (cmd.params[9]) {
                    case 0:
                        stringName = "[G" + MathUtils.fixIntDigit(cmd.params[10][0], 4) + "-" + GameListData.getName(Game.data.stringNameList, cmd.params[10][0]) + "]";
                        break;
                    case 1:
                        stringName = "[" + MathUtils.fixIntDigit(cmd.params[10][1], 4) + "-" + GameListData.getName(Game.data.playerStringNameList, cmd.params[10][1]) + "]";
                        break;
                }
                str = "字符串比较：" + stringName + " == \"" + StringUtils.toHtmlEscape(cmd.params[11]).replace(/\n/g, "↓") + "\"";
                break;
            case 3:
                str = "脚本：" + StringUtils.toHtmlEscape(cmd.params[12]).split("\n")[0];
                break;
        }
        return "<span style='color:#008aff;'>" + str + "</span>";
    }
    CommandExecute.message0 = message0;
    function indentEnd0() {
        return 1;
    }
    CommandExecute.indentEnd0 = indentEnd0;
    CommandExecute.shrink0 = true;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_65(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "playBGS");
        }
    }
    CommandExecute.command_65 = command_65;
    function messageTitle65(cmd) {
        return "<span style='color:#279cb9;'>播放环境音效：</span>";
    }
    CommandExecute.messageTitle65 = messageTitle65;
    function message65(cmd) {
        var filename = cmd.params[0].split("/").pop();
        var fadeInStr = "";
        if (cmd.params[3] != 0) {
            fadeInStr = " 淡入:" + cmd.params[3] + "秒";
        }
        return "<span style='color:#279cb9;'>" + filename + " \u97F3\u91CF:" + cmd.params[1] + " \u97F3\u8C03:" + cmd.params[2] + fadeInStr + "</span>";
    }
    CommandExecute.message65 = message65;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_1001(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            var parms = [cmd.params[0], cmd.params[1], cmd.params[2], cmd.params[3], cmd.params[4], cmd.params[5]];
            cmd.callClient(trigger.id, trigger.triggerPlayer, parms);
            if (cmd.params[6]) {
                trigger.pause = true;
                trigger.offset(1);
            }
        }
    }
    CommandExecute.command_1001 = command_1001;
    function messageTitle1001(cmd) {
        return "<span style='color:#0070BB;'>玩家转账：</span>";
    }
    CommandExecute.messageTitle1001 = messageTitle1001;
    function message1001(cmd) {
        return "<span style='color:#0070BB;'>\u540D\u79F0:" + cmd.params[0] + ",\u6536\u6B3E\u5730\u5740:" + cmd.params[1] + ",\u8D44\u4EA7\u7C7B\u522B:" + cmd.params[2] + ",\u8F6C\u8D26\u91D1\u989D:" + cmd.params[3] + ",\u8BA9\u73A9\u5BB6\u8F93\u5165\u91D1\u989D:" + cmd.params[4] + ",\u4E0D\u5141\u8BB8\u53D6\u6D88\u8F6C\u8D26:" + cmd.params[5] + "</span>";
    }
    CommandExecute.message1001 = message1001;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_66(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "stopBGS");
        }
    }
    CommandExecute.command_66 = command_66;
    function messageTitle66(cmd) {
        return "<span style='color:#279cb9;'>停止播放环境音效</span>";
    }
    CommandExecute.messageTitle66 = messageTitle66;
    function message66(cmd) {
        if (cmd.params[0] != 0) {
            return "<span style='color:#279cb9;'>：淡出" + cmd.params[0] + "秒</span>";
        }
        return "";
    }
    CommandExecute.message66 = message66;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_67(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, [-1].concat(cmd.params), "playSE");
        }
    }
    CommandExecute.command_67 = command_67;
    function messageTitle67(cmd) {
        return "<span style='color:#279cb9;'>播放音效：</span>";
    }
    CommandExecute.messageTitle67 = messageTitle67;
    function message67(cmd) {
        var filename = cmd.params[0].split("/").pop();
        return "<span style='color:#279cb9;'>" + filename + ",\u97F3\u91CF\uFF1A" + cmd.params[1] + ",\u97F3\u8C03\uFF1A" + cmd.params[2] + "</span>";
    }
    CommandExecute.message67 = message67;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_68(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "stopSE");
        }
    }
    CommandExecute.command_68 = command_68;
    function messageTitle68(cmd) {
        return "<span style='color:#279cb9;'>停止播放音效</span>";
    }
    CommandExecute.messageTitle68 = messageTitle68;
    function message68(cmd) {
        return "";
    }
    CommandExecute.message68 = message68;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_6(commandPage, cmd, trigger, triggerPlayer) {
        trigger.goto(cmd.gotoLine[0]);
    }
    CommandExecute.command_6 = command_6;
    function precompile_6(commandPage, cmd, index) {
        cmd.insertable = true;
        var len = commandPage.commands.length;
        var indent = 0;
        for (var i = index - 1; i >= 0; i--) {
            var targetCmd = commandPage.commands[i];
            if (!targetCmd)
                continue;
            if (targetCmd.type == 6) {
                indent++;
            }
            else if (indent == 0 && targetCmd.type == 7) {
                targetCmd.gotoLine.push(index + 1);
            }
            else if (targetCmd.type == 5) {
                if (indent == 0) {
                    cmd.gotoLine.push(i + 1);
                    targetCmd.link = cmd;
                    cmd.link = cmd;
                    break;
                }
                else {
                    indent--;
                }
            }
        }
    }
    CommandExecute.precompile_6 = precompile_6;
    function messageTitle6(cmd) {
        return "<span style='color:#008aff;'>以上反复</span>";
    }
    CommandExecute.messageTitle6 = messageTitle6;
    function message6(cmd) {
        return "";
    }
    CommandExecute.message6 = message6;
    function indentStart6() {
        return -1;
    }
    CommandExecute.indentStart6 = indentStart6;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_72(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "openUI");
        }
    }
    CommandExecute.command_72 = command_72;
    function messageTitle72(cmd) {
        return "<span style='color:#c7c11b;'>打开界面</span>";
    }
    CommandExecute.messageTitle72 = messageTitle72;
    function message72(cmd) {
        var uiName = GameListData.getName(Common.uiList, cmd.params[0]);
        return "<span style='color:#c7c11b;'>：" + cmd.params[0] + "-" + uiName + "</span>";
    }
    CommandExecute.message72 = message72;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_73(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            cmd.callClient(trigger.id, trigger.triggerPlayer, cmd.params, "closeUI");
        }
    }
    CommandExecute.command_73 = command_73;
    function messageTitle73(cmd) {
        return "<span style='color:#c7c11b;'>关闭界面</span>";
    }
    CommandExecute.messageTitle73 = messageTitle73;
    function message73(cmd) {
        var uiName = GameListData.getName(Common.uiList, cmd.params[0]);
        return "<span style='color:#c7c11b;'>：" + cmd.params[0] + "-" + uiName + "</span>";
    }
    CommandExecute.message73 = message73;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_7(commandPage, cmd, trigger, triggerPlayer) {
        if (cmd.gotoLine[0] != null)
            trigger.goto(cmd.gotoLine[0]);
    }
    CommandExecute.command_7 = command_7;
    function messageTitle7(cmd) {
        return "<span style='color:#008aff;'>中断循环</span>";
    }
    CommandExecute.messageTitle7 = messageTitle7;
    function message7(cmd) {
        return "";
    }
    CommandExecute.message7 = message7;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function messageTitle8(cmd) {
        return "<span style='color:#008aff;'>标签：</span>";
    }
    CommandExecute.messageTitle8 = messageTitle8;
    function message8(cmd) {
        return "<span style='color:#008aff;'>" + cmd.params[0] + "</span>";
    }
    CommandExecute.message8 = message8;
})(CommandExecute || (CommandExecute = {}));
var CommandExecute;
(function (CommandExecute) {
    function command_9(commandPage, cmd, trigger, triggerPlayer) {
        if (cmd.gotoLine[0] != null)
            trigger.goto(cmd.gotoLine[0]);
    }
    CommandExecute.command_9 = command_9;
    function precompile_9(commandPage, cmd, index) {
        var len = commandPage.commands.length;
        var indent = 0;
        for (var i = 0; i < len; i++) {
            var targetCmd = commandPage.commands[i];
            if (!targetCmd)
                continue;
            if (targetCmd.type == 8 && cmd.params[0] == targetCmd.params[0]) {
                cmd.gotoLine.push(i + 1);
                break;
            }
        }
    }
    CommandExecute.precompile_9 = precompile_9;
    function messageTitle9(cmd) {
        return "<span style='color:#008aff;'>跳转至标签：</span>";
    }
    CommandExecute.messageTitle9 = messageTitle9;
    function message9(cmd) {
        return "<span style='color:#008aff;'>" + cmd.params[0] + "</span>";
    }
    CommandExecute.message9 = message9;
})(CommandExecute || (CommandExecute = {}));
var CommandPage = (function () {
    function CommandPage(commandDatas) {
        this.commands = [];
        this.parse(commandDatas);
    }
    CommandPage.prototype.parse = function (commandDatas) {
        if (!commandDatas || commandDatas.length == 0)
            return;
        var len = commandDatas.length;
        var cmdType;
        for (var i = 0; i < len; i++) {
            var cmdData = commandDatas[i];
            cmdType = cmdData[0];
            var cmd = new Command(cmdType, cmdData.slice(1));
            this.commands.push(cmd);
        }
        for (var i = 0; i < len; i++) {
            var cmd = this.commands[i];
            cmdType = cmd.type;
            var executeMethod = CommandExecute["command_" + cmdType];
            if (executeMethod) {
                cmd.exeFunc = executeMethod;
            }
            else {
                cmd.exeFunc = CommandPage.blankMethod;
            }
            var precompileMethod = CommandExecute["precompile_" + cmdType];
            if (precompileMethod)
                precompileMethod(this, cmd, i);
        }
    };
    CommandPage.prototype.refreshPrecompile = function () {
        for (var i = 0; i < this.commands.length; i++) {
            var cmd = this.commands[i];
            if (!cmd)
                continue;
            cmd.gotoLine.length = 0;
            var precompileMethod = CommandExecute["precompile_" + cmd.type];
            if (precompileMethod)
                precompileMethod(this, cmd, i);
        }
    };
    CommandPage.prototype.startTriggerEvent = function (trigger, executor, playerInput) {
        if (playerInput === void 0) { playerInput = []; }
        if (trigger.isExecuteing)
            return;
        trigger.isExecuteing = true;
        trigger.commandScope.push({ cmdPage: this, index: 0 });
        trigger.executor = executor;
        EventUtils.happen(trigger, CommandTarget.EVENT_START);
        CommandPage.executeEvent(trigger, playerInput);
    };
    CommandPage.executeEvent = function (trigger, playerInput) {
        if (playerInput === void 0) { playerInput = []; }
        trigger.inputMessage = playerInput;
        var triggerPlayer = trigger.triggerPlayer;
        if (trigger.trigger && trigger.trigger.playerUID && !triggerPlayer) {
            trigger.dispose();
            return;
        }
        while (1) {
            var len = trigger.commandScope.length;
            if (len == 0) {
                EventUtils.happen(trigger, CommandTarget.EVENT_OVER);
                if (trigger.multiline) {
                    trigger.dispose();
                }
                trigger.isExecuteing = false;
                break;
            }
            var commandScope = trigger.commandScope[len - 1];
            var cmdPage = commandScope.cmdPage;
            if (commandScope.index == cmdPage.commands.length) {
                trigger.commandScope.pop();
                continue;
            }
            if (trigger.executor.isDisposed) {
                trigger.commandScope.length = 0;
                continue;
            }
            var cmd = cmdPage.commands[commandScope.index];
            cmd.exeFunc(cmdPage, cmd, trigger, triggerPlayer, playerInput);
            playerInput = [];
            if (trigger.pause) {
                trigger.pause = false;
                break;
            }
            if (trigger.cmdReturn) {
                trigger.cmdReturn = false;
                trigger.commandScope.pop();
                continue;
            }
            commandScope.index++;
        }
    };
    CommandPage.blankMethod = new Function();
    return CommandPage;
}());





var ServerPlayer = (function (_super) {
    __extends(ServerPlayer, _super);
    function ServerPlayer(key, uid) {
        _super.call(this, ServerPlayerData);
        this.varListens = [[], [], []];
        this.loginSign = 0;
        this.controlEnabled = true;
        this.saveVariables = true;
        this.key = key;
        this.uid = uid;
        if (ServerThread.threadID == 2) {
            this.sqlVar = new Variable();
        }
    }
    ServerPlayer.prototype.dataInit = function () {
        this.data.sceneObject.playerUID = this.uid;
    };
    ServerPlayer.prototype.toScene = function (sceneID, x, y) {
        if (x === void 0) { x = 0; }
        if (y === void 0) { y = 0; }
        if (ServerThread.threadID == 2)
            return;
        ServerGate.requestInScene(this.uid, sceneID, x, y, 0, this.loginSign);
    };
    ServerPlayer.prototype.execCommonCommand = function (commandID, inputMessage, fromClient) {
        if (fromClient === void 0) { fromClient = false; }
        if (!this.scene)
            return;
        var commonEvCmd = ServerWorld.getClientCallWorldEvent(commandID, fromClient);
        if (commonEvCmd) {
            var trigger = new CommandTarget(CommandTarget.COMMAND_MAIN_TYPE_CALL_COMMON_EVENT, 0, this.scene, this.sceneObject, true);
            commonEvCmd.startTriggerEvent(trigger, this.sceneObject, inputMessage);
            return trigger;
        }
    };
    ServerPlayer.changePlayerData = function (uid, func, args, onFin, useVariables) {
        if (args === void 0) { args = []; }
        if (onFin === void 0) { onFin = null; }
        if (useVariables === void 0) { useVariables = true; }
        if (ServerThread.threadID != 2) {
            var player = ServerPlayer.getPlayerByUID(uid);
            if (player) {
                var v = func.apply(func, [player].concat(args));
                onFin && onFin.runWith([v]);
            }
            else {
                var funcCode = func.toString();
                ServerThread.callFunction(2, "ServerPlayer", "doChangePlayerData", [uid, funcCode, useVariables, args], onFin);
            }
        }
    };
    ServerPlayer.doChangePlayerData = function (uid, funcCode, useVariables, args) {
        var sqlUsers = SQLUtils.query("user", "sceneID,data", "where id=" + uid + " limit 0,1");
        if (sqlUsers.length == 0)
            return;
        var userObj = sqlUsers[0];
        var sqlPlayerData = JSON.parse(userObj.data);
        var player = new ServerPlayer(null, uid);
        if (useVariables) {
            var readSqlArr = [
                ["playervariable", "variables"], ["playerswitch", "switchs"], ["playerstring", "strings"]
            ];
            for (var s in readSqlArr) {
                var sqlVariables = SQLUtils.query(readSqlArr[s][0], "varID,varValue", "where uid=" + player.uid);
                for (var i = 0; i < sqlVariables.length; i++) {
                    var varTypeName = readSqlArr[s][1];
                    var varSqlData = sqlVariables[i];
                    player.variable[varTypeName][varSqlData.varID] = varSqlData.varValue;
                    player.sqlVar[varTypeName][varSqlData.varID] = true;
                }
            }
        }
        player.saveVariables = useVariables;
        player.sceneID = userObj.sceneID;
        player.installPlayerData(sqlPlayerData, true);
        player.dataInit();
        globalThis.__tempPlayerFuncArgs = [player].concat(args);
        try {
            var v = globalThis.eval("(" + funcCode + ").apply(this,globalThis.__tempPlayerFuncArgs);");
        }
        catch (e) {
            traceError(e);
        }
        ServerSql.savePlayer(player, player.loginSign, true);
        return v;
    };
    ServerPlayer.prototype.clientListenerVarEnabled = function (type, varID, isListen) {
        var varArr = this.varListens[type];
        if (isListen)
            varArr[varID] = true;
        else
            delete varArr[varID];
    };
    ServerPlayer.prototype.onVarChange = function (type, varID, value) {
        var varArr = this.varListens[type];
        if (varArr[varID]) {
            ServerMsgSender.rpc(this, "ClientPlayer", "playerVariableChange", [type, varID, value]);
        }
        ServerSql.addPlayerVariableToSaveList(this.uid, type, varID, value);
    };
    ServerPlayer.getPlayer = function (key) {
        return ServerPlayer.playerList[key];
    };
    ServerPlayer.getPlayerByUID = function (uid) {
        return ServerPlayer.playerIDList[uid];
    };
    ServerPlayer.addPlayer = function (key, uid) {
        var p = ServerPlayer.playerList[key] = new ServerPlayer(key, uid);
        ServerPlayer.playerIDList[uid] = p;
        return p;
    };
    ServerPlayer.removePlayer = function (key) {
        var player = ServerPlayer.playerList[key];
        if (player) {
            delete ServerPlayer.playerList[key];
            delete ServerPlayer.playerIDList[player.uid];
        }
        return player;
    };
    ServerPlayer.onHandleMsg = function (key, msgContent) {
        var player = ServerPlayer.getPlayer(key);
        if (!player)
            return;
        var msgType = msgContent.substr(0, 1);
        if (msgType == "0") {
            EventUtils.happen(ServerPlayer, ServerPlayer.EVENT_PLAYER_MESSAGE, [player, msgContent.substr(1)]);
        }
        else {
            var msgObj = JSON.parse(msgContent.substr(1));
            var classFunc = ServerWorld.getServerFunction(msgObj.c, msgObj.f);
            if (classFunc) {
                var returnMsg = classFunc.func.apply(classFunc.class, [player].concat(msgObj.p));
                if (msgObj.r != 0) {
                    ServerMsgSender.rpc(player, "ClientMsgSender", "rpcReturn", [1, msgObj.r, returnMsg]);
                }
            }
            else {
                trace("T-" + kdsrpg_scriptID + ":", "找不到方法！", msgObj.c, msgObj.f);
                if (msgObj.r != 0) {
                    ServerMsgSender.rpc(player, "ClientMsgSender", "rpcReturn", [0, msgObj.r, null, msgObj.c, msgObj.f]);
                }
            }
        }
    };
    Object.defineProperty(ServerPlayer.prototype, "sceneObject", {
        get: function () {
            return this.data.sceneObject;
        },
        enumerable: true,
        configurable: true
    });
    ServerPlayer.prototype.getTransportableData = function () {
        var o = {
            key: this.key,
            uid: this.uid,
            data: this.data.getTransportableData(),
            variable: this.variable.getTransportableData(),
            varListens: this.varListens,
            sceneID: this.sceneID,
            threadID: this.threadID,
            loginSign: this.loginSign,
            useThreadSceneData: this.useThreadSceneData
        };
        return o;
    };
    ServerPlayer.prototype.syncClientData = function (syncSelf) {
        var o = {
            uid: this.uid,
            data: this.data.getTransportableData(false, syncSelf)
        };
        return o;
    };
    ServerPlayer.prototype.installFromTransportableData = function (playerDataObj) {
        var playerdata = playerDataObj.data;
        delete playerDataObj.data;
        ObjectUtils.assignment(this, playerDataObj);
        this.installPlayerData(playerdata);
    };
    ServerPlayer.prototype.installPlayerData = function (playerdata, formatPlayerData) {
        if (playerdata === void 0) { playerdata = null; }
        if (formatPlayerData === void 0) { formatPlayerData = false; }
        if (playerdata) {
            this.data.sceneObject = ServerSceneObject.create(playerdata.sceneObject, null, this, true);
            if (!formatPlayerData) {
                for (var i in playerdata) {
                    if (i == "sceneObject")
                        continue;
                    this.data[i] = playerdata[i];
                }
                for (var i in playerdata.sceneObject) {
                    this.data.sceneObject[i] = playerdata.sceneObject[i];
                }
            }
            else {
                var playerModelData = Common.customGameAttribute.playerAttributeSetting;
                this.data.installFilePlayerData(this, playerdata);
            }
        }
        else {
            this.data.installDefaultPlayerData(this);
        }
    };
    ServerPlayer.EVENT_PLAYER_LOGIN = "ServerPlayer_EVENT_PLAYER_LOGIN";
    ServerPlayer.EVENT_PLAYER_DISPLACEMENT = "ServerPlayer_EVENT_PLAYER_DISPLACEMENT";
    ServerPlayer.EVENT_PLAYER_LOGOUT = "ServerPlayer_EVENT_PLAYER_LOGOUT";
    ServerPlayer.EVENT_PLAYER_MESSAGE = "ServerPlayer_EVENT_PLAYER_MESSAGE";
    ServerPlayer.playerList = {};
    ServerPlayer.playerIDList = [];
    return ServerPlayer;
}(Player));
var ServerPlayerData = (function () {
    function ServerPlayerData() {
    }
    ServerPlayerData.prototype.installDefaultPlayerData = function (player, initSceneObject) {
        if (initSceneObject === void 0) { initSceneObject = true; }
        if (initSceneObject)
            this.sceneObject = ServerSceneObject.create(ServerConfig.BORN.so, ServerConfig.BORN.customAttribute, player, true);
        var customGameAttribute = ServerWorld.gameData.customGameAttribute;
        var attrSettings = CustomCompositeSetting.getAllAttributes(customGameAttribute.playerAttributeSetting, false);
        CustomAttributeSetting.installAttributeFromEditorSet(this, customGameAttribute.playerAttributeConfig.attrs, attrSettings, false, false, GameData.CUSTOM_ATTR_PLAYER_DATA);
    };
    ServerPlayerData.prototype.installFilePlayerData = function (player, fileData) {
        this.installDefaultPlayerData(player, false);
        var fileSceneObjectData = fileData.sceneObject;
        delete fileData.sceneObject;
        var customGameAttribute = ServerWorld.gameData.customGameAttribute;
        var attrSettings = CustomCompositeSetting.getAllAttributes(customGameAttribute.playerAttributeSetting, false);
        CustomAttributeSetting.installAttributeFromRecordData(this, fileData, attrSettings);
        var modelData = ServerWorld.gameData.sceneObjectModelList.data[this.sceneObject.modelID];
        if (modelData) {
            CustomAttributeSetting.installAttributeFromRecordData(this.sceneObject, fileSceneObjectData, modelData.varAttributes);
        }
    };
    ServerPlayerData.prototype.getTransportableData = function (allAttributes, syncSelf) {
        if (allAttributes === void 0) { allAttributes = true; }
        if (syncSelf === void 0) { syncSelf = true; }
        var tData = {};
        if (allAttributes) {
            tData.sceneObject = this.sceneObject.getTransportableData();
        }
        var customGameAttribute = ServerWorld.gameData.customGameAttribute;
        var attrSettings = CustomCompositeSetting.getAllAttributes(customGameAttribute.playerAttributeSetting, false);
        for (var i in attrSettings) {
            var customAttributeSetting = attrSettings[i];
            if (!allAttributes && (customAttributeSetting.accessMode === 0 || customAttributeSetting.syncMode === 0 ||
                (!syncSelf && customAttributeSetting.syncMode === 2)))
                continue;
            var varName = attrSettings[i].varName;
            tData[varName] = this[varName];
        }
        return tData;
    };
    return ServerPlayerData;
}());
var Command = (function () {
    function Command(type, params) {
        this.gotoLine = [];
        this.type = type;
        this.params = params;
    }
    Command.prototype.callClient = function (triggerLineID, player, params, gameFunc) {
        if (gameFunc === void 0) { gameFunc = null; }
        var p = gameFunc ? [gameFunc].concat(params) : params;
        ServerMsgSender.rpc(player, "GameCommand", "rpcCall", [triggerLineID, [this.type].concat(p)]);
    };
    return Command;
}());
var CommandExecute;
(function (CommandExecute) {
    function getSceneObjectNameInfo(soIndex, sceneID, soNames) {
        var soID = soIndex >= 0 ? soIndex + "-" : "";
        var soName;
        if (soIndex < 0) {
            soName = (soIndex == -2 ? "玩家对象" : "当前对象");
        }
        else {
            if (sceneID) {
                soName = (soIndex + 1) + "-" + (soNames[soIndex] ? soNames[soIndex] : "SceneObject");
            }
            else {
                soName = (soIndex + 1) + "-场景对象";
            }
        }
        return soName;
    }
    CommandExecute.getSceneObjectNameInfo = getSceneObjectNameInfo;
    function getSceneObject(soIndex, trigger, triggerPlayer) {
        var targetSo;
        if (soIndex == -2) {
            if (triggerPlayer)
                targetSo = triggerPlayer.sceneObject;
        }
        else if (soIndex == -1) {
            targetSo = trigger.executor;
        }
        else {
            targetSo = trigger.scene.sceneObjects[soIndex];
        }
        return targetSo;
    }
    CommandExecute.getSceneObject = getSceneObject;
})(CommandExecute || (CommandExecute = {}));





var ServerScene = (function (_super) {
    __extends(ServerScene, _super);
    function ServerScene() {
        _super.call(this);
        this.playerMap = {};
        this.playerCount = 0;
        this.sceneObjectCount = 0;
        this.customCommandPages = [];
    }
    ServerScene.init = function (onFin) {
        ServerScene.loadSceneData(onFin);
    };
    ServerScene.createScene = function (dataID, copyMode) {
        if (copyMode === void 0) { copyMode = false; }
        if (copyMode) {
            var copySceneID = (ServerScene.COPY_SCENE_ID_START + ServerScene.COPY_SCENE_ID_INC++) * ServerConfig.SCENE_FIXED_THREAD_COUNT + ServerThread.threadID - 3;
            trace("创建模型ID=", dataID, "副本ID=", copySceneID, "所属线程=", copySceneID % ServerConfig.SCENE_FIXED_THREAD_COUNT + 3);
        }
        var sceneData = ServerWorld.gameData.sceneList.data[dataID];
        var cls = sceneData.mapData.serverInstanceClassName;
        var classImpl = globalThis[cls];
        var scene = (classImpl && classImpl.prototype instanceof ServerScene) ? new classImpl : new ServerScene();
        Scene.parse(sceneData.mapData, scene, ServerWorld.gameData);
        scene.modelID = scene.id;
        if (copyMode) {
            ServerScene.sceneCopys[copySceneID] = scene;
            scene.id = copySceneID;
            trace("存在的副本===", copySceneID, ServerScene.sceneCopys[copySceneID]);
        }
        else {
            ServerScene.scenes[scene.id] = scene;
        }
        var sceneObjDatas = sceneData.sceneObjectData;
        var sceneObjects = sceneObjDatas.sceneObjects;
        var len = sceneObjects.length;
        for (var i = 0; i < len; i++) {
            var soObj = sceneObjects[i];
            if (!soObj)
                continue;
            var preSo = ServerSceneObject.clone(scene.modelID, i, scene, false);
            preSo.index = i;
            scene.sceneObjects[i] = preSo;
        }
        for (var s in sceneObjDatas.customCommands) {
            var commands = sceneObjDatas.customCommands[s];
            if (commands == null)
                continue;
            scene.customCommandPages[s] = new CommandPage(commands);
        }
        scene["customCommands"] = null;
        return scene.id;
    };
    ServerScene.installNpcSwitch = function (sceneID, switchInfo) {
        var scene = ServerScene.getScene(sceneID);
        if (!scene)
            return;
        for (var index in switchInfo) {
            var npc = scene.sceneObjects[index];
            if (!npc)
                continue;
            var npcSwitchs = switchInfo[index];
            for (var varID in npcSwitchs) {
                npc.setSwitchs(parseInt(varID), npcSwitchs[varID], false);
            }
            npc["refreshDisappearStatus"]();
        }
    };
    ServerScene.getScene = function (sceneID) {
        if (sceneID < ServerScene.COPY_SCENE_ID_START) {
            return ServerScene.scenes[sceneID];
        }
        else {
            return ServerScene.sceneCopys[sceneID];
        }
    };
    ServerScene.prototype.update = function (now) {
    };
    ServerScene.prototype.dispose = function () {
        if (this.isCopy) {
            if (this.playerCount != 0)
                return;
            delete ServerScene.sceneCopys[this.id];
            for (var i in this) {
                this[i] = null;
            }
            this.isDisposed = true;
        }
    };
    Object.defineProperty(ServerScene.prototype, "isCopy", {
        get: function () {
            return this.id != this.modelID;
        },
        enumerable: true,
        configurable: true
    });
    ServerScene.prototype.readyInScene = function (player) {
        ServerMsgSender.eval(player, "ClientMsgSender.threadID=" + ServerThread.getSceneThread(this.id) + ";");
    };
    ServerScene.prototype.addPlayer = function (player) {
        var lastPlayer = this.playerMap[player.uid];
        if (lastPlayer) {
            this.removeSceneObject(lastPlayer.data.sceneObject, true, true);
        }
        this.playerMap[player.uid] = player;
        player.scene = this;
        this.addSceneObject(player.data.sceneObject);
        this.playerCount++;
    };
    ServerScene.prototype.removePlayer = function (player) {
        var scenePlayer = this.playerMap[player.uid];
        if (scenePlayer) {
            this.removeSceneObject(player.data.sceneObject);
            player.scene = null;
            delete this.playerMap[player.uid];
            this.playerCount--;
        }
    };
    ServerScene.prototype.getPlayer = function (uid) {
        return this.playerMap[uid];
    };
    ServerScene.prototype.addSceneObject = function (so, addToList) {
        if (addToList === void 0) { addToList = true; }
        so.scene = this;
        if (so.playerUID)
            so.initPlayer();
        if (addToList)
            so.index = ArrayUtils.insertToNullPosition(this.sceneObjects, so);
        so.inScene = true;
        this.sceneObjectCount++;
    };
    ServerScene.prototype.removeSceneObject = function (so, removeFromList, force) {
        if (removeFromList === void 0) { removeFromList = true; }
        if (force === void 0) { force = false; }
        if (force || this.sceneObjects[so.index] == so) {
            if (removeFromList)
                this.sceneObjects[so.index] = null;
            so.inScene = false;
            this.sceneObjectCount--;
            return true;
        }
        return false;
    };
    ServerScene.loadSceneData = function (onFin) {
        if (ServerThread.threadID == 2) {
            onFin.run();
            return;
        }
        ServerWorld.gameData.loadSceneList(Callback.New(function () {
            for (var i in ServerWorld.gameData.sceneList.data) {
                var id = parseInt(i);
                if (ServerThread.getSceneThread(id) == ServerThread.threadID) {
                    var sceneData = ServerWorld.gameData.sceneList.data[id];
                    ServerScene.createScene(id, false);
                }
            }
            onFin.run();
        }, this, []), function (id) {
            return true;
        });
    };
    ServerScene.COPY_SCENE_ID_START = 10000000;
    ServerScene.COPY_SCENE_ID_INC = 0;
    ServerScene.COPY_SCENE_KEY = "ServerSceneCopyID";
    ServerScene.scenes = [];
    ServerScene.sceneCopys = [];
    return ServerScene;
}(Scene));
var CommandExecute;
(function (CommandExecute) {
    function command_1002(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            var parms = [cmd.params[0], cmd.params[1], cmd.params[2], cmd.params[3], cmd.params[4]];
            cmd.callClient(trigger.id, trigger.triggerPlayer, parms);
            if (cmd.params[5]) {
                trigger.pause = true;
                trigger.offset(1);
            }
        }
    }
    CommandExecute.command_1002 = command_1002;
    function messageTitle1002(cmd) {
        return "<span style='color:#0070BB;'>调用合约：</span>";
    }
    CommandExecute.messageTitle1002 = messageTitle1002;
    function message1002(cmd) {
        return "<span style='color:#0070BB;'>\u540D\u79F0:" + cmd.params[0] + ",\u5408\u7EA6\u5730\u5740:" + cmd.params[1] + ",\u8C03\u7528\u65B9\u6CD5:" + cmd.params[2] + ",\u4E0D\u5141\u8BB8\u53D6\u6D88\u8C03\u7528:" + cmd.params[4] + "</span>";
    }
    CommandExecute.message1002 = message1002;
})(CommandExecute || (CommandExecute = {}));
var ServerWorld = (function () {
    function ServerWorld() {
    }
    Object.defineProperty(ServerWorld, "isStop", {
        get: function () { return this._isStop; },
        enumerable: true,
        configurable: true
    });
    ServerWorld.close = function (onFin) {
        if (onFin === void 0) { onFin = null; }
        if (ServerThread.threadID != 2) {
            ServerThread.callFunction(2, "ServerWorld", "close", []);
            return;
        }
        ServerWorld.isOpenGate = false;
        this._isStop = true;
        ServerThread.syncCode("ServerWorld._isStop=true;", true);
        for (var key in ServerPlayer.playerList) {
            var p = ServerPlayer.playerList[key];
            websocket_kickOffLine(p.key);
        }
        ServerSql.save(Callback.New(function () {
            onFin && onFin.run();
            closeServer(getPID());
        }, this));
    };
    ServerWorld.restart = function () {
        if (ServerThread.threadID != 2) {
            ServerThread.callFunction(2, "ServerWorld", "restart", []);
            return;
        }
        this.close(Callback.New(function () {
        }, this));
    };
    ServerWorld.kickPlayer = function (uid) {
        if (ServerThread.threadID != 2) {
            ServerThread.callFunction(2, "ServerWorld", "kickPlayer", [uid]);
            return;
        }
        var player = ServerPlayer.getPlayerByUID(uid);
        if (player) {
            websocket_kickOffLine(player.key);
            ServerGate.onLogout(player.key);
        }
    };
    ServerWorld.addPlayerToBlackList = function (uid) {
    };
    ServerWorld.removePlayerToBlackList = function (uid) {
    };
    ServerWorld.addServerFunction = function (classDomain, functionName) {
        if (functionName === void 0) { functionName = null; }
        var classObj = globalThis[classDomain];
        if (functionName == null) {
            if (classObj) {
                for (var i in classObj) {
                    var funcObj = classObj[i];
                    if (typeof funcObj == "function") {
                        var key = classDomain + "_" + i;
                        ServerWorld.serverFuncs[key] = { class: classObj, func: funcObj };
                    }
                }
            }
            return;
        }
        var key = classDomain + "_" + functionName;
        if (classObj) {
            var funcObj = classObj[functionName];
            if (!functionName || (funcObj && typeof funcObj == "function")) {
                ServerWorld.serverFuncs[key] = { class: classObj, func: funcObj };
            }
        }
    };
    ServerWorld.getServerFunction = function (classDomain, functionName) {
        var key = classDomain + "_" + functionName;
        return ServerWorld.serverFuncs[key];
    };
    ServerWorld.dataWrite = function (func, args) {
        var funcCode = func.toString();
        var ___arrSyncFuncIndex = func["___arrSyncFuncIndex"];
        if (func["___arrSyncFuncIndex"] == null) {
            ___arrSyncFuncIndex = func["___arrSyncFuncIndex"] = ++ServerMain.arrSyncFuncIndex;
            var newFuncCode = "ServerMain.__sa" + ServerMain.arrSyncFuncIndex + " = " + funcCode;
            globalThis.eval(newFuncCode);
            ServerThread.callAllThreadFunction("globalThis", "eval", [newFuncCode], true);
        }
        func.apply(func, args);
        ServerThread.callAllThreadFunction("ServerMain", "__sa" + ___arrSyncFuncIndex, args, true);
    };
    ServerWorld.update = function (now) {
        var sceneLen = ServerScene.scenes.length;
        for (var s = 0; s < sceneLen; s++) {
            var scene = ServerScene.scenes[s];
            if (scene)
                scene.update(now);
        }
        for (var i in ServerScene.sceneCopys) {
            ServerScene.sceneCopys[i].update(now);
        }
    };
    ServerWorld.setWorldVariableAccessible = function (type, index, accessible) {
        this.accessibles[type][index] = accessible;
    };
    ServerWorld.getWorldVariableAccessible = function (type, index) {
        return this.accessibles[type][index];
    };
    ServerWorld.setWorldVariable = function (index, value, isNotice) {
        if (isNotice === void 0) { isNotice = true; }
        setGlobalValue("v" + index, value.toString());
        if (isNotice)
            ServerWorld.noticeChange(0, index, value);
    };
    ServerWorld.getWorldVariable = function (index) {
        var v = parseInt(getGlobalValue("v" + index));
        return isNaN(v) ? 0 : v;
    };
    ServerWorld.setWorldSwitch = function (index, value, isNotice) {
        if (isNotice === void 0) { isNotice = true; }
        setGlobalValue("w" + index, value ? "1" : "0");
        if (isNotice)
            ServerWorld.noticeChange(1, index, value);
    };
    ServerWorld.getWorldSwitch = function (index) {
        var v = parseInt(getGlobalValue("w" + index));
        return isNaN(v) ? 0 : v;
    };
    ServerWorld.setWorldString = function (index, value, isNotice) {
        if (isNotice === void 0) { isNotice = true; }
        setGlobalValue("s" + index, value.toString());
        if (isNotice)
            ServerWorld.noticeChange(2, index, value);
    };
    ServerWorld.getWorldString = function (index) {
        var v = getGlobalValue("s" + index);
        return v ? v : "";
    };
    ServerWorld.addListenerVariable = function (type, onChange) {
        EventUtils.addEventListener(ServerWorld, "worldVar" + type, onChange);
    };
    ServerWorld.removeListenerVariable = function (type, onChange) {
        EventUtils.removeEventListener(ServerWorld, "worldVar" + type, onChange);
    };
    ServerWorld.getClientCallWorldEvent = function (commonEventID, fromClient) {
        if (fromClient === void 0) { fromClient = false; }
        var ws = ServerWorld.commonEventPages[commonEventID];
        if (!ws || (fromClient && !ServerWorld.allowClientCall[commonEventID]))
            return null;
        return ws;
    };
    ServerWorld.initCommands = function (onFin) {
        var task = new AsynTask(onFin);
        task.execute("commonEvent");
        ServerWorld.gameData.loadCommonEventList(Callback.New(function () {
            var wsList = ServerWorld.gameData.commonEventList.data;
            for (var i in wsList) {
                var scriptData = wsList[i];
                var ws = new CommandPage(scriptData.commands);
                ServerWorld.commonEventPages[i] = ws;
                if (scriptData.allowClient)
                    ServerWorld.allowClientCall[i] = true;
            }
            task.complete();
            ServerWorld.gameData.commonEventList = null;
        }, this));
        task.execute("uiClickEvent");
        ServerWorld.gameData.loadUIList(Callback.New(function () {
            var uiList = ServerWorld.gameData.uiList.data;
            for (var i in uiList) {
                var uiData = uiList[i];
                if (!uiData)
                    continue;
                for (var uicompID in uiData.uiCommandData) {
                    if (uicompID == "id" || uicompID == "data")
                        continue;
                    var uiCommandData = uiData.uiCommandData[uicompID];
                    var commandDatas = uiCommandData.commands;
                    var commands = ServerWorld.uiCustomCommandPages[i + "_" + uicompID] = [];
                    for (var s in commandDatas) {
                        var cmdData = commandDatas[s];
                        if (!cmdData || cmdData.length == 0)
                            continue;
                        commands[s] = new CommandPage(cmdData);
                    }
                }
            }
            task.complete();
        }, this));
    };
    ServerWorld.noticeChange = function (type, varID, value) {
        ServerThread.callAllThreadFunction("ServerWorld", "happenVarChange", [type, varID, value], true);
        ServerWorld.happenVarChange(type, varID, value);
    };
    ServerWorld.happenVarChange = function (type, varID, value) {
        EventUtils.happen(ServerWorld, "worldVar" + type, [varID, value]);
        if (ServerThread.threadID == 2) {
            ServerSql.addWorldVariableToSaveList(type, varID, value);
        }
    };
    ServerWorld.triggerEvent = function (player, type, mainType, indexType, params) {
        var scene = ServerScene.getScene(player.sceneID);
        if (!scene || indexType < 0)
            return;
        if (params.length < 1)
            return;
        var onReturnID = params[2];
        if (type == 0) {
            this.startTriggerCommand(player, mainType, indexType, params, onReturnID != 0 ? Callback.New(function (player, onReturnID, trigger) {
                EventUtils.addEventListener(trigger, CommandTarget.EVENT_OVER, Callback.New(ServerWorld.onCommandOver, this, [player, onReturnID]), true);
            }, this, [player, onReturnID]) : null);
            return;
        }
        var commandID = params[0];
        var playerInput = params[1];
        if (playerInput == null)
            playerInput = [];
        switch (type) {
            case 1:
                var trigger = player.sceneObject.triggerLines[commandID];
                if (trigger) {
                    CommandPage.executeEvent(trigger, playerInput);
                }
                break;
            case 2:
                var trigger = player.execCommonCommand(commandID, playerInput, true);
                if (onReturnID != 0 && trigger)
                    EventUtils.addEventListener(trigger, CommandTarget.EVENT_OVER, Callback.New(ServerWorld.onCommandOver, this, [player, onReturnID]), true);
                break;
        }
    };
    ServerWorld.onCommandOver = function (player, onReturnID) {
        ServerMsgSender.rpc(player, "ClientMsgSender", "cmdReturn", [onReturnID]);
    };
    ServerWorld.startTriggerCommand = function (player, mainType, indexType, params, onTriggerCreated) {
        return null;
    };
    ServerWorld.listenerPlayerVariable = function (player, isListener, type, varID) {
        if (isListener) {
            var funcs = [player.variable.getVariable, player.variable.getSwitch, player.variable.getString];
            var value = funcs[type].apply(player.variable, [varID]);
            ServerMsgSender.rpc(player, "ClientPlayer", "playerVariableChange", [type, varID, value]);
            player.clientListenerVarEnabled(type, varID, true);
        }
        else {
            player.clientListenerVarEnabled(type, varID, false);
        }
    };
    ServerWorld.requestGetWorldVariable = function (player, type, varID) {
        if (ServerWorld.getWorldVariableAccessible(type, varID)) {
            var funcs = [ServerWorld.getWorldVariable, ServerWorld.getWorldSwitch, ServerWorld.getWorldString];
            var value = funcs[type].apply(ServerWorld, [varID]);
            ServerMsgSender.rpc(player, "ClientWorld", "reponseGetVariable", [true, type, varID, value]);
        }
        else {
            ServerMsgSender.rpc(player, "ClientWorld", "reponseGetVariable", [false, type, varID]);
        }
    };
    ServerWorld.EVENT_STARTUP_COMPLETE = "ServerWorld_EVENT_STARTUP_COMPLETE";
    ServerWorld.gameData = new GameData();
    ServerWorld.isOpenGate = false;
    ServerWorld.commonEventPages = [];
    ServerWorld.uiCustomCommandPages = {};
    ServerWorld.accessibles = [[], [], []];
    ServerWorld.allowClientCall = {};
    ServerWorld.serverFuncs = {};
    return ServerWorld;
}());
var ServerGate = (function () {
    function ServerGate() {
    }
    ServerGate.onLogin = function (key) {
        if (!ServerWorld.isOpenGate) {
            websocket_kickOffLine(key);
            return;
        }
        var uid = ServerGate.checkPlayerLogin(key);
        var hasOnlinePlayer = false;
        if (uid) {
            var p = ServerPlayer.getPlayer(key);
            if (p) {
                EventUtils.happen(ServerPlayer, ServerPlayer.EVENT_PLAYER_DISPLACEMENT, [p]);
                p.loginSign++;
                p.useThreadSceneData = true;
                doLogin(p);
                p.useThreadSceneData = false;
                hasOnlinePlayer = true;
            }
            else {
                p = ServerPlayer.addPlayer(key, uid);
                ServerSql.installPlayerData(p, new Callback(function (p) {
                    EventUtils.happen(ServerPlayer, ServerPlayer.EVENT_PLAYER_LOGIN, [p]);
                    doLogin(p);
                }, this));
            }
        }
        else {
            websocket_kickOffLine(key);
        }
        function doLogin(p) {
            ServerMsgSender.rpc(p, "Game", "setPlayerData", [p.uid]);
            ServerGate.requestInScene(p.uid, p.sceneID, p.data.sceneObject.x, p.data.sceneObject.y, p.data.sceneObject.z, p.loginSign, hasOnlinePlayer);
        }
    };
    ServerGate.onLogout = function (key) {
        var player = ServerPlayer.getPlayer(key);
        if (player) {
            EventUtils.happen(ServerPlayer, ServerPlayer.EVENT_PLAYER_LOGOUT, [player]);
            ServerThread.logoutThreadPlayerData(player);
        }
    };
    ServerGate.checkPlayerLogin = function (key) {
        var msgArr = key.split("_");
        var uid = parseInt(msgArr[0]);
        return uid;
    };
    ServerGate.requestInScene = function (playerID, sceneID, x, y, z, loginSign, hasOnlinePlayer) {
        if (hasOnlinePlayer === void 0) { hasOnlinePlayer = false; }
        var player = ServerPlayer.getPlayerByUID(playerID);
        if (!player)
            return;
        if (player.loginSign != loginSign)
            return;
        if (ServerThread.threadID == 2) {
            if (player.sceneID != sceneID) {
                ServerThread.clearPlayerData(player.sceneID, player.uid, player.loginSign, ServerThread.getSceneThread(player.sceneID));
            }
            player.sceneID = sceneID;
            player.data.sceneObject.x = x;
            player.data.sceneObject.y = y;
            player.data.sceneObject.z = z;
            ServerThread.syncPlayer(player, ServerThread.getSceneThread(sceneID));
        }
        else {
            this.outScene(player);
            ServerThread.syncPlayer(player);
            ServerThread.requestInSceneToMain(player, sceneID, x, y, z);
            ServerPlayer.removePlayer(player.key);
        }
    };
    ServerGate.inScene = function (player) {
        var scene = ServerScene.getScene(player.sceneID);
        if (!scene) {
            ServerGate.requestInScene(player.uid, ServerConfig.WHEN_NO_SCENE.sceneID, ServerConfig.WHEN_NO_SCENE.x, ServerConfig.WHEN_NO_SCENE.y, ServerConfig.WHEN_NO_SCENE.z, player.loginSign);
            return;
        }
        scene.readyInScene(player);
    };
    ServerGate.outScene = function (player) {
        var scene = ServerScene.getScene(player.sceneID);
        if (!scene)
            return;
        scene.removePlayer(player);
    };
    ServerGate.clearPlayerData = function (sceneID, playerID, loginSign) {
        if (loginSign === void 0) { loginSign = -1; }
        var player = ServerPlayer.getPlayerByUID(playerID);
        if (!player)
            return;
        if (ServerThread.threadID == 2 && player.loginSign != loginSign) {
            return;
        }
        ServerGate.outScene(player);
        ServerPlayer.removePlayer(player.key);
        if (ServerThread.threadID == 2) {
            ServerThread.clearPlayerData(player.sceneID, player.uid, player.loginSign, ServerThread.getSceneThread(player.sceneID));
        }
    };
    ServerGate.sync = function (playerDataObj) {
        var ldPlayer = ServerPlayer.getPlayerByUID(playerDataObj.uid);
        if (ServerThread.threadID == 2 && (!ldPlayer || ldPlayer.loginSign != playerDataObj.loginSign)) {
            return;
        }
        var needSyncPlayerData = true;
        if (!ldPlayer) {
            ldPlayer = ServerPlayer.addPlayer(playerDataObj.key, playerDataObj.uid);
            playerDataObj.useThreadSceneData = false;
        }
        else {
            if (playerDataObj.useThreadSceneData) {
                needSyncPlayerData = false;
                ldPlayer.loginSign = playerDataObj.loginSign;
            }
        }
        if (needSyncPlayerData) {
            ldPlayer.installFromTransportableData(playerDataObj);
        }
        if (ServerThread.threadID != 2) {
            ServerGate.inScene(ldPlayer);
        }
    };
    ServerGate.savePlayerData = function (sceneID, playerID) {
        var scene = ServerScene.getScene(sceneID);
        if (!scene)
            return false;
        var player = ServerPlayer.getPlayerByUID(playerID);
        if (!player)
            return false;
        ServerThread.syncPlayer(player);
        ServerThread.requestMainSavePlayerData(player.uid, player.loginSign);
        return true;
    };
    ServerGate.logoutPlayer = function (sceneID, playerID) {
        var scene = ServerScene.getScene(sceneID);
        if (!scene)
            return;
        var player = ServerPlayer.getPlayerByUID(playerID);
        if (!player)
            return;
        ServerGate.outScene(player);
        ServerThread.syncPlayer(player);
        ServerThread.requestMainSavePlayerData(player.uid, player.loginSign, true);
        ServerThread.clearPlayerData(player.sceneID, player.uid, player.loginSign);
    };
    return ServerGate;
}());
var ServerMsgSender = (function () {
    function ServerMsgSender() {
    }
    ServerMsgSender.send = function (player, msg) {
        ServerMsgSender.doSend(player.key, msg, false);
    };
    ServerMsgSender.eval = function (player, code) {
        ServerMsgSender.rpc(player, "globalThis", "eval", [code]);
    };
    ServerMsgSender.rpc = function (player, className, funcName, params) {
        if (!player)
            return;
        var obj = {
            c: className,
            f: funcName,
            p: params
        };
        var msg = JSON.stringify(obj);
        ServerMsgSender.doSend(player.key, msg, true);
    };
    ServerMsgSender.doSend = function (key, msg, isRPC) {
        var msgLen = msg.length;
        var fragmentUnit = 5000;
        var i = 0;
        var fragMode;
        var normalMode;
        if (isRPC) {
            fragMode = 2;
            normalMode = 1;
        }
        else {
            fragMode = 3;
            normalMode = 0;
        }
        if (msgLen > fragmentUnit) {
            while (1) {
                var msgFrag = msg.substr(i, fragmentUnit);
                i += fragmentUnit;
                if (i >= msgLen) {
                    websocket_sendClientMsg(key, normalMode + msgFrag);
                    break;
                }
                else {
                    websocket_sendClientMsg(key, fragMode + msgFrag);
                }
            }
        }
        else {
            websocket_sendClientMsg(key, normalMode + msg);
        }
    };
    return ServerMsgSender;
}());
var ServerSql = (function () {
    function ServerSql() {
    }
    ServerSql.init = function () {
        this.mysql_query = eval("mysql_query");
        this.mysql_insert = eval("mysql_query");
        this.mysql_delete = eval("mysql_query");
        this.mysql_update = eval("mysql_query");
        this.mysql_ping = eval("mysql_ping");
        if (ServerThread.threadID == 2)
            setTimeout(ServerSql.save, ServerSql.SAVE_INTERVAL);
    };
    ServerSql.installPlayerData = function (player, onFin) {
        function setUserData(userObj) {
            player.sceneID = userObj.sceneID;
            player.threadID = ServerThread.getSceneThread(player.sceneID);
            player.dataInit();
            onFin.runWith([player]);
        }
        var readSqlArr = [
            ["playervariable", "variables"], ["playerswitch", "switchs"], ["playerstring", "strings"]
        ];
        for (var s in readSqlArr) {
            var sqlVariables = SQLUtils.query(readSqlArr[s][0], "varID,varValue", "where uid=" + player.uid);
            for (var i = 0; i < sqlVariables.length; i++) {
                var varTypeName = readSqlArr[s][1];
                var varSqlData = sqlVariables[i];
                player.variable[varTypeName][varSqlData.varID] = varSqlData.varValue;
                player.sqlVar[varTypeName][varSqlData.varID] = true;
            }
        }
        var sqlUsers = SQLUtils.query("user", "sceneID,data", "where id=" + player.uid + " limit 0,1");
        if (sqlUsers.length == 0) {
            var bornSo = ObjectUtils.depthClone(ServerConfig.BORN.so);
            player.installPlayerData();
            ObjectUtils.clone(bornSo, player.data.sceneObject);
            setUserData({ sceneID: ServerConfig.BORN.sceneID });
            var playerData = JSON.stringify(player.data.getTransportableData());
            SQLUtils.insert("user", { id: player.uid, sceneID: player.sceneID, data: playerData });
        }
        else {
            var sqlPlayerData = JSON.parse(sqlUsers[0].data);
            player.installPlayerData(sqlPlayerData, true);
            setUserData({ sceneID: sqlUsers[0].sceneID });
        }
    };
    ServerSql.installWorldData = function () {
        if (ServerThread.threadID != 2) {
            this.installCustomWorldData();
            return;
        }
        var readSqlArr = [
            ["worldvariable", "setWorldVariable", "variables"], ["worldswitch", "setWorldSwitch", "switchs"], ["worldstring", "setWorldString", "strings"]
        ];
        for (var s in readSqlArr) {
            var varTypeName = readSqlArr[s][2];
            var sqlVariables = SQLUtils.query(readSqlArr[s][0], "varID,varValue", "");
            for (var i = 0; i < sqlVariables.length; i++) {
                var varID = sqlVariables[i].varID;
                var varValue = sqlVariables[i].varValue;
                ServerWorld[readSqlArr[s][1]](sqlVariables[i].varID, sqlVariables[i].varValue, false);
                ServerSql.sqlWorldVar[varTypeName][varID] = true;
            }
        }
        this.installCustomWorldData();
        var npcswitchs = SQLUtils.query("npcswitch", "sceneID,npcIndex,varID,varValue", "order by sceneID,npcIndex,varID");
        var readNPCSwitch = {};
        for (var s in npcswitchs) {
            var npcswitch = npcswitchs[s];
            var sqlScene = this.sqlNPCSwitch[npcswitch.sceneID];
            if (!sqlScene)
                sqlScene = this.sqlNPCSwitch[npcswitch.sceneID] = {};
            var sqlNPC = sqlScene[npcswitch.npcIndex];
            if (!sqlNPC)
                sqlNPC = sqlScene[npcswitch.npcIndex] = {};
            sqlNPC[npcswitch.varID] = true;
            var readScene = readNPCSwitch[npcswitch.sceneID];
            if (!readScene)
                readScene = readNPCSwitch[npcswitch.sceneID] = {};
            var readNpc = readScene[npcswitch.npcIndex];
            if (!readNpc)
                readNpc = readScene[npcswitch.npcIndex] = {};
            readNpc[npcswitch.varID] = npcswitch.varValue;
        }
        for (var sceneID in readNPCSwitch) {
            var sceneThreadID = ServerThread.getSceneThread(parseInt(sceneID));
            ServerThread.callFunction(sceneThreadID, "ServerScene", "installNpcSwitch", [parseInt(sceneID), readNPCSwitch[sceneID]]);
        }
    };
    ServerSql.installCustomWorldData = function () {
        var worldDataRs = SQLUtils.query("worlddata", "data", "");
        if (worldDataRs.length != 1) {
            trace("没有找到世界数据!");
            return;
        }
        var worldData = worldDataRs[0];
        var recordWorldData = ServerSql.recordWorldData = JSON.parse(worldData.data);
        trace(kdsrpg_scriptID, "                               =========================================世界数据=", ServerSql.recordWorldData._arr, ServerSql.recordWorldData.arr);
    };
    ServerSql.save = function (onFin) {
        if (onFin === void 0) { onFin = null; }
        trace("==INTERVAL SAVE==");
        ServerSql.saveWorld();
        ServerSql.saveScene();
        ServerSql.savePlayers(onFin);
        setTimeout(ServerSql.save, ServerSql.SAVE_INTERVAL);
    };
    ServerSql.savePlayers = function (onFin) {
        if (onFin === void 0) { onFin = null; }
        var count = 0;
        for (var i in ServerPlayer.playerList) {
            var p = ServerPlayer.playerList[i];
            if (p && p.threadID != 2) {
                if (onFin) {
                    count++;
                    ServerThread.saveThreadPlayerData(p, Callback.New(function () {
                        count--;
                        if (count == 0)
                            onFin.run();
                    }, this));
                }
                else {
                    ServerThread.saveThreadPlayerData(p);
                }
            }
        }
        if (onFin && count == 0)
            onFin.run();
    };
    ServerSql.addPlayerVariableToSaveList = function (playerID, type, varID, value) {
        if (ServerThread.threadID != 2) {
            ServerThread.callFunction(2, "ServerSql", "addPlayerVariableToSaveList", [playerID, type, varID, value]);
            return;
        }
        var needSavePlayerVar = ServerSql.needSavePlayerVars[playerID];
        if (!needSavePlayerVar)
            needSavePlayerVar = ServerSql.needSavePlayerVars[playerID] = [];
        needSavePlayerVar.push({ type: type, varID: varID, value: value });
    };
    ServerSql.savePlayerByID = function (playerID, loginSign, force) {
        if (force === void 0) { force = false; }
        var player = ServerPlayer.getPlayerByUID(playerID);
        if (!player)
            return false;
        return ServerSql.savePlayer(player, loginSign, force);
    };
    ServerSql.savePlayer = function (player, loginSign, force) {
        if (force === void 0) { force = false; }
        if (!player)
            return false;
        var now = new Date().getTime();
        if (player.loginSign != loginSign)
            return false;
        if (!force && player.lastSaveTime && now - player.lastSaveTime < ServerSql.SAVEABLE_INTERVAL)
            return false;
        player.lastSaveTime = now;
        if (player.saveVariables) {
            var needSavePlayerVars = ServerSql.needSavePlayerVars[player.uid];
            if (needSavePlayerVars) {
                var varSqlArr = [
                    ["playervariable", "variables"], ["playerswitch", "switchs"], ["playerstring", "strings"]
                ];
                var saved = {};
                delete ServerSql.needSavePlayerVars[player.uid];
                var len = needSavePlayerVars.length;
                for (var i = len - 1; i >= 0; i--) {
                    var needSavePlayerVar = needSavePlayerVars[i];
                    var key = needSavePlayerVar.type + "_" + needSavePlayerVar.varID;
                    if (saved[key])
                        continue;
                    saved[key] = true;
                    var varTypeName = varSqlArr[needSavePlayerVar.type][1];
                    var varTabelName = varSqlArr[needSavePlayerVar.type][0];
                    var hasSqlVarData = player.sqlVar[varTypeName][needSavePlayerVar.varID];
                    if (hasSqlVarData) {
                        mysql_update(varTabelName, [("set varValue='" + needSavePlayerVar.value + "' where uid=" + player.uid + " and varID=" + needSavePlayerVar.varID)]);
                    }
                    else {
                        mysql_insert(varTabelName, [("(uid,varID,varValue) values(" + player.uid + "," + needSavePlayerVar.varID + ",'" + needSavePlayerVar.value + "');")]);
                        player.sqlVar[varTypeName][needSavePlayerVar.varID] = true;
                    }
                }
            }
        }
        var playerData = JSON.stringify(player.data.getTransportableData());
        var isSuccess = mysql_update("user", [("set sceneID=" + player.sceneID + ",data = '" + playerData + "' where id=" + player.uid)]);
        return isSuccess > 0;
    };
    ServerSql.addWorldVariableToSaveList = function (type, varID, value) {
        var worldTypeVar = ServerSql.needSaveWorldVars[type];
        worldTypeVar[MathUtils.int(varID)] = value;
    };
    ServerSql.saveWorld = function () {
        var varSqlArr = [
            ["worldvariable", "variables"], ["worldswitch", "switchs"], ["worldstring", "strings"]
        ];
        for (var t in ServerSql.needSaveWorldVars) {
            var tableName = varSqlArr[t][0];
            var varTypeName = varSqlArr[t][1];
            var worldTypeVars = ServerSql.needSaveWorldVars[t];
            for (var varID in worldTypeVars) {
                var value = worldTypeVars[varID];
                if (ServerSql.sqlWorldVar[varTypeName][varID]) {
                    mysql_update(tableName, [("set varValue='" + value + "' where varID=" + varID)]);
                }
                else {
                    mysql_insert(tableName, [("(varID,varValue) values(" + varID + ",'" + value + "');")]);
                    ServerSql.sqlWorldVar[varTypeName][varID] = true;
                }
            }
        }
        ServerSql.needSaveWorldVars = [{}, {}, {}];
        var worldSaveData = JSON.stringify(ServerWorld.data);
        mysql_update("worlddata", [("set data='" + worldSaveData + "'")]);
    };
    ServerSql.addSceneNPCSwitchToSaveList = function (sceneID, index, varID, varValue) {
        var scene = ServerSql.needSaveSceneNPCSwitch[sceneID];
        if (!scene)
            scene = ServerSql.needSaveSceneNPCSwitch[sceneID] = {};
        var npc = scene[index];
        if (!npc)
            npc = scene[index] = {};
        npc[varID] = varValue;
    };
    ServerSql.saveScene = function () {
        for (var sceneID in ServerSql.needSaveSceneNPCSwitch) {
            var scene = ServerSql.needSaveSceneNPCSwitch[sceneID];
            var sqlScene = ServerSql.sqlNPCSwitch[sceneID];
            if (!sqlScene)
                sqlScene = ServerSql.sqlNPCSwitch[sceneID] = {};
            for (var index in scene) {
                var npc = scene[index];
                var sqlNpc = sqlScene[index];
                if (!sqlNpc)
                    sqlScene[index] = sqlNpc = {};
                for (var varID in npc) {
                    var sqlValue = sqlNpc[varID];
                    if (sqlValue) {
                        mysql_update("npcswitch", [("set varValue='" + npc[varID] + "' where sceneID=" + sceneID + " and npcIndex=" + index + " and varID=" + varID)]);
                    }
                    else {
                        mysql_insert("npcswitch", [("(sceneID,npcIndex,varID,varValue) values(" + sceneID + "," + index + "," + varID + ",'" + npc[varID] + "');")]);
                        sqlNpc[varID] = true;
                    }
                }
            }
        }
        ServerSql.needSaveSceneNPCSwitch = {};
    };
    ServerSql.SAVE_INTERVAL = 10000;
    ServerSql.SAVEABLE_INTERVAL = ServerSql.SAVE_INTERVAL - 5000;
    ServerSql.sqlWorldVar = new Variable();
    ServerSql.sqlNPCSwitch = {};
    ServerSql.needSavePlayerVars = {};
    ServerSql.needSaveWorldVars = [{}, {}, {}];
    ServerSql.needSaveSceneNPCSwitch = {};
    return ServerSql;
}());
var ServerThread = (function () {
    function ServerThread() {
    }
    ServerThread.callFunction = function (threadID, funcDomain, funcName, params, onReturn) {
        if (onReturn === void 0) { onReturn = null; }
        var ldThreadRPC = new ServerThread();
        ldThreadRPC.funcDomain = funcDomain;
        ldThreadRPC.funcName = funcName;
        ldThreadRPC.params = params;
        ldThreadRPC.fromThreadID = ServerThread.threadID;
        if (onReturn) {
            ldThreadRPC.isReturn = true;
            ldThreadRPC.returnID = ServerThread.callCount++;
            ServerThread.callFuncReturnMap[ldThreadRPC.returnID] = onReturn;
        }
        sendMsgToPassages(threadID, JSON.stringify(ldThreadRPC));
    };
    ServerThread.callAllThreadFunction = function (funcDomain, funcName, params, excludeSelfThread) {
        if (excludeSelfThread === void 0) { excludeSelfThread = false; }
        for (var i = 0; i <= ServerConfig.SCENE_FIXED_THREAD_COUNT; i++) {
            var threadID = i + 2;
            if (excludeSelfThread && threadID == ServerThread.threadID)
                continue;
            ServerThread.callFunction(threadID, funcDomain, funcName, params);
        }
    };
    ServerThread.syncCode = function (code, excludeSelfThread) {
        ServerThread.callAllThreadFunction("globalThis", "eval", [code], excludeSelfThread);
    };
    Object.defineProperty(ServerThread, "threadID", {
        get: function () {
            return kdsrpg_scriptID;
        },
        enumerable: true,
        configurable: true
    });
    ServerThread.getSceneThread = function (sceneID) {
        return sceneID % ServerConfig.SCENE_FIXED_THREAD_COUNT + 3;
    };
    ServerThread.syncPlayer = function (player, threadID) {
        if (threadID === void 0) { threadID = 2; }
        ServerThread.callFunction(threadID, "ServerGate", "sync", [player.getTransportableData()]);
    };
    ServerThread.requestInSceneToMain = function (player, sceneID, x, y, z) {
        ServerThread.callFunction(2, "ServerGate", "requestInScene", [player.uid, sceneID, x, y, z, player.loginSign]);
    };
    ServerThread.clearPlayerData = function (sceneID, playerID, loginSign, threadID) {
        if (loginSign === void 0) { loginSign = -1; }
        if (threadID === void 0) { threadID = 2; }
        ServerThread.callFunction(threadID, "ServerGate", "clearPlayerData", [sceneID, playerID, loginSign]);
    };
    ServerThread.requestMainSavePlayerData = function (playerID, loginSign, force) {
        if (force === void 0) { force = false; }
        ServerThread.callFunction(2, "ServerSql", "savePlayerByID", [playerID, loginSign, force]);
    };
    ServerThread.saveThreadPlayerData = function (player, onFin) {
        if (onFin === void 0) { onFin = null; }
        ServerThread.callFunction(ServerThread.getSceneThread(player.sceneID), "ServerGate", "savePlayerData", [player.sceneID, player.uid], onFin);
    };
    ServerThread.logoutThreadPlayerData = function (player) {
        ServerThread.callFunction(ServerThread.getSceneThread(player.sceneID), "ServerGate", "logoutPlayer", [player.sceneID, player.uid]);
    };
    ServerThread.callFunctionReturn = function (returnID, isSuccess, returnValue) {
        var cb = ServerThread.callFuncReturnMap[returnID];
        delete ServerThread.callFuncReturnMap[returnID];
        if (!isSuccess)
            return;
        cb.runWith([returnValue]);
    };
    ServerThread.callCount = 0;
    ServerThread.callFuncReturnMap = {};
    return ServerThread;
}());
var Point = (function () {
    function Point(x, y) {
        if (x === void 0) { x = 0; }
        if (y === void 0) { y = 0; }
        this.x = x;
        this.y = y;
    }
    Point.prototype.setTo = function (x, y) {
        this.x = x;
        this.y = y;
        return this;
    };
    Point.prototype.distance = function (x, y) {
        return Math.sqrt((this.x - x) * (this.x - x) + (this.y - y) * (this.y - y));
    };
    Point.prototype.toString = function () {
        return this.x + "," + this.y;
    };
    Point.prototype.normalize = function () {
        var d = Math.sqrt(this.x * this.x + this.y * this.y);
        if (d > 0) {
            var id = 1.0 / d;
            this.x *= id;
            this.y *= id;
        }
    };
    Point.interpolate = function (to, from, per) {
        var p = new Point();
        p.x = (to.x - from.x) * per + from.x;
        p.y = (to.y - from.y) * per + from.y;
        return p;
    };
    Point.distance = function (from, to) {
        return from.distance(to.x, to.y);
    };
    Point.distance2 = function (ax, ay, bx, by) {
        return Math.sqrt((bx - ax) * (bx - ax) + (by - ay) * (by - ay));
    };
    Point.interpolate2 = function (toX, toY, fromX, fromY, per) {
        var x = (toX - fromX) * per + fromX;
        var y = (toY - fromY) * per + fromY;
        return [x, y];
    };
    Point.TEMP = new Point();
    return Point;
}());
var CommandExecute;
(function (CommandExecute) {
    function messageTitle10(cmd) {
        return "<span style='color:#bd2c85;'>选项结束</span>";
    }
    CommandExecute.messageTitle10 = messageTitle10;
    function message10(cmd) {
        return "";
    }
    CommandExecute.message10 = message10;
    function indentStart10() {
        return -2;
    }
    CommandExecute.indentStart10 = indentStart10;
})(CommandExecute || (CommandExecute = {}));
var ServerMain = (function () {
    function ServerMain() {
        this.initTask = "ServerMainInitTask";
        this.soModelBaseCode = "";
        ServerMain.self = this;
        this.init();
    }
    ServerMain.prototype.init = function () {
        var _this = this;
        FileUtils.init();
        new SyncTask(this.initTask, this.installDataConfig, [Config.JSON_CONFIG, Config], this);
        new SyncTask(this.initTask, this.installDataConfig, [ServerConfig.JSON_SERVER_CONFIG, ServerConfig], this);
        new SyncTask(this.initTask, this.connSQL, [], this);
        new SyncTask(this.initTask, this.initVariables, [], this);
        new SyncTask(this.initTask, this.initWorldScript, [], this);
        new SyncTask(this.initTask, this.iniCustomModule, [], this);
        new SyncTask(this.initTask, this.iniSceneObjectModel, [], this);
        new SyncTask(this.initTask, this.initServerScript, [], this);
        new SyncTask(this.initTask, this.initScene, [], this);
        new SyncTask(this.initTask, this.startRun, [], this);
    };
    ServerMain.prototype.installDataConfig = function (url, configObj) {
        FileUtils.loadJsonFile(url, new Callback(function (cfgJson) {
            for (var i in cfgJson)
                configObj[i] = cfgJson[i];
            if (configObj == Config)
                Config.init();
            SyncTask.taskOver(this.initTask);
        }, this));
    };
    ServerMain.prototype.connSQL = function () {
        ServerSql.init();
        var sql_start = eval("mysql_start");
        var isConn = sql_start(ServerConfig.MYSQL_CONN_HOST, parseInt(ServerConfig.MYSQL_CONN_PORT), ServerConfig.MYSQL_CONN_DATABASE, ServerConfig.MYSQL_CONN_USERNAME, ServerConfig.MYSQL_CONN_PASSWORD);
        if (isConn == -1) {
            trace("mysql connection error !", ServerConfig.MYSQL_CONN_HOST, parseInt(ServerConfig.MYSQL_CONN_PORT), ServerConfig.MYSQL_CONN_DATABASE, ServerConfig.MYSQL_CONN_USERNAME, ServerConfig.MYSQL_CONN_PASSWORD);
            return;
        }
        trace(kdsrpg_scriptID, "mysql", isConn);
        ServerMain.sqlIndex = isConn;
        function pingMysqlTest() {
            var pingRes = mysql_ping(isConn);
            if (pingRes == 0) {
            }
            else {
                trace(kdsrpg_scriptID, "线程的数据库连接失败！");
            }
            setTimeout(pingMysqlTest, 30000);
        }
        pingMysqlTest();
        SyncTask.taskOver(this.initTask);
    };
    ServerMain.prototype.initVariables = function () {
        ServerSql.installWorldData();
        SyncTask.taskOver(this.initTask);
    };
    ServerMain.prototype.initWorldScript = function () {
        ServerWorld.initCommands(Callback.New(SyncTask.taskOver, this, [this.initTask]));
    };
    ServerMain.prototype.initScene = function () {
        ServerWorld.gameData.loadTileList(new Callback(function () {
            ServerScene.init(new Callback(function () {
                SyncTask.taskOver(this.initTask);
            }, this));
        }, this));
    };
    ServerMain.prototype.iniSceneObjectModel = function () {
        var _this = this;
        ServerWorld.gameData.loadSceneObjectModelList(Callback.New(function () {
            var len = GameListData.getLength(ServerWorld.gameData.sceneObjectModelList);
            for (var i = 1; i <= len; i++) {
                var soModelData = ServerWorld.gameData.sceneObjectModelList.data[i];
                if (!soModelData)
                    continue;
                var soModelBaseCode = SceneObjectModelData.getServerJsBaseCode(soModelData);
                _this.soModelBaseCode += soModelBaseCode + "SceneObjectModelData.sceneObjectClass[" + i + "]=ServerSceneObject_" + i + ";";
            }
            SyncTask.taskOver(_this.initTask);
        }, this), true);
    };
    ServerMain.prototype.iniCustomModule = function () {
        var _this = this;
        var task = new AsynTask(Callback.New(function () {
            CustomCompositeSetting.runCode(ServerWorld.gameData);
            SyncTask.taskOver(_this.initTask);
        }, this));
        var onloadDataOver = Callback.New(task.complete, task, []);
        task.execute(1);
        task.execute(2);
        task.execute(3);
        task.execute(4);
        ServerWorld.gameData.loadDataStructureList(onloadDataOver);
        ServerWorld.gameData.loadCustomModuleList(onloadDataOver);
        ServerWorld.gameData.loadGameAttributeConfig(onloadDataOver);
        ServerWorld.gameData.loadCustomEventType(onloadDataOver);
    };
    ServerMain.prototype.initServerScript = function () {
        var _this = this;
        ServerWorld.gameData.loadScript(2, Callback.New(function () {
            var jsCode = "";
            for (var i in ServerWorld.gameData.commonScript.bin) {
                jsCode += ServerWorld.gameData.commonScript.bin[i] + "\n";
            }
            ServerWorld.gameData.loadScript(0, Callback.New(function () {
                for (var i in ServerWorld.gameData.serverScript.bin) {
                    var title = ServerWorld.gameData.serverScript.title[i];
                    jsCode += ServerWorld.gameData.serverScript.bin[i] + "\n";
                    if (title == SceneObjectModelData.SERVER_SCENE_OBJECT_CORE_CLASS) {
                        jsCode += _this.soModelBaseCode;
                        _this.soModelBaseCode = null;
                    }
                }
                try {
                    globalThis.eval(jsCode);
                }
                catch (e) {
                    trace("scripterror", e);
                }
                SyncTask.taskOver(_this.initTask);
            }, _this), false);
        }, this), false);
    };
    ServerMain.prototype.startRun = function () {
        var server_websocket_regMsgID = eval("websocket_regMsgID");
        var server_websocket_getClientMsg = eval("websocket_getClientMsg");
        var server_delay = eval("delay");
        var server_isMac = eval("isMacOS");
        var server_whileFunc = eval("whileFunc");
        var server_start = eval("websocket_start");
        var server_receiveMsgFormPassages = ServerMain.receiveMsgFormPassages = eval("receiveMsgFormPassages");
        var server_sendMsgToPassages = ServerMain.sendMsgToPassages = eval("sendMsgToPassages");
        var server_websocket_sendClientMsg = eval("websocket_sendClientMsg");
        var server_scriptThread_create = eval("scriptThread_create");
        function threadMsgHandle() {
            var threadMsgArr = server_receiveMsgFormPassages(ServerThread.threadID);
            if (threadMsgArr) {
                var len = threadMsgArr.length;
                for (var s = 0; s < len; s++) {
                    var lgThreadRPC = JSON.parse(threadMsgArr[s]);
                    try {
                        var mysqlRes = globalThis[lgThreadRPC.funcDomain][lgThreadRPC.funcName].apply(this, lgThreadRPC.params);
                        if (lgThreadRPC.isReturn) {
                            ServerThread.callFunction(lgThreadRPC.fromThreadID, "ServerThread", "callFunctionReturn", [lgThreadRPC.returnID, true, mysqlRes]);
                        }
                    }
                    catch (e) {
                        trace(kdsrpg_scriptID + ":错误的线程调用来自线程" + lgThreadRPC.fromThreadID, lgThreadRPC.funcDomain, lgThreadRPC.funcName, lgThreadRPC.params);
                        traceError(e);
                        if (lgThreadRPC.isReturn) {
                            ServerThread.callFunction(lgThreadRPC.fromThreadID, "ServerThread", "callFunctionReturn", [lgThreadRPC.returnID, false]);
                        }
                    }
                }
            }
        }
        var doWhile;
        if (ServerThread.threadID == 2) {
            for (var i = 0; i < ServerConfig.SCENE_FIXED_THREAD_COUNT; i++) {
                server_scriptThread_create();
            }
            this.needStartupCount = 1 + ServerConfig.SCENE_FIXED_THREAD_COUNT;
            server_websocket_regMsgID(1);
            doWhile = function (now) {
                if (!now)
                    now = new Date().getTime();
                doSetTimeout(now);
                var msgArr = server_websocket_getClientMsg(0);
                if (!msgArr)
                    msgArr = server_websocket_getClientMsg(1);
                for (var i in msgArr) {
                    var obj = msgArr[i].split(",");
                    var key = obj.shift();
                    var msg = obj.join(",");
                    if (msg == "onClientConnected") {
                        ServerGate.onLogin(key);
                    }
                    else if (msg == "onClientDisconnected") {
                        ServerGate.onLogout(key);
                    }
                }
                threadMsgHandle();
            };
            this.runComplete();
        }
        else {
            ServerWorld.addServerFunction("ServerWorld", "triggerEvent");
            ServerWorld.addServerFunction("ServerWorld", "listenerPlayerVariable");
            ServerWorld.addServerFunction("ServerWorld", "requestGetWorldVariable");
            server_websocket_regMsgID(ServerThread.threadID);
            doWhile = function (now) {
                if (!now)
                    now = new Date().getTime();
                doSetTimeout(now);
                var msgArr = server_websocket_getClientMsg(ServerThread.threadID);
                for (var i in msgArr) {
                    var obj = msgArr[i].split(",");
                    var key = obj.shift();
                    var msg = obj.join(",");
                    ServerPlayer.onHandleMsg(key, msg);
                }
                threadMsgHandle();
                ServerWorld.update(now);
            };
            doWhile(new Date().getTime());
            this.runComplete();
        }
        if (server_isMac) {
            server_whileFunc(doWhile, 16);
        }
        else {
            while (1) {
                var now = new Date().getTime();
                doWhile(now);
                var costTime = now - new Date().getTime();
                if (costTime < 16) {
                    server_delay(16 - costTime);
                }
            }
        }
    };
    ServerMain.prototype.runComplete = function () {
        if (ServerThread.threadID != 2) {
            ServerThread.callFunction(2, "globalThis", "eval", ["ServerMain.self.runComplete();"]);
            return;
        }
        this.needStartupCount--;
        if (this.needStartupCount == 0) {
            try {
                var v = websocket_start(Config.GAME_SERVER_PORT, ServerConfig.MAX_CONN);
            }
            catch (e) {
                trace("socket启动失败！端口已被占用，占用的进程：", Config.GAME_SERVER_PORT, e);
                http_get("http://127.0.0.1:" + IDEHttpPort + "/kdsrpg_custom_message.js?serverRunFail");
                return;
            }
            if (!v) {
                trace("websocket server startup fail!");
                http_get("http://127.0.0.1:" + IDEHttpPort + "/kdsrpg_custom_message.js?serverRunFail");
                return;
            }
            trace("========================================= 启动完毕 ==============");
            ServerWorld.isOpenGate = true;
            EventUtils.happen(ServerWorld, ServerWorld.EVENT_STARTUP_COMPLETE);
            ServerThread.syncCode("EventUtils.happen(ServerWorld, ServerWorld.EVENT_STARTUP_COMPLETE);", true);
            http_get("http://127.0.0.1:" + IDEHttpPort + "/kdsrpg_custom_message.js?serverRunSuccess");
        }
    };
    ServerMain.arrSyncFuncIndex = 0;
    return ServerMain;
}());
if (typeof window == "undefined") {
    var __setTimeoutFunc = [];
    var __setFrameoutFunc = [];
    var __fCount = 0;
    var setTimeout = function (func, time) {
        var arg = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            arg[_i - 2] = arguments[_i];
        }
        var t = ObjectUtils.getInstanceID() + 1;
        __setTimeoutFunc.push([func, new Date().getTime(), time, arg, t]);
        return t;
    };
    var setFrameout = function (func, frame) {
        var arg = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            arg[_i - 2] = arguments[_i];
        }
        var t = ObjectUtils.getInstanceID() + 1;
        __setFrameoutFunc.push([func, __fCount, frame, arg, t]);
        return t;
    };
    var clearFrameout = function (t) {
        var m = ArrayUtils.matchAttributes(__setFrameoutFunc, { 4: t }, true, "==", true);
        if (m.length == 1) {
            __setFrameoutFunc.splice(m[0], 1);
        }
    };
    var clearTimeout = function (t) {
        var m = ArrayUtils.matchAttributes(__setTimeoutFunc, { 4: t }, true, "==", true);
        if (m.length == 1) {
            __setTimeoutFunc.splice(m[0], 1);
        }
    };
    var doSetTimeout = function (nowTime) {
        if (ServerWorld.isStop)
            return;
        __fCount++;
        for (var s = 0; s < __setTimeoutFunc.length; s++) {
            var arr = __setTimeoutFunc[s];
            if (nowTime - arr[1] >= arr[2]) {
                __setTimeoutFunc.splice(s, 1);
                s--;
                arr[0].apply(this, arr[3]);
            }
        }
        for (var s = 0; s < __setFrameoutFunc.length; s++) {
            var arr = __setFrameoutFunc[s];
            if (__fCount - arr[1] >= arr[2]) {
                __setFrameoutFunc.splice(s, 1);
                s--;
                arr[0].apply(this, arr[3]);
            }
        }
    };
}
var ServerConfig = (function () {
    function ServerConfig() {
    }
    ServerConfig.exclude = ["exclude", "JSON_SERVER_CONFIG"];
    ServerConfig.JSON_SERVER_CONFIG = "asset/json/server/serverConfig.json";
    ServerConfig.customConfig = {};
    return ServerConfig;
}());
var SQLUtils = (function () {
    function SQLUtils() {
    }
    SQLUtils.query = function (tableName, params, condition) {
        var str = ServerSql.mysql_query(tableName, params, condition);
        if (str == null)
            return null;
        var dataRows = str.split(String.fromCharCode(6));
        dataRows.pop();
        var dataList = [];
        var paramArr = params.split(",");
        for (var i in dataRows) {
            var columnStr = dataRows[i].split(String.fromCharCode(5));
            columnStr.pop();
            var sqlObjData = {};
            for (var s in paramArr) {
                var value = columnStr[s];
                sqlObjData[paramArr[s]] = isNaN(value) || value == " " ? value : parseFloat(value);
            }
            dataList.push(sqlObjData);
        }
        return dataList;
    };
    SQLUtils.insert = function (tableName, sqlObj) {
        var params = "";
        var values = "";
        for (var i in sqlObj) {
            if (typeof sqlObj[i] == "function")
                continue;
            params += i + ",";
            values += "'" + sqlObj[i] + "',";
        }
        params = params.substr(0, params.length - 1);
        values = values.substr(0, values.length - 1);
        var sqlStr = "(" + params + ") values(" + values + ")";
        return mysql_insert(tableName, [sqlStr]) == 1 ? true : false;
    };
    SQLUtils.update = function (tableName, sqlObj, where) {
        var updateStr = "set ";
        for (var i in sqlObj) {
            if (typeof sqlObj[i] == "function")
                continue;
            updateStr += i + "='" + sqlObj[i] + "',";
        }
        updateStr = updateStr.substr(0, updateStr.length - 1);
        updateStr += " " + where;
        return mysql_update(tableName, [updateStr]) == 1 ? true : false;
    };
    SQLUtils.delete_data = function (tableName, condition) {
        return mysql_delete(tableName, [condition]) == 1 ? true : false;
    };
    return SQLUtils;
}());
var Rectangle = (function () {
    function Rectangle(x, y, width, height) {
        if (x === void 0) { x = 0; }
        if (y === void 0) { y = 0; }
        if (width === void 0) { width = 0; }
        if (height === void 0) { height = 0; }
        (x === void 0) && (x = 0);
        (y === void 0) && (y = 0);
        (width === void 0) && (width = 0);
        (height === void 0) && (height = 0);
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }
    Rectangle.prototype.setTo = function (x, y, width, height) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        return this;
    };
    Rectangle.prototype.copyFrom = function (source) {
        this.x = source.x;
        this.y = source.y;
        this.width = source.width;
        this.height = source.height;
        return this;
    };
    Rectangle.prototype.contains = function (x, y) {
        if (this.width <= 0 || this.height <= 0)
            return false;
        if (x >= this.x && x < this.right) {
            if (y >= this.y && y < this.bottom) {
                return true;
            }
        }
        return false;
    };
    Rectangle.prototype.intersects = function (rect) {
        return !(rect.x > (this.x + this.width) || (rect.x + rect.width) < this.x || rect.y > (this.y + this.height) || (rect.y + rect.height) < this.y);
    };
    Rectangle.prototype.intersection = function (rect, out) {
        if (out === void 0) { out = null; }
        if (!this.intersects(rect))
            return null;
        out || (out = new Rectangle());
        out.x = Math.max(this.x, rect.x);
        out.y = Math.max(this.y, rect.y);
        out.width = Math.min(this.right, rect.right) - out.x;
        out.height = Math.min(this.bottom, rect.bottom) - out.y;
        return out;
    };
    Rectangle.prototype.union = function (source, out) {
        if (out === void 0) { out = null; }
        out || (out = new Rectangle());
        this.clone(out);
        if (source.width <= 0 || source.height <= 0)
            return out;
        out.addPoint(source.x, source.y);
        out.addPoint(source.right, source.bottom);
        return this;
    };
    Rectangle.prototype.clone = function (out) {
        if (out === void 0) { out = null; }
        out || (out = new Rectangle());
        out.x = this.x;
        out.y = this.y;
        out.width = this.width;
        out.height = this.height;
        return out;
    };
    Rectangle.prototype.toString = function () {
        return this.x + "," + this.y + "," + this.width + "," + this.height;
    };
    Rectangle.prototype.equals = function (rect) {
        if (!rect || rect.x !== this.x || rect.y !== this.y || rect.width !== this.width || rect.height !== this.height)
            return false;
        return true;
    };
    Rectangle.prototype.addPoint = function (x, y) {
        this.x > x && (this.width += this.x - x, this.x = x);
        this.y > y && (this.height += this.y - y, this.y = y);
        if (this.width < x - this.x)
            this.width = x - this.x;
        if (this.height < y - this.y)
            this.height = y - this.y;
        return this;
    };
    Rectangle.prototype._getBoundPoints = function () {
        var rst = Rectangle._temB;
        rst.length = 0;
        if (this.width == 0 || this.height == 0)
            return rst;
        rst.push(this.x, this.y, this.x + this.width, this.y, this.x, this.y + this.height, this.x + this.width, this.y + this.height);
        return rst;
    };
    Rectangle.prototype.isEmpty = function () {
        if (this.width <= 0 || this.height <= 0)
            return true;
        return false;
    };
    Object.defineProperty(Rectangle.prototype, "right", {
        get: function () {
            return this.x + this.width;
        },
        enumerable: true,
        configurable: true
    });
    ;
    Object.defineProperty(Rectangle.prototype, "bottom", {
        get: function () {
            return this.y + this.height;
        },
        enumerable: true,
        configurable: true
    });
    ;
    Rectangle.prototype._getBoundPointS = function (x, y, width, height) {
        var rst = Rectangle._temA;
        rst.length = 0;
        if (width == 0 || height == 0)
            return rst;
        rst.push(x, y, x + width, y, x, y + height, x + width, y + height);
        return rst;
    };
    Rectangle.prototype._getWrapRec = function (pointList, rst) {
        if (!pointList || pointList.length < 1)
            return rst ? rst.setTo(0, 0, 0, 0) : Rectangle.TEMP.setTo(0, 0, 0, 0);
        rst = rst ? rst : new Rectangle();
        var i, len = pointList.length, minX, maxX, minY, maxY, tPoint = Point.TEMP;
        minX = minY = 99999;
        maxX = maxY = -minX;
        for (i = 0; i < len; i += 2) {
            tPoint.x = pointList[i];
            tPoint.y = pointList[i + 1];
            minX = minX < tPoint.x ? minX : tPoint.x;
            minY = minY < tPoint.y ? minY : tPoint.y;
            maxX = maxX > tPoint.x ? maxX : tPoint.x;
            maxY = maxY > tPoint.y ? maxY : tPoint.y;
        }
        return rst.setTo(minX, minY, maxX - minX, maxY - minY);
    };
    Rectangle.EMPTY = new Rectangle();
    Rectangle.TEMP = new Rectangle();
    Rectangle._temB = [];
    Rectangle._temA = [];
    return Rectangle;
}());
var CommandExecute;
(function (CommandExecute) {
    function command_1000(commandPage, cmd, trigger, triggerPlayer) {
        if (triggerPlayer) {
            if (trigger.inputMessage.length == 0) {
                cmd.callClient(trigger.id, trigger.triggerPlayer, [cmd.params[0], cmd.params[1]]);
                if (cmd.params[2]) {
                    trigger.pause = true;
                }
            }
            else {
                if (trigger.inputMessage[0])
                    triggerPlayer.variable.setString(cmd.params[3], trigger.inputMessage[0]);
            }
        }
    }
    CommandExecute.command_1000 = command_1000;
    function messageTitle1000(cmd) {
        return "<span style='color:#0070BB;'>登陆NEO钱包：</span>";
    }
    CommandExecute.messageTitle1000 = messageTitle1000;
    function message1000(cmd) {
        return "<span style='color:#0070BB;'>\u4E0D\u5141\u8BB8\u53D6\u6D88\u767B\u9646:" + cmd.params[0] + ",\u7B49\u5F85\u767B\u9646\u5B8C\u6210:" + cmd.params[2] + ",\u5DF2\u767B\u9646\u5FFD\u7565\u6B64\u754C\u9762:" + cmd.params[1] + "</span>";
    }
    CommandExecute.message1000 = message1000;
})(CommandExecute || (CommandExecute = {}));





var CommandTarget = (function (_super) {
    __extends(CommandTarget, _super);
    function CommandTarget(mainType, indexType, scene, trigger, multiline) {
        _super.call(this);
        this.commandScope = [];
        this.inputMessage = [];
        this.behaviorCount = 0;
        this.mainType = mainType;
        this.indexType = indexType;
        this.scene = scene;
        this.trigger = trigger;
        this.multiline = multiline;
        trigger.triggerLines[this.id] = this;
    }
    CommandTarget.prototype.dispose = function () {
        if (!this.trigger || !this.trigger.triggerLines)
            return;
        delete this.trigger.triggerLines[this.id];
        EventUtils.clear(this);
    };
    Object.defineProperty(CommandTarget.prototype, "triggerPlayer", {
        get: function () {
            return this.trigger ? this.trigger.player : null;
        },
        enumerable: true,
        configurable: true
    });
    CommandTarget.prototype.goto = function (index) {
        this.commandScope[this.commandScope.length - 1].index = index - 1;
    };
    CommandTarget.prototype.offset = function (i) {
        this.commandScope[this.commandScope.length - 1].index += i;
    };
    CommandTarget.prototype.end = function () {
        this.commandScope.pop();
    };
    CommandTarget.prototype.clearBehaviorCount = function () {
        this.behaviorCount = 0;
    };
    CommandTarget.prototype.addBehaviorCount = function () {
        this.behaviorCount++;
    };
    CommandTarget.prototype.removeBehaviorCount = function () {
        this.behaviorCount--;
        if (this.behaviorCount == 0) {
            var behaviorOverCallback = this.behaviorOverCallback;
            this.behaviorOverCallback = null;
            EventUtils.happen(this, CommandTarget.EVENT_BEHAVIOR_OVER);
            behaviorOverCallback && behaviorOverCallback.run();
        }
    };
    Object.defineProperty(CommandTarget.prototype, "hasBehavior", {
        get: function () {
            return this.behaviorCount > 0;
        },
        enumerable: true,
        configurable: true
    });
    CommandTarget.EVENT_START = "CommandTarget_EVENT_START_TRIGGER";
    CommandTarget.EVENT_OVER = "CommandTarget_EVENT_OVER";
    CommandTarget.EVENT_BEHAVIOR_OVER = "CommandTarget_EVENT_BEHAVIOR_OVER";
    CommandTarget.COMMAND_MAIN_TYPE_SCENE = 0;
    CommandTarget.COMMAND_MAIN_TYPE_SCENE_OBJECT = 1;
    CommandTarget.COMMAND_MAIN_TYPE_UI = 2;
    CommandTarget.COMMAND_MAIN_TYPE_CALL_COMMON_EVENT = 3;
    return CommandTarget;
}(IdentityObject));





var ServerSceneObject = (function (_super) {
    __extends(ServerSceneObject, _super);
    function ServerSceneObject(soData, presetCustomAttrs, player) {
        if (soData === void 0) { soData = null; }
        if (presetCustomAttrs === void 0) { presetCustomAttrs = null; }
        if (player === void 0) { player = null; }
        _super.call(this);
        this.switchs = [0, 0, 0, 0, 0, 0, 0];
        this.inScene = false;
        this.customCommandPages = [];
        this.triggerLines = {};
        this.triggerSingleLines = [];
        this.player = player;
        if (soData) {
            ObjectUtils.clone(soData, this);
        }
        var modelData = this.modelData = ServerWorld.gameData.sceneObjectModelList.data[this.modelID];
        if (modelData) {
            var attrSettings = modelData.varAttributes;
            if (!presetCustomAttrs) {
                presetCustomAttrs = CustomAttributeSetting.formatCustomData(null, modelData.varAttributes);
            }
            CustomAttributeSetting.installAttributeFromEditorSet(this, presetCustomAttrs, attrSettings, false, false, GameData.CUSTOM_ATTR_SCENE_OBJECT_DATA);
        }
    }
    ServerSceneObject.prototype.getSwitchs = function (index) {
        return this.switchs[index];
    };
    ServerSceneObject.prototype.setSwitchs = function (varID, value, notice) {
        if (notice === void 0) { notice = true; }
        this.switchs[varID] = value;
        if (notice) {
            this.refreshDisappearStatus();
            if (!this.player && !this.isCopy) {
                ServerThread.callFunction(2, "ServerSql", "addSceneNPCSwitchToSaveList", [this.scene.id, this.index, varID, value]);
            }
        }
    };
    Object.defineProperty(ServerSceneObject.prototype, "isCopy", {
        get: function () { return this._isCopy; },
        enumerable: true,
        configurable: true
    });
    ;
    ServerSceneObject.prototype.dispose = function () {
        if (!this.isCopy)
            return;
        EventUtils.clear(this);
        this.clearCondition();
        if (this.scene) {
            this.scene.removeSceneObject(this, false);
        }
        for (var i in this) {
            this[i] = null;
        }
        this.isDisposed = true;
    };
    ServerSceneObject.create = function (soData, presetCustomAttrs, player, isClone) {
        if (presetCustomAttrs === void 0) { presetCustomAttrs = null; }
        if (player === void 0) { player = null; }
        if (isClone === void 0) { isClone = true; }
        var so;
        var modelCls = SceneObjectModelData.sceneObjectClass[soData.modelID];
        if (modelCls) {
            var modelData = ServerWorld.gameData.sceneObjectModelList.data[soData.modelID];
            if (modelData.serverInstanceClassName && globalThis[modelData.serverInstanceClassName]) {
                so = new globalThis[modelData.serverInstanceClassName](soData, presetCustomAttrs, player);
            }
            else {
                so = new modelCls(soData, presetCustomAttrs, player);
            }
        }
        else {
            so = new ServerSceneObject(soData, presetCustomAttrs, player);
        }
        so._isCopy = isClone;
        return so;
    };
    ServerSceneObject.clone = function (fromSceneID, fromSceneObjectindex, toScene, isCopy) {
        if (isCopy === void 0) { isCopy = true; }
        var sceneData = ServerWorld.gameData.sceneList.data[fromSceneID];
        var soData = sceneData.sceneObjectData.sceneObjects[fromSceneObjectindex];
        var customAttr = sceneData.sceneObjectData.customAttributes[fromSceneObjectindex];
        var behavior = sceneData.sceneObjectData.behaviors[fromSceneObjectindex];
        var event = sceneData.sceneObjectData.events[fromSceneObjectindex];
        var preSo = ServerSceneObject.create(soData, customAttr, null, isCopy);
        preSo.initNpc(toScene, behavior, event);
        return preSo;
    };
    ServerSceneObject.prototype.initNpc = function (scene, behaviorData, eventData) {
        if (behaviorData === void 0) { behaviorData = null; }
        if (eventData === void 0) { eventData = null; }
        if (behaviorData) {
            this.addBehavior(behaviorData[2], behaviorData[1] == 1, null, null, false);
        }
        if (eventData) {
            for (var i in eventData.customCommands) {
                var customCmd = eventData.customCommands[i];
                if (!customCmd)
                    continue;
                this.customCommandPages[i] = new CommandPage(customCmd);
                if (customCmd.length != 0) {
                    this.hasCommand[i] = true;
                }
            }
            this.condition = eventData.condition;
            this.initCondition();
        }
        this.scene = scene;
    };
    ServerSceneObject.prototype.initPlayer = function () {
    };
    ServerSceneObject.prototype.addBehavior = function (behaviorData, loop, targetPlayerSceneObject, onOver, cover) {
    };
    ServerSceneObject.prototype.getCommandTrigger = function (mainType, indexType) {
        if (mainType < 0 || indexType < 0)
            return null;
        var trigger;
        var typeCmd = [ServerWorld.gameData.customSceneEventTypeList, ServerWorld.gameData.customObjectEventTypeList, ServerWorld.gameData.customUIEventTypeList][mainType].data[indexType + 1];
        if (typeCmd) {
            if (typeCmd.multiline) {
                return new CommandTarget(mainType, indexType, this.scene, this, typeCmd.multiline);
            }
            else {
                var triggerID = mainType * 10000 + indexType;
                var trigger = this.triggerSingleLines[triggerID];
                if (!trigger)
                    trigger = this.triggerSingleLines[triggerID] = new CommandTarget(mainType, indexType, this.scene, this, typeCmd.multiline);
            }
        }
        return trigger;
    };
    ServerSceneObject.prototype.update = function (now) {
    };
    ServerSceneObject.prototype.clearCondition = function () {
        if (this.conditionWorldVarChangeCB) {
            ServerWorld.removeListenerVariable(0, this.conditionWorldVarChangeCB);
            this.conditionWorldVarChangeCB = null;
        }
        if (this.conditionWorldSwitchChangeCB) {
            ServerWorld.removeListenerVariable(1, this.conditionWorldSwitchChangeCB);
            this.conditionWorldSwitchChangeCB = null;
        }
        this.conditionMySwitchs = {};
        this.conditionWorldSwitchs = {};
        this.conditionWorldVars = {};
    };
    ServerSceneObject.prototype.initCondition = function () {
        this.clearCondition();
        var hasWorldVarCondition = false;
        var hasWorldSwitchCondition = false;
        for (var s = 0; s < this.condition.length; s++) {
            var condition = this.condition[s];
            if (condition.type == 3) {
                this.conditionWorldVars[condition.varID] = true;
                hasWorldVarCondition = true;
            }
            if (condition.type == 4) {
                this.conditionWorldSwitchs[condition.varID] = true;
                hasWorldSwitchCondition = true;
            }
            if (condition.type == 2)
                this.conditionMySwitchs[condition.varID] = true;
        }
        if (hasWorldVarCondition) {
            this.conditionWorldVarChangeCB = Callback.New(this.onMyConditionWorldVarChange, this);
            ServerWorld.addListenerVariable(0, this.conditionWorldVarChangeCB);
        }
        if (hasWorldSwitchCondition) {
            this.conditionWorldSwitchChangeCB = Callback.New(this.onMyConditionWorldSwitchChange, this);
            ServerWorld.addListenerVariable(1, this.conditionWorldSwitchChangeCB);
        }
        this.refreshDisappearStatus();
    };
    ServerSceneObject.prototype.onMyConditionWorldVarChange = function (varID, value) {
        if (this.conditionWorldVars[varID])
            this.refreshDisappearStatus();
    };
    ServerSceneObject.prototype.onMyConditionWorldSwitchChange = function (varID, value) {
        if (this.conditionWorldSwitchs[varID])
            this.refreshDisappearStatus();
    };
    ServerSceneObject.prototype.refreshDisappearStatus = function () {
        if (!this.condition)
            return;
        var lastInScene = this.inScene;
        var len = this.condition.length;
        var curInScene = true;
        for (var i = 0; i < len; i++) {
            var condition = this.condition[i];
            if (condition.type == 3) {
                var varValue = ServerWorld.getWorldVariable(condition.varID);
                if ((condition.compare == 0 && varValue !== condition.value) ||
                    (condition.compare == 1 && varValue < condition.value) ||
                    (condition.compare == 2 && varValue <= condition.value) ||
                    (condition.compare == 3 && varValue > condition.value) ||
                    (condition.compare == 4 && varValue >= condition.value) ||
                    (condition.compare == 5 && varValue === condition.value)) {
                    curInScene = false;
                    break;
                }
            }
            else if ((condition.type == 2 && this.switchs[condition.varID] !== condition.value) ||
                (condition.type == 4 && ServerWorld.getWorldSwitch(condition.varID) !== MathUtils.int(condition.value))) {
                curInScene = false;
                break;
            }
        }
        this.inScene = curInScene;
        if (this.scene) {
            if (lastInScene != curInScene) {
                if (curInScene) {
                    this.scene.addSceneObject(this, false);
                }
                else {
                    this.scene.removeSceneObject(this, false);
                }
            }
        }
    };
    ServerSceneObject.prototype.getTransportableData = function (allAttributes, syncSelf) {
        if (allAttributes === void 0) { allAttributes = true; }
        if (syncSelf === void 0) { syncSelf = true; }
        var so = new SceneObject;
        ObjectUtils.cloneExcludeNonExistentAttribute(this, so);
        var soCustomAttribute = {};
        if (this.modelData) {
            for (var i in this.modelData.varAttributes) {
                var customAttributeSetting = this.modelData.varAttributes[i];
                if (!allAttributes && (customAttributeSetting.accessMode === 0 || customAttributeSetting.syncMode === 0 ||
                    (!syncSelf && customAttributeSetting.syncMode === 2)))
                    continue;
                var varName = customAttributeSetting.varName;
                so[varName] = this[varName];
            }
        }
        return so;
    };
    ServerSceneObject.prototype.syncClientData = function (syncSelf) {
        var soData = this.getTransportableData(false, syncSelf);
        if (this.player) {
            soData["player"] = this.player.syncClientData(syncSelf);
        }
        return soData;
    };
    ServerSceneObject.EVENT_NEED_STOP_BEHAVIOR = "ServerSceneObject_EVENT_NEED_STOP_BEHAVIOR";
    return ServerSceneObject;
}(SceneObject));
var isMacOS = false;
function main() {
    new ServerMain();
}
