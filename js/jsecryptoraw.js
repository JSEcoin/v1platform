var crypto = require('crypto');
var eccrypto = require("eccrypto");
var sr = require('secure-random');

function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2buf(hex) {
	var array = new Uint8Array(hex.length / 2);
	var k = 0;
	for (var i = 0; i < hex.length; i +=2 ) {
		array[k] = parseInt(hex[i] + hex[i+1], 16);
		k++;
	}
	var buffer = new Buffer(array.buffer);
	return buffer;
}

window.createKeyPair = function() {
//function createKeyPair() {
	var privateKey = sr.randomBuffer(32);
	var privateKeyString = buf2hex(privateKey);
	var publicKey = eccrypto.getPublic(privateKey);
	var publicKeyString = buf2hex(publicKey); 

	var keyPair = {};
	keyPair.privateKey = privateKeyString;
	keyPair.publicKey = publicKeyString;
	return keyPair;
}

window.signData = function(stringData, keyPair,callback) {
//function signData(stringData, keyPair,callback) {
	var shaBuffer = crypto.createHash("sha256").update(stringData).digest();
 	var privateKey = hex2buf(keyPair.privateKey);

	eccrypto.sign(privateKey, shaBuffer).then(function(signatureArrayBuffer) {
		var signatureString = buf2hex(signatureArrayBuffer);
		var signed = {}
		signed.data = stringData;
		signed.hash = buf2hex(shaBuffer);
		signed.publicKey = keyPair.publicKey;
		signed.signature = signatureString;
		callback(signed);
	});
}

window.verifyData = function(signed, successCallback, failCallback) {
//function verifyData(signed, successCallback, failCallback) {
	var shaBuffer = crypto.createHash("sha256").update(signed.data).digest();
	publicKey = hex2buf(signed.publicKey);
	signature = hex2buf(signed.signature);

	eccrypto.verify(publicKey, shaBuffer, signature).then(function() {
		successCallback(signed);
	}).catch(function(err) {
		failCallback(signed);
	});
}

window.browserifySha256 = function(data) {
//function browserifySha256(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}