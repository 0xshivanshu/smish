// SmishingDetectorApp/crypto-client.js
import { RSA } from 'react-native-rsa-native';
import SInfo from 'react-native-sensitive-info';
import CryptoJS from 'crypto-js';

const SINFO_OPTIONS = {
 sharedPreferencesName: 'com.smishingdetector.sharedprefs',
 keychainService: 'com.smishingdetector.keychainservice',
};
const PUBLIC_KEY_KEY = 'rsaPublicKey';
const PRIVATE_KEY_KEY = 'rsaPrivateKey';

export async function getOrCreateKeys() {
 const privateKey = await SInfo.getItem(PRIVATE_KEY_KEY, SINFO_OPTIONS);

 if (privateKey) {
 console.log("Found existing keys in secure storage.");
 const publicKey = await SInfo.getItem(PUBLIC_KEY_KEY, SINFO_OPTIONS);
 return { privateKey, publicKey };
 } else {
 console.log("No keys found, generating new RSA key pair..."); const keys = await RSA.generateKeys(2048); // Generate new keys

 // Store the new keys separately
 await SInfo.setItem(PUBLIC_KEY_KEY, keys.public, SINFO_OPTIONS);
 await SInfo.setItem(PRIVATE_KEY_KEY, keys.private, SINFO_OPTIONS); 
 console.log("New keys generated and stored securely.");
 return { privateKey: keys.private, publicKey: keys.public };
 }
}

// --- Encryption and Signing ---
export async function createSecurePayload(url, clientPublicKey, clientPrivateKey, serverPublicKey) {
 const aesKey = CryptoJS.lib.WordArray.random(32); // 256-bit key
 const iv = CryptoJS.lib.WordArray.random(16); // Initialization Vector

 const encrypted = CryptoJS.AES.encrypt(url, aesKey, { iv: iv });
 const encryptedUrlHex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(encrypted.toString()));

 const aesKeyAndIv = `${aesKey.toString(CryptoJS.enc.Hex)}:${iv.toString(CryptoJS.enc.Hex)}`;
 const encryptedAesKey = await RSA.encrypt(aesKeyAndIv, serverPublicKey);
 const encryptedAesKeyHex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(encryptedAesKey));

 const hash = CryptoJS.SHA512(encryptedUrlHex).toString(CryptoJS.enc.Hex);
 const signature = await RSA.sign(hash, clientPrivateKey);
 const signatureHex = CryptoJS.enc.Hex.stringify(CryptoJS.enc.Base64.parse(signature));
 
 return {
 encrypted_url_hex: encryptedUrlHex,
 nonce_hex: iv.toString(CryptoJS.enc.Hex), // We'll send the IV as a nonce
 tag_hex: '', 
 encrypted_aes_key_hex: encryptedAesKeyHex,
 };
}
