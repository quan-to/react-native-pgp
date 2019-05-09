# react-native-pgp
React Native OpenPGP for iOS and Android (in development)

## Documentation
- [Install](https://github.com/quan-to/react-native-pgp#install)
- [Usage](https://github.com/quan-to/react-native-pgp#usage)
- [Example](https://github.com/quan-to/react-native-pgp#example)
- [Methods](https://github.com/quan-to/react-native-pgp#methods)
- [Errors](https://github.com/quan-to/react-native-pgp#errors)

### Install

```bash
npm --save install react-native-pgp
react-native link react-native-pgp
```

Note: Run `npm install -g rnpm` if you haven't installed RNPM (React-Native Package Manager) yet! Alternatively you can add the Android and iOS modules library by following the official guide.

### Usage

```javascript
import ReactNativePGP from 'react-native-pgp';
```

### Example

#### Generating Key-Pair

```javascript
const userName = 'myUsername';
const keyBits = 4096;
const keyPassword = 'mySuperSecretPassword';

const {
    fingerprint,      // Fingerprint of the key
    generationTimeMs, // Number of milisseconds to generate the key
    privateKey,       // ASCII Armored Private Key Encrypted with keyPassword
    publicKey,        // ASCII Armored Public Key
} = await ReactNativePGP.generateKeyPair(userName, keyBits, keyPassword);
```

#### Signing data

```javascript
const privateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`;

const privateKeyPassword = 'mySuperSecretPassword';
const dataToSign = 'I signed this, no one else!';

const {
    privateKeysLoaded,
    fingerprints,
} = await ReactNativePGP.loadKey(privateKey);
  
console.log(`Loaded ${privateKeysLoaded} private keys. Fingerprints: ${fingerprints}`);
const fingerprint = fingerprints[0];

await ReactNativePGP.unlockKey(fingerprint, privateKeyPassword);

console.log(`Key unlocked`);


const {
    asciiArmoredSignature, // "-----BEGIN PGP SIGNATURE----- ... -----END PGP SIGNATURE-----"
    hashingAlgo, // SHA512
    // fingerprint, // Key Fingerprint
} = await ReactNativePGP.sign(fingerprint, dataToSign);

console.log(asciiArmoredSignature);
```

### Methods

* `randomBytes(size, cb)` - Generate Secure Random Bytes using OS SecureRandom
* `loadKey(keyData)` - Loads a Private or Public key into memory storage
* `unlockKey(fingerprint, password)` - Unlocks a loaded private key to be used for signing / decrypting
* `verifySignature(data, signature)` - Verifies a signature of the specified data. A public key for the signature should be loaded with `loadkey` before calling this.
* `verifyB64DataSignature(data, signature)` - Verifies a signature of the specified data (encoded in base64). A public key for the signature should be loaded with `loadkey` before calling this.
* `generateKeyPair(userName, keyBits, keyPassword)` - Generates a public/private keyPair and encrypts the private key with specified password.
* `sign(fingerprint, data)` - Signs data payload with a unlocked private key
* `signB64(fingerprint, b64data)` - Signs a base64 encoded data with a unlocked private key

### Deprecated Methods
* `signData(asciiArmoredPrivateKey, privateKeyPassword, dataToSign)` - (Use `sign` instead) Signs the data using the private key
* `signB64Data(asciiArmoredPrivateKey, privateKeyPassword, dataToSignInB64)` - (Use `signB64` instead) - Signs data using the specified private key and password
* `setHashingAlgo(hashingAlgo)` - (Don't need to use anymore, fixed to SHA512) Sets the hashing algorithm (check the _Constants_)

### Errors

> TODO

## Contributing

If you want to contribute, see the [Contributing guidelines](CONTRIBUTING.md) before and feel free to send your contributions.
