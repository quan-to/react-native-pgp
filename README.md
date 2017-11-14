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
react-native link react-native-openpgp
```

Note: Run `npm install -g rnpm` if you haven't installed RNPM (React-Native Package Manager) yet! Alternatively you can add the Android and iOS modules library by following the official guide.

### Usage

```javascript
import { NativeModules } from 'react-native';
const RNPGP = NativeModules.ReactNativePGP;
```

### Example

#### Generating Key-Pair

```javascript
const userName = 'myUsername';
const keyBits = 4096;
const keyPassword = 'mySuperSecretPassword';

const keyPair = await RNPGP.generateKeyPair(userName, keyBits, keyPassword);
// Returns an object with privateKey and publicKey in ASCII Armored Format
console.log(keyPair.privateKey);
console.log(keyPair.publicKey);
```

#### Signing data

```javascript
const privateKey = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----`;

const privateKeyPassword = 'mySuperSecretPassword';
const dataToSign = 'I signed this, no one else!';

const signed = await RNPGP.signData(privateKey, privateKeyPassword, dataToSign);
// Returns an object with asciiArmoredSignature, fingerPrint and hashingAlgo

console.log(signed.asciiArmoredSignature); // "-----BEGIN PGP SIGNATURE----- ... -----END PGP SIGNATURE-----"
```

### Methods

* `generateKeyPair(userName, keyBits, keyPassword)` - Generates a public/private keyPair and encrypts the private key with specified password.
* `signData(asciiArmoredPrivateKey, privateKeyPassword, dataToSign)` - Signs the data using the private key
* `setHashingAlgo(hashingAlgo)` - Sets the hashing algorithm (check the )Constants_)

### Erros

> TODO

## Contributing

If you want to contribute, see the [Contributing guidelines](CONTRIBUTING.md) before and feel free to send your contributions.