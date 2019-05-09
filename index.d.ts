type RandomBytesCallback = (data: string) => void

// Result data from loadKey call
type LoadKeyResult = {
    // Number of loaded private keys
    privateKeysLoaded: number;

    // Fingerprints of the keys that were loaded
    fingerprints: string[];
}

// Signature Data
type SignatureResult = {
    // ASCII Armored PGP Signature
    asciiArmoredSignature: string;

    // Hashing Algorithm used on the Signature
    hashingAlgo: string;

    // Fingerprint of the key used to sign
    fingerprint: string;
}

// Generated Key Result
type GenerateKeyResult = {
    // ASCII Armored Public Key
    publicKey: string;

    // ASCII Armored Encrypted Private Key
    privateKey: string;

    // Key Fingerprint
    fingerprint: string;

    // Number of milliseconds took to generate the key
    delta: number;
}

declare namespace ReactNativePGP {
    // Generate a base64 encoded byte array from Operating System secure random
    export function randomBytes(size: number, cb: RandomBytesCallback);

    // Loads a private or public key into the memory keyring
    export function loadKey(keyData: string): Promise<LoadKeyResult>;

    // Unlocks a already loaded private key to be used
    export function unlockKey(fingerprint: string, password: string): Promise<boolean>;

    // Verifies a signature using a already loaded public key
    export function verifySignature(data: string, signature: string): Promise<boolean>;

    // Verifies a signature using a already loaded public key.
    // The b64data is a raw binary data encoded in base64 string
    export function verifyB64Signature(data: string, signature: string): Promise<boolean>;

    // Signs data using a already loaded and unlocked private key
    export function signB64(fingerprint: string, b64data: string): Promise<SignatureResult>;

    // Signs data using a already loaded and unlocked private key.
    // The b64data is a raw binary data encoded in base64 string
    export function sign(fingerprint: string, b64data: string): Promise<SignatureResult>;

    // Re-encrypts the input key using newPassword
    export function changeKeyPassword(key: string, oldPassword: string, newPassword: string): Promise<string>;

    // Generates a new key using specified bits and identifier and encrypts it using the specified password
    export function generateKeyPair(userId: string, numBits: number, password: string): Promise<GenerateKeyResult>;

    // Signs data using the specified private key and password
    // @deprecated Use sign
    export function signData(privKeyData: string, password: string, data: string): Promise<SignatureResult>;

    // Signs data using the specified private key and password
    // The b64data is a raw binary data encoded in base64 string
    // @deprecated Use signB64
    export function signB64Data(privKeyData: string, password: string, b64data: string): Promise<SignatureResult>;

    // Sets the hashing Algorithm to be used by signer
    // @deprecated Fixed to SHA512
    export function setHashingAlgo(hashingAlgo: number);
}
