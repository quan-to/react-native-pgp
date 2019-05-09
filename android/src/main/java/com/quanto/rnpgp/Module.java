package com.quanto.rnpgp;

import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import org.bouncycastle.bcpg.HashAlgorithmTags;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import chevronwrap.Chevronwrap;

public class Module extends ReactContextBaseJavaModule {
    public Module(ReactApplicationContext reactContext) {
        super(reactContext);
        Chevronwrap.touch();
    }

    private String getKeyFingerprint(String keydata) throws Exception {
        String fp = Chevronwrap.getKeyFingerprints(keydata);
        String[] fps = fp.split(",");

        if (fps.length == 0) {
            throw new Exception("No key in specified data");
        }

        return fps[0];
    }

    @ReactMethod
    public void randomBytes(int size, Callback success) {
        SecureRandom sr = new SecureRandom();
        byte[] output = new byte[size];
        sr.nextBytes(output);
        String string = Base64.encodeToString(output, Base64.DEFAULT);
        success.invoke(null, string);
    }

    @ReactMethod
    public void loadKey(final String keyData, Promise promise) {
        try {
            long privateKeysLoaded = Chevronwrap.loadKey(keyData);
            promise.resolve(privateKeysLoaded);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void unlockKey(final String fingerprint, final String password, Promise promise) {
        try {
            Chevronwrap.unlockKey(fingerprint, password);
            promise.resolve(true);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void verifySignature(final String pubKey, final String data, final String signature, Promise promise) {
        try {
            Chevronwrap.loadKey(pubKey);
        } catch (Exception e) {
            promise.reject(e);
        }
        try {
            boolean result = Chevronwrap.verifySignature(data.getBytes(), signature);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void signData(final String privKeyData, final String password, final String data, Promise promise) {
        try {
            // Fix Private Key from old iOS version that includes Public Key at the start
            String privKeyDataFixed = privKeyData.replaceAll("-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*-----END PGP PUBLIC KEY BLOCK-----", "");

            long n = Chevronwrap.loadKey(privKeyDataFixed);
            if (n == 0) {
                throw new Exception("No private key in specified data");
            }

            String fingerprint = getKeyFingerprint(privKeyDataFixed);
            String signature = Chevronwrap.signData(data.getBytes(), fingerprint);
            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("asciiArmoredSignature", signature);
            resultMap.putString("hashingAlgo", "SHA512"); // Chevron always use SHA512
            resultMap.putString("fingerPrint", fingerprint);
            promise.resolve(resultMap);
            // endregion
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void signB64Data(final String privKeyData, final String password, final String b64Data, Promise promise) {
        try {
            // Fix Private Key from old iOS version that includes Public Key at the start
            String privKeyDataFixed = privKeyData.replaceAll("-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*-----END PGP PUBLIC KEY BLOCK-----", "");

            long n = Chevronwrap.loadKey(privKeyDataFixed);
            if (n == 0) {
                throw new Exception("No private key in specified data");
            }

            String fingerprint = getKeyFingerprint(privKeyDataFixed);
            String signature = Chevronwrap.signBase64Data(b64Data, fingerprint);
            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("asciiArmoredSignature", signature);
            resultMap.putString("hashingAlgo", "SHA512"); // Chevron always use SHA512
            resultMap.putString("fingerPrint", fingerprint);
            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void setHashingAlgo(final int hashingAlgo) {
        Log.e("Quanto PGP", "DEPRECATED CALL setHashingAlgo: Chevron uses fixed SHA512");
    }

    @ReactMethod
    @Deprecated
    public void changeKeyPassword(final String key, final String oldPassword, final String newPassword, Promise promise) {
        try {
            // Fix Private Key from iOS version that includes Public Key at the start
            String privKeyDataFixed = key.replaceAll("-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*-----END PGP PUBLIC KEY BLOCK-----", "");
            String result = Chevronwrap.changeKeyPassword(privKeyDataFixed, oldPassword, newPassword);

            promise.resolve(result);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void generateKeyPair(final String userId, final int numBits, final String passphrase, Promise promise) {
        Log.d("ReactNativePGP", "generateKeyPair");
        try {

            String key = Chevronwrap.generateKey(passphrase, userId, numBits);
            Chevronwrap.loadKey(key);
            String fingerprint = getKeyFingerprint(key);

            String publicKey = Chevronwrap.getPublicKey(fingerprint);

            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("publicKey", publicKey);
            resultMap.putString("privateKey", key);
            resultMap.putString("fingerPrint", fingerprint);

            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @Override
    public String getName() {
        return "ReactNativePGP";
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("SHA512", HashAlgorithmTags.SHA512);
        return constants;
    }
}
