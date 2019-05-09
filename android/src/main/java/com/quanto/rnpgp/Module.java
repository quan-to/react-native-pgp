package com.quanto.rnpgp;

import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import chevronwrap.Chevronwrap;

public class Module extends ReactContextBaseJavaModule {
    private final String TAG = "ReactNativePGP";

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
            String fp = Chevronwrap.getKeyFingerprints(keyData);
            String[] fps = fp.split(",");
            WritableArray fpsArray = Arguments.createArray();

            for (String fp1 : fps) {
                fpsArray.pushString(fp1);
            }

            WritableMap resultMap = Arguments.createMap();

            resultMap.putInt("privateKeysLoaded", (int) privateKeysLoaded);
            resultMap.putArray("fingerprints", fpsArray);

            Log.d(TAG, "Loaded " + privateKeysLoaded + " private keys. Fingerprints: " + fp);

            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void unlockKey(final String fingerprint, final String password, Promise promise) {
        try {
            Log.d(TAG, "Unlocking key " + fingerprint);
            Chevronwrap.unlockKey(fingerprint, password);
            promise.resolve(true);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void verifySignature(final String data, final String signature, Promise promise) {
        try {
            boolean result = Chevronwrap.verifySignature(data.getBytes(), signature);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void verifyB64DataSignature(final String b64data, final String signature, Promise promise) {
        try {
            boolean result = Chevronwrap.verifyBase64DataSignature(b64data, signature);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void signB64(final String fingerprint, final String data, Promise promise) {
        try {
            String signature = Chevronwrap.signBase64Data(data, fingerprint);
            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("asciiArmoredSignature", signature);
            resultMap.putString("hashingAlgo", "SHA512"); // Chevron always use SHA512
            resultMap.putString("fingerprint", fingerprint);
            promise.resolve(resultMap);
            // endregion
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void sign(final String fingerprint, final String data, Promise promise) {
        try {
            String signature = Chevronwrap.signData(data.getBytes(), fingerprint);
            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("asciiArmoredSignature", signature);
            resultMap.putString("hashingAlgo", "SHA512"); // Chevron always use SHA512
            resultMap.putString("fingerprint", fingerprint);
            promise.resolve(resultMap);
            // endregion
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void signData(final String privKeyData, final String password, final String data, Promise promise) {
        Log.w(TAG, "Use of deprecated method signData. Please use sign instead.");
        try {
            // Fix Private Key from old iOS version that includes Public Key at the start
            String privKeyDataFixed = privKeyData.replaceAll("-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*-----END PGP PUBLIC KEY BLOCK-----", "");

            long n = Chevronwrap.loadKey(privKeyDataFixed);
            if (n == 0) {
                throw new Exception("No private key in specified data");
            }
            String fingerprint = getKeyFingerprint(privKeyDataFixed);
            Chevronwrap.unlockKey(fingerprint, password);

            sign(fingerprint, data, promise);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void signB64Data(final String privKeyData, final String password, final String b64Data, Promise promise) {
        Log.w(TAG, "Use of deprecated method signB64Data. Please use signB64 instead.");
        try {
            // Fix Private Key from old iOS version that includes Public Key at the start
            String privKeyDataFixed = privKeyData.replaceAll("-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*-----END PGP PUBLIC KEY BLOCK-----", "");

            long n = Chevronwrap.loadKey(privKeyDataFixed);
            if (n == 0) {
                throw new Exception("No private key in specified data");
            }

            String fingerprint = getKeyFingerprint(privKeyDataFixed);
            Chevronwrap.unlockKey(fingerprint, password);

            signB64(fingerprint, b64Data, promise);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    @Deprecated
    public void setHashingAlgo(final int hashingAlgo) {
        Log.e("Quanto PGP", "Use of deprecated call setHashingAlgo: Chevron uses fixed SHA512");
    }

    @ReactMethod
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
    public void generateKeyPair(final String userId, final int numBits, final String passphrase, Promise promise) {
        Log.d(TAG, "generateKeyPair");
        try {
            long st = System.currentTimeMillis();
            String key = Chevronwrap.generateKey(passphrase, userId, numBits);
            Chevronwrap.loadKey(key);
            String fingerprint = getKeyFingerprint(key);
            String publicKey = Chevronwrap.getPublicKey(fingerprint);

            int delta = (int) (System.currentTimeMillis() - st);

            Log.d(TAG, "Took " + delta + " ms to generate the key.");

            WritableMap resultMap = Arguments.createMap();
            resultMap.putString("publicKey", publicKey);
            resultMap.putString("privateKey", key);
            resultMap.putString("fingerprint", fingerprint);
            resultMap.putInt("generationTimeMs", delta);

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
        constants.put("SHA512", 0);
        return constants;
    }
}
