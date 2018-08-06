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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Module extends ReactContextBaseJavaModule {
  private static int signatureAlgo = HashAlgorithmTags.SHA512;

  public Module(ReactApplicationContext reactContext) {
    super(reactContext);
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
  public void verifySignature(final String pubKey, final String data, final String signature, Promise promise) {
    // TODO
    promise.reject(new Exception("Not Implemented yet"));
  }

  @ReactMethod
  public void signData(final String privKeyData, final String password, final String data, Promise promise) {
    try {
      // region Decode Private Key
      PGPSecretKey secKey = PGPUtils.getSecretKey(privKeyData);
      PGPPrivateKey privKey = PGPUtils.decryptArmoredPrivateKey(secKey, password);
      // endregion
      // region Sign Data
      String signature = PGPUtils.signArmoredAscii(privKey, data, signatureAlgo);
      WritableMap resultMap = Arguments.createMap();
      resultMap.putString("asciiArmoredSignature", signature);
      resultMap.putString("hashingAlgo",  PGPUtils.hashAlgoToString(signatureAlgo));
      resultMap.putString("fingerPrint", Utils.bytesToHex(secKey.getPublicKey().getFingerprint()));
      promise.resolve(resultMap);
      // endregion
    } catch (Exception e) {
      promise.reject(e);
    }
  }

  @ReactMethod
  public void signB64Data(final String privKeyData, final String password, final String b64Data, Promise promise) {
    try {
      // region Decode Base64
      byte[] data = Base64.decode(b64Data, Base64.DEFAULT);
      // endregion
      // region Decode Private Key
      PGPSecretKey secKey = PGPUtils.getSecretKey(privKeyData);
      PGPPrivateKey privKey = PGPUtils.decryptArmoredPrivateKey(secKey, password);
      // endregion
      // region Sign Data
      String signature = PGPUtils.signArmoredAscii(privKey, data, signatureAlgo);
      WritableMap resultMap = Arguments.createMap();
      resultMap.putString("asciiArmoredSignature", signature);
      resultMap.putString("hashingAlgo",  PGPUtils.hashAlgoToString(signatureAlgo));
      resultMap.putString("fingerPrint", Utils.bytesToHex(secKey.getPublicKey().getFingerprint()));
      promise.resolve(resultMap);
      // endregion
    } catch (Exception e) {
      promise.reject(e);
    }
  }

  @ReactMethod
  public void setHashingAlgo(final int hashingAlgo) {
    String hashName = PGPUtils.hashAlgoToString(hashingAlgo); // Man, that's REALLY bad I know. Please FIXME
    if (hashName.equalsIgnoreCase("unknown")) {
      throw new IllegalArgumentException("Value " + hashingAlgo + " is not a valid algorithm for hashing.");
    }

    signatureAlgo = hashingAlgo;
  }

  @ReactMethod
  public void changeKeyPassword(final String key, final String oldPassword, final String newPassword, Promise promise) {
    try {
      // region Decode Base64
      PGPSecretKey secKey = PGPUtils.getSecretKey(key);
      // endregion
      PGPSecretKey reencryptedKey = PGPUtils.reencryptArmoredPrivateKey(secKey, oldPassword, newPassword);
      ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
      ArmoredOutputStream armoredPrivOutputStream  = new ArmoredOutputStream(privateKeyOutputStream);
      reencryptedKey.encode(armoredPrivOutputStream);
      armoredPrivOutputStream.close();
      promise.resolve(privateKeyOutputStream.toString("UTF-8"));
    } catch (Exception e) {
      promise.reject(e);
    }
  }

  @ReactMethod
  public void generateKeyPair(final String userId, final int numBits, final String passphrase, Promise promise) {
    Log.d("ReactNativePGP", "generateKeyPair");
    try {
      WritableMap resultMap = Arguments.createMap();
      PGPKeyRingGenerator keyGenerator = PGPUtils.generateKeyRingGenerator(userId, numBits, passphrase.toCharArray());

      // public key
      PGPPublicKeyRing publicKeyRing              = keyGenerator.generatePublicKeyRing();
      ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
      ArmoredOutputStream armoredPubOutputStream  = new ArmoredOutputStream(publicKeyOutputStream);

      publicKeyRing.encode(armoredPubOutputStream);
      armoredPubOutputStream.close();
      resultMap.putString("publicKey", publicKeyOutputStream.toString("UTF-8"));

      // private key
      PGPSecretKeyRing secretKeyRing               = keyGenerator.generateSecretKeyRing();
      ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
      ArmoredOutputStream armoredPrivOutputStream  = new ArmoredOutputStream(privateKeyOutputStream);

      secretKeyRing.encode(armoredPrivOutputStream);
      armoredPrivOutputStream.close();
      resultMap.putString("privateKey", privateKeyOutputStream.toString("UTF-8"));
      resultMap.putString("fingerPrint", Utils.bytesToHex(secretKeyRing.getPublicKey().getFingerprint()));

      promise.resolve(resultMap);
    } catch(Exception e) {
      promise.reject(new Exception(e.getMessage()));
    }
  }

  @Override
  public String getName() {
    return "ReactNativePGP";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put(PGPUtils.hashAlgoToString(HashAlgorithmTags.SHA1), HashAlgorithmTags.SHA1);
    constants.put(PGPUtils.hashAlgoToString(HashAlgorithmTags.SHA256), HashAlgorithmTags.SHA256);
    constants.put(PGPUtils.hashAlgoToString(HashAlgorithmTags.SHA384), HashAlgorithmTags.SHA384);
    constants.put(PGPUtils.hashAlgoToString(HashAlgorithmTags.SHA512), HashAlgorithmTags.SHA512);
    return constants;
  }
}
