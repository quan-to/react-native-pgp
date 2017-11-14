package com.quanto.rnpgp;

import android.util.Base64;
import android.widget.Toast;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Module extends ReactContextBaseJavaModule {

  private static final String DURATION_SHORT_KEY = "SHORT";
  private static final String DURATION_LONG_KEY = "LONG";

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
  public void verifySignature(String pubKey, String data, String signature, Promise promise) {
    // TODO
    promise.reject(new Exception("Not Implemented yet"));
  }

  @ReactMethod
  public void signData(String privKey, String password, String data, Promise promise) {
    // TODO
    promise.reject(new Exception("Not Implemented yet"));
  }

  @ReactMethod
  public void generateKeyPair(String userId, int numBits, String passphrase, Promise promise) {
    try {
      WritableMap resultMap = Arguments.createMap();
      PGPKeyRingGenerator keyGenerator = generateKeyRingGenerator(userId, numBits, passphrase.toCharArray());

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

      resultMap.putString("fingerPrint", bytesToHex(secretKeyRing.getPublicKey().getFingerprint()));

      promise.resolve(resultMap);
    } catch(Exception e) {
      promise.reject(new Exception(e.getMessage()));
    }
  }

  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

  private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  private final static PGPKeyRingGenerator generateKeyRingGenerator(String userId, int numBits, char[] passphrase)
    throws Exception
  {
    RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();

    keyPairGenerator.init(
      new RSAKeyGenerationParameters(
        BigInteger.valueOf(0x10001),
        new SecureRandom(),
        numBits,
        12
      )
    );

    PGPKeyPair rsaKeyPairSign = new BcPGPKeyPair(
      PGPPublicKey.RSA_SIGN,
      keyPairGenerator.generateKeyPair(),
      new Date()
    );

    PGPKeyPair rsaKeyPairEncrypt = new BcPGPKeyPair(
      PGPPublicKey.RSA_ENCRYPT,
      keyPairGenerator.generateKeyPair(),
      new Date()
    );

    PGPSignatureSubpacketGenerator signHashGenerator = new PGPSignatureSubpacketGenerator();

    signHashGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);

    signHashGenerator.setPreferredSymmetricAlgorithms(
      false,
      new int[] {
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128
      }
    );

    signHashGenerator.setPreferredHashAlgorithms(
      false,
      new int[] {
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA1,    // Not recommended
        HashAlgorithmTags.SHA224,  // Not recommended
      }
    );

    signHashGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

    PGPSignatureSubpacketGenerator encryptHashGenerator = new PGPSignatureSubpacketGenerator();

    encryptHashGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

    PGPDigestCalculator sha1DigestCalculator   = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
    PGPDigestCalculator sha256DigestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

    PBESecretKeyEncryptor secretKeyEncryptor = (
      new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256DigestCalculator)
    )
      .build(passphrase);

    PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
      PGPSignature.NO_CERTIFICATION,
      rsaKeyPairSign,
      userId,
      sha1DigestCalculator,
      signHashGenerator.generate(),
      null,
      new BcPGPContentSignerBuilder(rsaKeyPairSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
      secretKeyEncryptor
    );

    keyRingGen.addSubKey(rsaKeyPairEncrypt, encryptHashGenerator.generate(), null);

    return keyRingGen;
  }

  @Override
  public String getName() {
    return "ReactNativePGP";
  }

  @Override
  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put(DURATION_SHORT_KEY, Toast.LENGTH_SHORT);
    constants.put(DURATION_LONG_KEY, Toast.LENGTH_LONG);
    return constants;
  }

  @ReactMethod
  public void show(String message, int duration) {
    Toast.makeText(getReactApplicationContext(), message, duration).show();
  }
}
