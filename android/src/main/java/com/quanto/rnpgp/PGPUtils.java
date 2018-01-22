package com.quanto.rnpgp;

import com.quanto.rnpgp.Interfaces.StreamHandler;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Created by Lucas Teske on 14/11/17.
 */

class PGPUtils {

  static String hashAlgoToString(int hashAlgo) {
    switch (hashAlgo) {
      case HashAlgorithmTags.DOUBLE_SHA:
        return "DOUBLESHA";
      case HashAlgorithmTags.HAVAL_5_160:
        return "HAVAL5_160";
      case HashAlgorithmTags.MD2:
        return "MD2";
      case HashAlgorithmTags.MD5:
        return "MD5";
      case HashAlgorithmTags.RIPEMD160:
        return "RIPEMD160";
      case HashAlgorithmTags.SHA1:
        return "SHA1";
      case HashAlgorithmTags.SHA224:
        return "SHA224";
      case HashAlgorithmTags.SHA256:
        return "SHA256";
      case HashAlgorithmTags.SHA384:
        return "SHA384";
      case HashAlgorithmTags.SHA512:
        return "SHA512";
      case HashAlgorithmTags.TIGER_192:
        return "TIGER192";
      default:
        return "Unknown";
    }
  }

  static PGPSecretKey getSecretKey(String privateKeyData) throws IOException, PGPException {
    PGPPrivateKey privKey = null;
    try (InputStream privStream = new ArmoredInputStream(new ByteArrayInputStream(privateKeyData.getBytes("UTF-8")))) {
      PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privStream), new JcaKeyFingerprintCalculator());
      Iterator keyRingIter = pgpSec.getKeyRings();
      while (keyRingIter.hasNext()) {
        PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
        Iterator keyIter = keyRing.getSecretKeys();
        while (keyIter.hasNext()) {
          PGPSecretKey key = (PGPSecretKey)keyIter.next();

          if (key.isSigningKey()) {
            return key;
          }
        }
      }
    }
    throw new IllegalArgumentException("Can't find signing key in key ring.");
  }

  static PGPPrivateKey decryptArmoredPrivateKey(PGPSecretKey secretKey, String password) throws IOException, PGPException {
    return  secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
  }

  static String signArmoredAscii(PGPPrivateKey privateKey, String data, int signatureAlgo) throws IOException, PGPException {
    String signature = null;
    final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), signatureAlgo));
    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
    ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
    try( BCPGOutputStream outputStream = new BCPGOutputStream( new ArmoredOutputStream(signatureOutput)) ) {
      Utils.processStringAsStream(data, new StreamHandler() {
        @Override
        public void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException {
          signatureGenerator.update(buffer, offset, length);
        }
      });
      signatureGenerator.generate().encode(outputStream);
    }

    signature = new String(signatureOutput.toByteArray(), "UTF-8");

    return signature;
  }

  static String signArmoredAscii(PGPPrivateKey privateKey, byte[] data, int signatureAlgo) throws IOException, PGPException {
    String signature = null;
    final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), signatureAlgo));
    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
    ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
    try( BCPGOutputStream outputStream = new BCPGOutputStream( new ArmoredOutputStream(signatureOutput)) ) {
      Utils.processByteArrayAsStream(data, new StreamHandler() {
        @Override
        public void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException {
          signatureGenerator.update(buffer, offset, length);
        }
      });
      signatureGenerator.generate().encode(outputStream);
    }

    signature = new String(signatureOutput.toByteArray(), "UTF-8");

    return signature;
  }

  static PGPKeyRingGenerator generateKeyRingGenerator(String userId, int numBits, char[] passphrase) throws Exception  {
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

    PGPDigestCalculator sha1DigestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
    PGPDigestCalculator sha512DigestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA512);

    PBESecretKeyEncryptor secretKeyEncryptor = (
      new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha512DigestCalculator)
    )
      .build(passphrase);

    PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
      PGPSignature.NO_CERTIFICATION,
      rsaKeyPairSign,
      userId,
      sha1DigestCalculator,
      signHashGenerator.generate(),
      null,
      new BcPGPContentSignerBuilder(rsaKeyPairSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512),
      secretKeyEncryptor
    );

    keyRingGen.addSubKey(rsaKeyPairEncrypt, encryptHashGenerator.generate(), null);

    return keyRingGen;
  }
}
