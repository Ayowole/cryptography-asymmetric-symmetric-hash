package com.cryptography.asymmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ECC {

  private final KeyPair keyPair;
  private final Cipher cipher;

  public ECC() throws NoSuchAlgorithmException, NoSuchPaddingException {
    //specifies the key pair algorithm as ECC
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECC");

    //defines the key size
    keyPairGenerator.initialize(1024);

    //generates the key pair
    keyPair = keyPairGenerator.generateKeyPair();

    //specifies the cipher algorithm as ECC
    cipher = Cipher.getInstance("ECC");
  }

  public byte[] encrypt(byte[] bytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //initiates encrypt mode with the public key
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

    //returns encrypted bytes encoded with base64
    return Base64.getEncoder().encode(cipher.doFinal(bytes));
  }

  public byte[] decrypt(byte[] bytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //initiates decrypt mode
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

    //returns decrypted bytes
    return cipher.doFinal(bytes);
  }

}
