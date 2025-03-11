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

public class RSA {

  private final KeyPair keyPair;
  private final Cipher cipher;

  //constructor to initialize and keep in memory the key pair
  public RSA() throws NoSuchAlgorithmException, NoSuchPaddingException {
    //specifies the key pair generator algorithm as RSA
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

    //defines the key size
    keyPairGenerator.initialize(2048);

    //generates the key pair
    keyPair = keyPairGenerator.generateKeyPair();

    //specifies the cipher algorithm RSA
    cipher = Cipher.getInstance("RSA");
  }

  public byte[] encrypt(byte[] bytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //initiates encrypt mode with the public key
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

    //encodes the encrypted bytes to base64
    return Base64.getEncoder().encode(cipher.doFinal(bytes));
  }

  public byte[] decrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //initiates decrypt mode
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

    //returns decrypted bytes
    return cipher.doFinal(bytes);
  }

}
