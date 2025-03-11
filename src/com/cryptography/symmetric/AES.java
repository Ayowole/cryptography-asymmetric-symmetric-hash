package com.cryptography.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES {

  private final SecretKey secretKey;
  private final Cipher cipher;

  //constructor to initialize and keep in memory the secret key
  public AES() throws NoSuchAlgorithmException, NoSuchPaddingException {
    //specifies the key generator algorithm as AES
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

    //defines the key size
    keyGenerator.init(256);

    //generates the key
    secretKey = keyGenerator.generateKey();

    //specifies the cipher algorithm
    cipher = Cipher.getInstance("AES");
  }

  public byte[] encrypt(byte[] bytes)
    throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //initiates encrypt mode
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    //encodes the encrypted bytes to base64
    return Base64.getEncoder().encode(cipher.doFinal(bytes));
  }

  public byte[] decrypt(byte[] bytes)
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    //specify the cipher algorithm
    Cipher cipher = Cipher.getInstance("AES");

    //init decrypt mode
    cipher.init(Cipher.DECRYPT_MODE, secretKey);

    //returns the decrypted bytes
    return cipher.doFinal(bytes);
  }

}
