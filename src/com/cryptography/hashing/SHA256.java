package com.cryptography.hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {

  public byte[] hash(byte[] bytes) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

    byte[] hash = messageDigest.digest(bytes);

    StringBuilder hexBuilder = new StringBuilder();

    for (byte b : hash) {
      hexBuilder.append(String.format("%02x", b));
    }

    return hexBuilder.toString().getBytes();
  }

}
