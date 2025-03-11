package com.cryptography;

import com.cryptography.asymmetric.ECC;
import com.cryptography.asymmetric.RSA;
import com.cryptography.hashing.SHA256;
import com.cryptography.symmetric.AES;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Main {

  public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
    //AES
    var aes = new AES();

    //execute symmetric encryption with AES algorithm
    byte[] encryptedBytesAES = aes.encrypt("Encrypting with AES is fun".getBytes());

    //saves file in the secure folder
    Files.write(Path.of("secure-folder/aes-encrypted-file.enc"), encryptedBytesAES);

    byte[] decryptedBytesAES = aes.decrypt(Base64.getDecoder().decode(encryptedBytesAES));

    //saves file in the public folder
    Files.write(Path.of("public-folder/aes-decrypted-file.txt"), decryptedBytesAES);

    //RSA
    var rsa = new RSA();

    byte[] encryptedBytesRSA = rsa.encrypt("Encrypting with RSA is fun".getBytes());

    //saves file in the secure folder
    Files.write(Path.of("secure-folder/rsa-encrypted-file.enc"), encryptedBytesRSA);

    var decryptedBytesRSA = rsa.decrypt(Base64.getDecoder().decode(encryptedBytesRSA));

    //saves file in the public folder
    Files.write(Path.of("public-folder/rsa-decrypted-file.txt"), decryptedBytesRSA);

    //ECC
    ECC ecc = new ECC();

    byte[] encryptedBytesECC = ecc.encrypt("Encrypting with ECC is fun".getBytes());

    //saves file in the secure folder
    Files.write(Path.of("secure-folder/ecc-encrypted-file.enc"), encryptedBytesECC);

    byte[] decryptedBytesECC = ecc.decrypt(Base64.getDecoder().decode(encryptedBytesECC));

    //saves file in the public folder
    Files.write(Path.of("public-folder/ecc-decrypted-file.txt"), decryptedBytesECC);

    //plus hashing with SHA-256
    //SHA-256
    var sha256 = new SHA256();

    byte[] hashSha256 = sha256.hash("Hashing with SHA-256 sounds cool".getBytes());

    Files.write(Path.of("public-folder/sha256-hash.enc"), hashSha256);
  }

}