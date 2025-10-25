package ru.nsu.kozlov;

import java.io.*;
import java.security.*;

public class CreateCAKey {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java CreateCAKey <output_file>");
            return;
        }

        String outputFile = args[0];

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        try (FileOutputStream fos = new FileOutputStream(outputFile);
             DataOutputStream dos = new DataOutputStream(fos)) {

            byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
            dos.writeInt(privateKeyBytes.length);
            dos.write(privateKeyBytes);
        }

        System.out.println("CA private key saved to: " + outputFile);
        System.out.println("Private key format: PKCS#8");
    }
}