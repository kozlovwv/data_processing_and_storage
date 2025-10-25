package ru.nsu.kozlov;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class Client {
    private final String serverHost;
    private final int serverPort;
    private final String clientName;
    private final int delaySeconds;
    private final boolean exitBeforeReading;

    public Client(String serverHost, int serverPort, String clientName,
                  int delaySeconds, boolean exitBeforeReading) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.clientName = clientName;
        this.delaySeconds = delaySeconds;
        this.exitBeforeReading = exitBeforeReading;
    }

    public void run() throws Exception {
        System.out.println("Connecting to server " + serverHost + ":" + serverPort);
        System.out.println("Requesting keys for: " + clientName);

        try (SocketChannel channel = SocketChannel.open()) {
            channel.connect(new InetSocketAddress(serverHost, serverPort));

            byte[] nameBytes = clientName.getBytes();
            ByteBuffer nameBuffer = ByteBuffer.allocate(nameBytes.length + 1);
            nameBuffer.put(nameBytes);
            nameBuffer.put((byte) 0);
            nameBuffer.flip();

            while (nameBuffer.hasRemaining()) {
                channel.write(nameBuffer);
            }

            System.out.println("Request sent, waiting " + delaySeconds + " seconds...");

            Thread.sleep(delaySeconds * 1000L);

            if (exitBeforeReading) {
                System.out.println("Exiting before reading response (simulating crash)");
                System.exit(1);
            }

            KeyPairResult result = readKeyPair(channel);
            saveKeyPair(result, clientName);

            System.out.println("Key pair saved as " + clientName + ".key and " + clientName + ".crt");

        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            throw e;
        }
    }

    private KeyPairResult readKeyPair(SocketChannel channel) throws IOException {
        ByteBuffer lengthBuffer = ByteBuffer.allocate(4);
        while (lengthBuffer.hasRemaining()) {
            channel.read(lengthBuffer);
        }
        lengthBuffer.flip();
        int dataLength = lengthBuffer.getInt();

        ByteBuffer dataBuffer = ByteBuffer.allocate(dataLength);
        while (dataBuffer.hasRemaining()) {
            channel.read(dataBuffer);
        }
        dataBuffer.flip();

        byte[] data = new byte[dataLength];
        dataBuffer.get(data);

        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);

        try {
            int privateKeyLength = dis.readInt();
            byte[] privateKeyBytes = new byte[privateKeyLength];
            dis.readFully(privateKeyBytes);

            int certLength = dis.readInt();
            byte[] certBytes = new byte[certLength];
            dis.readFully(certBytes);

            PrivateKey privateKey = deserializePrivateKey(privateKeyBytes);
            X509Certificate certificate = deserializeCertificate(certBytes);

            return new KeyPairResult(privateKey, certificate);
        } catch (Exception e) {
            throw new IOException("Failed to deserialize key pair", e);
        }
    }

    private PrivateKey deserializePrivateKey(byte[] keyBytes) throws Exception {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new Exception("Failed to deserialize private key", e);
        }
    }

    private X509Certificate deserializeCertificate(byte[] certBytes) throws Exception {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (CertificateException e) {
            throw new Exception("Failed to deserialize certificate", e);
        }
    }

    private void saveKeyPair(KeyPairResult result, String baseName) throws Exception {
        // Save private key in PKCS8 format
        try (FileOutputStream fos = new FileOutputStream(baseName + ".key")) {
            fos.write(result.privateKey().getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream(baseName + ".crt")) {
            fos.write(result.certificate().getEncoded());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: java Client <server_host> <server_port> <client_name> [delay_seconds] [--exit-before-reading]");
            System.out.println("Example: java Client localhost 8080 alice 5");
            System.out.println("Example: java Client localhost 8080 bob 0 --exit-before-reading");
            return;
        }

        String serverHost = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String clientName = args[2];
        int delaySeconds = 0;
        boolean exitBeforeReading = false;

        for (int i = 3; i < args.length; i++) {
            if (args[i].equals("--exit-before-reading")) {
                exitBeforeReading = true;
            } else {
                try {
                    delaySeconds = Integer.parseInt(args[i]);
                } catch (NumberFormatException e) {
                    // Ignore non-numeric arguments
                }
            }
        }

        Client client = new Client(serverHost, serverPort, clientName, delaySeconds, exitBeforeReading);
        client.run();
    }

    private record KeyPairResult(PrivateKey privateKey, X509Certificate certificate) {}
}