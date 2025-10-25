package ru.nsu.kozlov;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class Server {
    private static final int KEY_SIZE = 8192;
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    private final int port;
    private final int generatorThreads;
    private final PrivateKey caPrivateKey;
    private final X500Name issuerName;
    private final AtomicLong certificateSerial = new AtomicLong(1);

    private final ConcurrentHashMap<String, CompletableFuture<KeyPairResult>> keyCache = new ConcurrentHashMap<>();
    private final ExecutorService generatorExecutor;
    private final ExecutorService virtualThreadExecutor;

    public Server(int port, int generatorThreads, PrivateKey caPrivateKey, X500Name issuerName) {
        this.port = port;
        this.generatorThreads = generatorThreads;
        this.caPrivateKey = caPrivateKey;
        this.issuerName = issuerName;

        this.generatorExecutor = Executors.newFixedThreadPool(generatorThreads);
        this.virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();

        Security.addProvider(new BouncyCastleProvider());
    }

    public void start() throws IOException {
        try (ServerSocketChannel serverChannel = ServerSocketChannel.open()) {
            serverChannel.bind(new InetSocketAddress(port));
            serverChannel.configureBlocking(false);

            System.out.println("Server started on port " + port);
            System.out.println("Using " + generatorThreads + " generator threads");

            while (true) {
                SocketChannel clientChannel = serverChannel.accept();
                if (clientChannel != null) {
                    virtualThreadExecutor.execute(() -> handleClient(clientChannel));
                }
            }
        }
    }

    private void handleClient(SocketChannel clientChannel) {
        try {
            clientChannel.configureBlocking(false);

            String clientName = readClientName(clientChannel);
            if (clientName == null) {
                clientChannel.close();
                return;
            }

            System.out.println("Received request for: " + clientName);

            CompletableFuture<KeyPairResult> keyPairFuture = keyCache.computeIfAbsent(
                    clientName,
                    name -> generateKeyPairAsync(name)
            );

            KeyPairResult result = keyPairFuture.get();
            sendKeyPair(clientChannel, result);

            clientChannel.close();

        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
            try {
                clientChannel.close();
            } catch (IOException ex) {
                // Ignore
            }
        }
    }

    private String readClientName(SocketChannel channel) throws IOException, InterruptedException {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        StringBuilder nameBuilder = new StringBuilder();

        int attempts = 0;
        while (attempts < 100) { // Timeout protection
            int bytesRead = channel.read(buffer);
            if (bytesRead == -1) {
                return null; // Client disconnected
            }

            if (bytesRead > 0) {
                buffer.flip();
                while (buffer.hasRemaining()) {
                    byte b = buffer.get();
                    if (b == 0) { // Null terminator
                        return nameBuilder.toString();
                    }
                    nameBuilder.append((char) b);
                }
                buffer.clear();
            }

            attempts++;
            Thread.sleep(10); // Small delay to prevent busy waiting
        }

        return null; // Timeout
    }

    private CompletableFuture<KeyPairResult> generateKeyPairAsync(String clientName) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                System.out.println("Generating key pair for: " + clientName);

                KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
                keyGen.initialize(KEY_SIZE);
                KeyPair keyPair = keyGen.generateKeyPair();

                X509Certificate certificate = createCertificate(clientName, keyPair);

                System.out.println("Key pair generated for: " + clientName);

                return new KeyPairResult(keyPair, certificate);

            } catch (Exception e) {
                throw new CompletionException("Failed to generate key pair for " + clientName, e);
            }
        }, generatorExecutor);
    }

    private X509Certificate createCertificate(String clientName, KeyPair keyPair) throws Exception {
        X500Name subjectName = new X500Name("CN=" + clientName);

        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(365)));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(certificateSerial.getAndIncrement()),
                notBefore,
                notAfter,
                subjectName,
                keyPair.getPublic()
        );

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        signerBuilder.setProvider("BC");

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signerBuilder.build(caPrivateKey)));
    }

    private void sendKeyPair(SocketChannel channel, KeyPairResult result) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            byte[] privateKeyBytes = result.keyPair().getPrivate().getEncoded();
            dos.writeInt(privateKeyBytes.length);
            dos.write(privateKeyBytes);

            byte[] certBytes = result.certificate().getEncoded();
            dos.writeInt(certBytes.length);
            dos.write(certBytes);

            byte[] data = baos.toByteArray();
            ByteBuffer buffer = ByteBuffer.allocate(4 + data.length);
            buffer.putInt(data.length);
            buffer.put(data);
            buffer.flip();

            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        } catch (CertificateEncodingException e) {
            throw new IOException("Failed to encode certificate", e);
        }
    }

    public void shutdown() {
        generatorExecutor.shutdown();
        virtualThreadExecutor.shutdown();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("Usage: java Server <port> <generator_threads> <ca_private_key_file> <issuer_name>");
            System.out.println("Example: java Server 8080 4 ca-private.key \"CN=My CA, O=My Organization\"");
            return;
        }

        int port = Integer.parseInt(args[0]);
        int generatorThreads = Integer.parseInt(args[1]);
        String caKeyFile = args[2];
        String issuerNameStr = args[3];

        PrivateKey caPrivateKey = loadPrivateKey(caKeyFile);
        X500Name issuerName = new X500Name(issuerNameStr);

        Server server = new Server(port, generatorThreads, caPrivateKey, issuerName);

        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdown));

        server.start();
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename);
             DataInputStream dis = new DataInputStream(fis)) {

            byte[] keyBytes = new byte[dis.readInt()];
            dis.readFully(keyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        }
    }

    private record KeyPairResult(KeyPair keyPair, X509Certificate certificate) {}
}