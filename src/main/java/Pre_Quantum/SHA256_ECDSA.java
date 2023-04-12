package Pre_Quantum;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class SHA256_ECDSA {

    ///@Param({"256", "512", "1024", "2048"})
    //static int plaintextSize;

    private static byte[] plaintext;
    private static KeyPairGenerator kpg;
    private static ECPublicKeyParameters publicKeyParameters;
    private static ECPrivateKeyParameters privateKeyParameters;
    private static ECDSASigner signer;
    private static ECDSASigner verifier;
    private static byte[] hash;
    private static byte[] output;
    private static BigInteger[] hashSigned;

    @Setup
    public void setup() throws Exception {
        // Selecting BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        // Creating data of size corresponding to size parameters.
        plaintext = new byte[1024];
        new Random().nextBytes(plaintext);
        // Key generation
        kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(new ECNamedCurveGenParameterSpec("secp256r1"), new SecureRandom()); // Elliptic curve pairing
        KeyPair kp = keyGeneration();
        signer = new ECDSASigner(); verifier = new ECDSASigner();
        // Getting public / private keys from keypair
        publicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(kp.getPublic());
        privateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(kp.getPrivate());

        hash = sha256Hashing(); hashSigned = ecdsaSign();
    }

    @Benchmark
    public static KeyPair keyGeneration() {
        return kpg.generateKeyPair();
    }

    @Benchmark
    public byte[] sha256Hashing() {
        SHA256Digest digest = new SHA256Digest();
        digest.update(plaintext, 0, plaintext.length);
        output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    @Benchmark
    public static BigInteger[] ecdsaSign() {
        signer.init(true, privateKeyParameters);
        return signer.generateSignature(hash);
    }

    @Benchmark
    public static boolean ecdsaVerify() {
        verifier.init(false, publicKeyParameters);
        return verifier.verifySignature(output, hashSigned[0], hashSigned[1]); // This takes 2 signature inputs as the BigInteger signing has an 'r' and 's' component
    }

    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" +
                "Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n";
    }

    private static void saveDataToFile(String data, String filePath) {
        try {
            File file = new File(filePath);
            File parent = file.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Couldn't create directory: " + parent);
            }
            FileWriter writer = new FileWriter(file, true);
            writer.write(data + System.lineSeparator());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getFilePath(String folderPath, String fileName) {
        // join the folder path and file name using the platform-specific file separator
        return folderPath + File.separator + fileName;
    }

    public static String decodeSignature(BigInteger[] signature) {
        return "Signature: " + Arrays.toString(signature) + System.lineSeparator() +
                "R: " + signature[0].toString(16) + System.lineSeparator() +
                "S: " + signature[1].toString(16) + System.lineSeparator();
    }

    public static void saveVerificationResult(boolean verify, String filePath) throws IOException {
        String verificationText = verify ? "Signature is valid" : "Signature is not valid";
        saveDataToFile(verificationText, filePath);
    }

    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static byte[] sha256Digest(byte[] plaintext) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(plaintext, 0, plaintext.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    public static BigInteger[] sha256Sign(byte[] digest, ECPrivateKeyParameters privateKeyParameters) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privateKeyParameters);
        signer.generateSignature(digest);
        return signer.generateSignature(digest);
    }

    public static Boolean sha256Verify(byte[] digest, BigInteger[] hash, ECPublicKeyParameters publicKeyParameters) {
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, publicKeyParameters);
        return verifier.verifySignature(digest, hash[0], hash[1]);
    }

    public static void main(String[] args) throws Exception {
        String foldersPath = "SHA256 BENCHMARKS/";
        File folder = new File(foldersPath);
        if (!folder.exists()) {
            if (folder.mkdirs()) {
                System.out.println("Created folder: " + foldersPath);
            } else {
                throw new RuntimeException("Failed to create folder: " + foldersPath);
            }
        }

        Options opt = new OptionsBuilder()
                .include(SHA256_ECDSA.class.getSimpleName())
                .resultFormat(ResultFormatType.CSV)
                .result("SHA256 BENCHMARKS/SHA256_Benchmarks.csv")
                .build();
        new Runner(opt).run();
        // Selecting BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        KeyPair keyPair;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        byte[] plaintext = new byte[2048];
        new Random().nextBytes(plaintext);
        // FIle locations
        String folderPath = "Benchmark Results/SHA256 Benchmarks/";
        String filePath = getFilePath(folderPath, "SHA256_Keys.txt");
        String signaturesFilePath = getFilePath(folderPath, "SHA256_Signatures.txt");
        String verifyFilePath = getFilePath(folderPath, "SHA256_Verification.txt");
        for (int i = 0; i < 3; i++) {
            // Creating key pairs
            keyPair = kpg.generateKeyPair();
            String keysString = getKeysAsString(keyPair);
            saveDataToFile(keysString, filePath);
            // Creating digests
            byte[] digest = sha256Digest(plaintext);
            String hashHexString = byteArrayToHexString(digest);
            saveDataToFile(hashHexString, signaturesFilePath);
            ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(keyPair.getPublic());
            ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(keyPair.getPrivate());
            // Creating signatures
            BigInteger[] hash = sha256Sign(digest, privateKeyParameters);
            String decodedSignature = decodeSignature(hash);
            saveDataToFile(decodedSignature, signaturesFilePath);
            // Verifying signatures
            Boolean verify = sha256Verify(digest, hash, publicKeyParameters);
            saveVerificationResult(verify, verifyFilePath);
        }
    }
}

