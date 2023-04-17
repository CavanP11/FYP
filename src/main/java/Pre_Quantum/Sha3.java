package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.openjdk.jmh.annotations.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 4, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class Sha3 {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static ECDSASigner signer; private static ECDSASigner verifier;

    private static ECPublicKeyParameters publicKeyParameters; private static ECPrivateKeyParameters privateKeyParameters;

    private static byte[] sha3Hash; private static BigInteger[] sha3Sig;

    private static byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;

    @Param({"secp256r1", "secp256k1", "brainpoolP256r1"})
    static String ecName;
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // Generate some random data to hash
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        // Creating keypair
        KeyPair sha3KP = sha3KeyGeneration();
        // Creating signer instances
        signer = new ECDSASigner(); verifier = new ECDSASigner();
        // Getting key parameters
        privateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(sha3KP.getPrivate());
        publicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(sha3KP.getPublic());

        sha3Hash = sha3Hashing(); sha3Sig = sha3Sign();
    }
    // ******************** \\
    // * Section 6: Sha 3 * \\
    // ******************** \\
    @Benchmark
    public static KeyPair sha3KeyGeneration() throws Exception {
        KeyPairGenerator sha3KPG = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(ecName);
        sha3KPG.initialize(ecSpec, new SecureRandom());
        return  sha3KPG.generateKeyPair();
    }
    @Benchmark
    public static byte[] sha3Hashing() {
        SHA3Digest sha3 = new SHA3Digest(512);
        sha3.update(plaintext, 0, plaintext.length);
        byte[] hash = new byte[sha3.getDigestSize()];
        sha3.doFinal(hash, 0);
        return hash;
    }

    @Benchmark
    public static BigInteger[] sha3Sign() {
        signer.init(true, privateKeyParameters);
        return signer.generateSignature(sha3Hash);
    }

    @Benchmark
    public static boolean sha3Verify() {
        verifier.init(false, publicKeyParameters);
        return verifier.verifySignature(sha3Hash, sha3Sig[0], sha3Sig[1]); // This takes 2 signature inputs as the BigInteger signing has an 'r' and 's' component
    }
    // ************************************************************* \\
    // * Section 7: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] sha3Digest(byte[] plaintext) {
        SHA3Digest digest = new SHA3Digest(512);
        digest.update(plaintext, 0, plaintext.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return output;
    }

    public static BigInteger[] sha3Sign(byte[] digest, ECPrivateKeyParameters privateKeyParameters) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privateKeyParameters);
        signer.generateSignature(digest);
        return signer.generateSignature(digest);
    }

    public static Boolean sha3Verify(byte[] digest, BigInteger[] hash, ECPublicKeyParameters publicKeyParameters) {
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, publicKeyParameters);
        return verifier.verifySignature(digest, hash[0], hash[1]);
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

    public static String decodePlaintext(byte[] text) {
        return "Plaintext:\n" + Base64.getEncoder().encodeToString(text) + "\n";
    }

    public static void saveVerificationResult(boolean verify, String filePath) {
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

    public static void writeBytesToFile(byte[] bytes, String filePath) throws IOException {
        Path path = Paths.get(filePath);
        // Ensure the directories exist
        Path parentDir = path.getParent();
        if (parentDir != null) {
            Files.createDirectories(parentDir);
        }
        // Create the file if it doesn't exist
        try {
            Files.createFile(path);
        } catch (FileAlreadyExistsException e) {
            // Ignore this exception, as the file already exists, and we can continue writing the content
        }
        // Write the content to the file
        Files.write(path, bytes);
    }

    public static void writeBigIntegerArrayToFile(BigInteger[] bigIntegers, String filePath) throws IOException {
        // Convert the BigInteger array to a byte array
        ByteBuffer byteBuffer = ByteBuffer.allocate(bigIntegers.length * 8);
        for (BigInteger bigInteger : bigIntegers) {
            byteBuffer.putLong(bigInteger.longValue());
        }
        byte[] bytes = byteBuffer.array();

        // Write the byte array to a file using the provided writeBytesToFile method
        writeBytesToFile(bytes, filePath);
    }

    public static byte[] toByteArray(KeyPair keyPair) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        objectOutputStream.writeObject(keyPair.getPrivate());
        objectOutputStream.writeObject(keyPair.getPublic());
        objectOutputStream.flush();
        return outputStream.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        // Selecting BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        // FIle locations
        String folderPath = "Benchmark Results/Pre-Quantum/SHA3 Benchmarks/";
        String plaintextFile = getFilePath(folderPath, "Plaintext.txt"); String plaintextFileDecoded = getFilePath(folderPath, "Decoded_Plaintext.txt");

        String r1FilePath = getFilePath(folderPath, "Keys/SECP256R1/Encoded/Keys.txt"); String r1FilePathDecoded = getFilePath(folderPath, "Keys/SECP256R1/Decoded/Keys.txt");
        String r1DigestFilePath = getFilePath(folderPath, "Digest/SECP256R1/Encoded/Digest.txt"); String r1DigestFilePathDecoded = getFilePath(folderPath, "Digest/SECP256R1/Decoded/Digest.txt");
        String r1SignaturesFilePath = getFilePath(folderPath, "Signatures/SECP256R1/Encoded/Signatures.txt"); String r1SignaturesFilePathDecoded = getFilePath(folderPath, "Signatures/SECP256R1/Decoded/Signatures.txt");
        String r1VerifyFilePath = getFilePath(folderPath, "VerifySignatures/SECP256R1/VerifySignatures.txt");

        String k1FilePath = getFilePath(folderPath, "Keys/SECP256K1/Encoded/Keys.txt"); String k1FilePathDecoded = getFilePath(folderPath, "Keys/SHA3-EC/SECP256K1/Decoded/Keys.txt");
        String k1DigestFilePath = getFilePath(folderPath, "Digest/SECP256K1/Encoded/Digest.txt"); String k1DigestFilePathDecoded = getFilePath(folderPath, "Digest/SECP256K1/Decoded/Digest.txt");
        String k1SignaturesFilePath = getFilePath(folderPath, "Signatures/SECP256K1/Encoded/Signatures.txt"); String k1SignaturesFilePathDecoded = getFilePath(folderPath, "Signatures/SECP256K1/Decoded/Signatures.txt");
        String k1VerifyFilePath = getFilePath(folderPath, "VerifySignatures/SECP256K1/VerifySignatures.txt");

        String bpFilePath = getFilePath(folderPath, "Keys/BRAINPOOLP256R1/Encoded/Keys.txt"); String bpFilePathDecoded = getFilePath(folderPath, "Keys/BRAINPOOLP256R1/Decoded/Keys.txt");
        String bpDigestFilePath = getFilePath(folderPath, "Digest/BRAINPOOLP256R1/Encoded/Digest.txt"); String bpDigestFilePathDecoded = getFilePath(folderPath, "Digest/BRAINPOOLP256R1/Decoded/Digest.txt");
        String bpSignaturesFilePath = getFilePath(folderPath, "Signatures/BRAINPOOLP256R1/Encoded/Signatures.txt"); String bpSignaturesFilePathDecoded = getFilePath(folderPath, "Signatures/BRAINPOOLP256R1/Decoded/Signatures.txt");
        String bpVerifyFilePath = getFilePath(folderPath, "VerifySignatures/BRAINPOOLP256R1/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new Random().nextBytes(plaintext);
            // Encoded plaintext
            writeBytesToFile(plaintext, plaintextFile);
            // Decoded plaintext
            String decodedPlaintext = decodePlaintext(plaintext);
            saveDataToFile(decodedPlaintext, plaintextFileDecoded);
            // Creating KG for key pair
            KeyPairGenerator r1KPG = KeyPairGenerator.getInstance("ECDSA", "BC"); r1KPG.initialize(new ECNamedCurveGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPairGenerator k1KPG = KeyPairGenerator.getInstance("ECDSA", "BC"); k1KPG.initialize(new ECNamedCurveGenParameterSpec("secp256k1"), new SecureRandom());
            KeyPairGenerator bpKPG = KeyPairGenerator.getInstance("ECDSA", "BC"); bpKPG.initialize(new ECNamedCurveGenParameterSpec("brainpoolP256r1"), new SecureRandom());
            // Creating key pair
            KeyPair r1KeyPair = r1KPG.generateKeyPair(); KeyPair k1KeyPair = k1KPG.generateKeyPair(); KeyPair bpKeyPair = bpKPG.generateKeyPair();
            String r1KeysString = getKeysAsString(r1KeyPair); String k1KeysString = getKeysAsString(k1KeyPair); String bpKeysString = getKeysAsString(bpKeyPair);
            saveDataToFile(r1KeysString, r1FilePathDecoded); saveDataToFile(k1KeysString, k1FilePathDecoded); saveDataToFile(bpKeysString, bpFilePathDecoded);
            // Encoded key pairs
            byte[] r1KP = toByteArray(r1KeyPair); byte[] k1KP = toByteArray(k1KeyPair); byte[] bpKP = toByteArray(bpKeyPair);
            writeBytesToFile(r1KP, r1FilePath); writeBytesToFile(k1KP, k1FilePath); writeBytesToFile(bpKP, bpFilePath);
            // Creating digests
            byte[] r1Digest = sha3Digest(plaintext); byte[] k1Digest = sha3Digest(plaintext); byte[] bpDigest = sha3Digest(plaintext);
            String r1HashHexString = byteArrayToHexString(r1Digest); String k1HashHexString = byteArrayToHexString(k1Digest); String bpHashHexString = byteArrayToHexString(bpDigest);
            saveDataToFile(r1HashHexString, r1DigestFilePathDecoded); saveDataToFile(k1HashHexString, k1DigestFilePathDecoded); saveDataToFile(bpHashHexString, bpDigestFilePathDecoded);
            // Encoded digest
            writeBytesToFile(r1Digest, r1DigestFilePath); writeBytesToFile(k1Digest, k1DigestFilePath); writeBytesToFile(bpDigest, bpDigestFilePath);
            // Key parameters
            ECPublicKeyParameters r1PublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(r1KeyPair.getPublic()); ECPrivateKeyParameters r1PrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(r1KeyPair.getPrivate());
            ECPublicKeyParameters k1PublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(k1KeyPair.getPublic()); ECPrivateKeyParameters k1PrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(k1KeyPair.getPrivate());
            ECPublicKeyParameters bpPublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(bpKeyPair.getPublic()); ECPrivateKeyParameters bpPrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(bpKeyPair.getPrivate());
            // Creating signatures
            BigInteger[] r1Hash = sha3Sign(r1Digest, r1PrivateKeyParameters); BigInteger[] k1Hash = sha3Sign(k1Digest, k1PrivateKeyParameters); BigInteger[] bpHash = sha3Sign(bpDigest, bpPrivateKeyParameters);
            String r1DecodedSignature = decodeSignature(r1Hash); String k1DecodedSignature = decodeSignature(k1Hash); String bpDecodedSignature = decodeSignature(bpHash);
            saveDataToFile(r1DecodedSignature, r1SignaturesFilePathDecoded); saveDataToFile(k1DecodedSignature, k1SignaturesFilePathDecoded); saveDataToFile(bpDecodedSignature, bpSignaturesFilePathDecoded);
            // Encoded hash
            writeBigIntegerArrayToFile(r1Hash, r1SignaturesFilePath); writeBigIntegerArrayToFile(k1Hash, k1SignaturesFilePath); writeBigIntegerArrayToFile(bpHash, bpSignaturesFilePath);
            // Verifying signatures
            Boolean r1Verify = sha3Verify(r1Digest, r1Hash, r1PublicKeyParameters); Boolean k1Verify = sha3Verify(k1Digest, k1Hash, k1PublicKeyParameters); Boolean bpVerify = sha3Verify(bpDigest, bpHash, bpPublicKeyParameters);
            saveVerificationResult(r1Verify, r1VerifyFilePath); saveVerificationResult(k1Verify, k1VerifyFilePath); saveVerificationResult(bpVerify, bpVerifyFilePath);
        }
    }
}