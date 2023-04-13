package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class SHA256_ECDSA {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static byte[] plaintext;
    private static KeyPairGenerator kpg;
    private static ECPublicKeyParameters publicKeyParameters;
    private static ECPrivateKeyParameters privateKeyParameters;
    private static ECDSASigner signer;
    private static ECDSASigner verifier;
    private static byte[] hash;
    private static byte[] output;
    private static BigInteger[] hashSigned;

    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;

    @Param({"secp256r1", "secp256k1", "brainpoolP256r1"})
    static String ecName;
    // ************************ \\
    // * Section 5: Setup     * \\
    // ************************ \\
    @Setup
    public void setup() throws Exception {
        // Selecting BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        // Creating data of size corresponding to size parameters.
        plaintext = new byte[plaintextSize];
        new Random().nextBytes(plaintext);
        // Key generation
        kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(new ECNamedCurveGenParameterSpec(ecName), new SecureRandom()); // Elliptic curve pairing
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
    // ************************************************************** \\
    // * Section 12: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
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

    public static void main(String[] args) throws Exception {
        // Selecting BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        // FIle locations
        String folderPath = "Benchmark Results/Pre-Quantum/SHA256-EC Benchmarks/";
        String plaintextFile = getFilePath(folderPath, "SHA256-EC/Plaintext.txt");
        String r1FilePath = getFilePath(folderPath, "SHA256-EC/SECP256R1/Keys.txt"); String k1FilePath = getFilePath(folderPath, "SHA256-EC/SECP256K1/Keys.txt"); String bpFilePath = getFilePath(folderPath, "SHA256-EC/BRAINPOOLP256R1/Keys.txt");
        String r1DigestFilePath = getFilePath(folderPath, "SHA256-EC/SECP256R1/Digest.txt"); String k1DigestFilePath = getFilePath(folderPath, "SHA256-EC/SECP256K1/Digest.txt"); String bpDigestFilePath = getFilePath(folderPath, "SHA256-EC/BRAINPOOLP256R1/Digest.txt");
        String r1SignaturesFilePath = getFilePath(folderPath, "SHA256-EC/SECP256R1/Signatures.txt"); String k1SignaturesFilePath = getFilePath(folderPath, "SHA256-EC/SECP256K1/Signatures.txt"); String bpSignaturesFilePath = getFilePath(folderPath, "SHA256-EC/BRAINPOOLP256R1/Signatures.txt");
        String r1VerifyFilePath = getFilePath(folderPath, "SHA256-EC/SECP256R1/VerifySignatures.txt"); String k1VerifyFilePath = getFilePath(folderPath, "SHA256-EC/SECP256K1/VerifySignatures.txt"); String bpVerifyFilePath = getFilePath(folderPath, "SHA256-EC/BRAINPOOLP256R1/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new Random().nextBytes(plaintext);
            String decodedPlaintext = decodePlaintext(plaintext);
            saveDataToFile(decodedPlaintext, plaintextFile);
            // Creating KG for key pair
            KeyPairGenerator r1KPG = KeyPairGenerator.getInstance("ECDSA", "BC"); r1KPG.initialize(new ECNamedCurveGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPairGenerator k1KPG = KeyPairGenerator.getInstance("ECDSA", "BC"); k1KPG.initialize(new ECNamedCurveGenParameterSpec("secp256k1"), new SecureRandom());
            KeyPairGenerator bpKPG = KeyPairGenerator.getInstance("ECDSA", "BC"); bpKPG.initialize(new ECNamedCurveGenParameterSpec("brainpoolP256r1"), new SecureRandom());
            // Creating key pair
            KeyPair r1KeyPair = r1KPG.generateKeyPair(); KeyPair k1KeyPair = k1KPG.generateKeyPair(); KeyPair bpKeyPair = bpKPG.generateKeyPair();
            String r1KeysString = getKeysAsString(r1KeyPair); String k1KeysString = getKeysAsString(k1KeyPair); String bpKeysString = getKeysAsString(bpKeyPair);
            saveDataToFile(r1KeysString, r1FilePath); saveDataToFile(k1KeysString, k1FilePath); saveDataToFile(bpKeysString, bpFilePath);
            // Creating digests
            byte[] r1Digest = sha256Digest(plaintext); byte[] k1Digest = sha256Digest(plaintext); byte[] bpDigest = sha256Digest(plaintext);
            String r1HashHexString = byteArrayToHexString(r1Digest); String k1HashHexString = byteArrayToHexString(k1Digest); String bpHashHexString = byteArrayToHexString(bpDigest);
            saveDataToFile(r1HashHexString, r1DigestFilePath); saveDataToFile(k1HashHexString, k1DigestFilePath); saveDataToFile(bpHashHexString, bpDigestFilePath);
            ECPublicKeyParameters r1PublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(r1KeyPair.getPublic()); ECPrivateKeyParameters r1PrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(r1KeyPair.getPrivate());
            ECPublicKeyParameters k1PublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(k1KeyPair.getPublic()); ECPrivateKeyParameters k1PrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(k1KeyPair.getPrivate());
            ECPublicKeyParameters bpPublicKeyParameters = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(bpKeyPair.getPublic()); ECPrivateKeyParameters bpPrivateKeyParameters = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(bpKeyPair.getPrivate());
            // Creating signatures
            BigInteger[] r1Hash = sha256Sign(r1Digest, r1PrivateKeyParameters); BigInteger[] k1Hash = sha256Sign(k1Digest, k1PrivateKeyParameters); BigInteger[] bpHash = sha256Sign(bpDigest, bpPrivateKeyParameters);
            String r1DecodedSignature = decodeSignature(r1Hash); String k1DecodedSignature = decodeSignature(k1Hash); String bpDecodedSignature = decodeSignature(bpHash);
            saveDataToFile(r1DecodedSignature, r1SignaturesFilePath); saveDataToFile(k1DecodedSignature, k1SignaturesFilePath); saveDataToFile(bpDecodedSignature, bpSignaturesFilePath);
            // Verifying signatures
            Boolean r1Verify = sha256Verify(r1Digest, r1Hash, r1PublicKeyParameters); Boolean k1Verify = sha256Verify(k1Digest, k1Hash, k1PublicKeyParameters); Boolean bpVerify = sha256Verify(bpDigest, bpHash, bpPublicKeyParameters);
            saveVerificationResult(r1Verify, r1VerifyFilePath); saveVerificationResult(k1Verify, k1VerifyFilePath); saveVerificationResult(bpVerify, bpVerifyFilePath);
        }
    }
}