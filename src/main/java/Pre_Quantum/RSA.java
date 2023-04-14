package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
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
public class RSA {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static AsymmetricCipherKeyPair aKP;
    private RSAEngine encryptEngine; private RSAEngine decryptEngine;
    private byte[] signature;
    private byte[] encrypted;
    private byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"1024", "2048", "4096"})
    static int keySize;

    @Param({"117", "245", "501"})
    static int plaintextSize;
    // ************************ \\
    // * Section 5: Setup     * \\
    // ************************ \\
    @Setup
    public void setup() throws Exception {
        // Generating a random plaintext
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        // Generate KP for engines
        aKP = generateKey();
        // Getting ready for encryption
        encryptEngine = new RSAEngine(); encryptEngine.init(true, aKP.getPublic());
        decryptEngine = new RSAEngine(); decryptEngine.init(false, aKP.getPrivate());
        // Use these in other methods
        signature = sign(); encrypted = encrypt();
    }
    // ********************** \\
    // * Section 6: RSA     * \\
    // ********************** \\
    @Benchmark
    public byte[] encrypt() {
        return encryptEngine.processBlock(plaintext, 0 , plaintext.length);
    }

    @Benchmark
    public byte[] decrypt() {
        return decryptEngine.processBlock(encrypted, 0, encrypted.length);
    }

    @Benchmark
    public AsymmetricCipherKeyPair generateKey() {
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), keySize, 80));
        return kpg.generateKeyPair();
    }

    @Benchmark
    public byte[] sign() throws CryptoException {
        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        signer.init(true, aKP.getPrivate());
        signer.update(encrypted, 0, encrypted.length);
        return signer.generateSignature();
    }

    @Benchmark
    public boolean verify() {
        PSSSigner verifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        verifier.init(false, aKP.getPublic());
        verifier.update(encrypted, 0, encrypted.length);
        return verifier.verifySignature(signature);
    }
    // ************************************************************* \\
    // * Section 7: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] rsaEncrypt(AsymmetricCipherKeyPair kp, byte[] plaintext) {
        RSAEngine engine = new RSAEngine();
        engine.init(true, kp.getPublic());
        return engine.processBlock(plaintext, 0 , plaintext.length);
    }

    public static byte[] rsaDecrypt(AsymmetricCipherKeyPair kp, byte[] encrypted) {
        RSAEngine engine = new RSAEngine();
        engine.init(false, kp.getPrivate());
        return engine.processBlock(encrypted, 0, encrypted.length);
    }

    public static byte[] rsaSign(AsymmetricCipherKeyPair kp, byte[] encrypted) throws CryptoException {
        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        signer.init(true, kp.getPrivate());
        signer.update(encrypted, 0, encrypted.length);
        return signer.generateSignature();
    }

    public static boolean rsaVerify(AsymmetricCipherKeyPair kp, byte[] encrypted, byte[] signature) {
        PSSSigner verifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        verifier.init(false, kp.getPublic());
        verifier.update(encrypted, 0, encrypted.length);
        return verifier.verifySignature(signature);
    }

    private static void saveDataToFile(String data, String filePath) {
        try {
            File file = new File(filePath);
            File parent = file.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Couldn't create directory: " + parent);
            }
            FileWriter writer = new FileWriter(file, true);
            writer.write(data + System.lineSeparator() + System.lineSeparator());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getFilePath(String folderPath, String fileName) {
        return folderPath + File.separator + fileName;
    }

    public static byte[] convertKeyPairToByteArray(AsymmetricCipherKeyPair keyPair) throws IOException {
        AsymmetricKeyParameter privateKey = keyPair.getPrivate();
        AsymmetricKeyParameter publicKey = keyPair.getPublic();

        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(privateKeyInfo.getEncoded());
        byteArrayOutputStream.write(publicKeyInfo.getEncoded());

        return byteArrayOutputStream.toByteArray();
    }

    public static String decodeEncrypted(byte[] text) {
        return "Encrypted plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static String decodeDecrypted(byte[] text) {
        return "Decrypted plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }
    public static String decodeEncryptedSign(byte[] text) {
        return "Signed encrypted plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static String decodePlaintext(byte[] text) {
        return "Plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static void saveByteArrayComparisonResult(byte[] array1, byte[] array2, String filePath) {
        boolean arraysAreEqual = Arrays.equals(array1, array2);
        String comparisonText = arraysAreEqual ? "The decrypted ciphertext matches the plaintext." : "The decrypted ciphertext does not match the plaintext.";
        saveDataToFile(comparisonText, filePath);
    }

    public static void saveVerificationResult(boolean verify, String filePath) throws IOException {
        String verificationText = verify ? "Signature is valid" : "Signature is not valid";
        saveDataToFile(verificationText, filePath);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String foldersPath = "Benchmark Results/Pre-Quantum/RSA Benchmarks/";
        String plaintextFilePath = getFilePath(foldersPath, "RSA-Plaintext.txt");
        String rsa1024KeyFilePath = getFilePath(foldersPath, "RSA-1024/Keys.txt"); String rsa2048KeyFilePath = getFilePath(foldersPath, "RSA-2048/Keys.txt"); String rsa4096KeyFilePath = getFilePath(foldersPath, "RSA-4096/Keys.txt");
        String rsa1024EncryptFilePath = getFilePath(foldersPath, "RSA-1024/Encrypted.txt"); String rsa2048EncryptFilePath = getFilePath(foldersPath, "RSA-2048/Encrypted.txt"); String rsa4096EncryptFilePath = getFilePath(foldersPath, "RSA-4096/Encrypted.txt");
        String decrypt1024FilePath = getFilePath(foldersPath, "RSA-1024/Decrypted.txt"); String decrypt2048FilePath = getFilePath(foldersPath, "RSA-2048/Decrypted.txt"); String decrypt4096FilePath = getFilePath(foldersPath, "RSA-4096/Decrypted.txt");
        String verify1024EncryptFilePath = getFilePath(foldersPath, "RSA-1024/VerifyEncryption.txt"); String verify2048EncryptFilePath = getFilePath(foldersPath, "RSA-2048/VerifyEncryption.txt"); String verify4096EncryptFilePath = getFilePath(foldersPath, "RSA-4096/VerifyEncryption.txt");
        String sig1024FilePath = getFilePath(foldersPath, "RSA-1024/Signatures.txt"); String sig2048FilePath = getFilePath(foldersPath, "RSA-2048/Signatures.txt"); String sig4096FilePath = getFilePath(foldersPath, "RSA-4096/Signatures.txt");
        String verify1024FilePath = getFilePath(foldersPath, "RSA-1024/VerifySignatures.txt"); String verify2048FilePath = getFilePath(foldersPath, "RSA-2048/VerifySignatures.txt"); String verify4096FilePath = getFilePath(foldersPath, "RSA-4096/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            // Random plaintext
            byte[] plaintext = new byte[117];
            new SecureRandom().nextBytes(plaintext);
            SecureRandom random = new SecureRandom();
            random.nextBytes(plaintext);
            String decodedPlaintext = decodePlaintext(plaintext);
            saveDataToFile(decodedPlaintext, plaintextFilePath);
            // Generate KPG for key pair
            RSAKeyPairGenerator rsa1024KPG = new RSAKeyPairGenerator(); RSAKeyPairGenerator rsa2048KPG = new RSAKeyPairGenerator(); RSAKeyPairGenerator rsa4096KPG = new RSAKeyPairGenerator();
            rsa1024KPG.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 1024, 80)); rsa2048KPG.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 80)); rsa4096KPG.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 4096, 80));
            // Creating key pair
            AsymmetricCipherKeyPair rsa1024KP = rsa1024KPG.generateKeyPair(); AsymmetricCipherKeyPair rsa2048KP = rsa2048KPG.generateKeyPair(); AsymmetricCipherKeyPair rsa4096KP = rsa4096KPG.generateKeyPair();
            byte[] rsa1024KeyPair = convertKeyPairToByteArray(rsa1024KP); byte[] rsa2048KeyPair = convertKeyPairToByteArray(rsa2048KP); byte[] rsa4096KeyPair = convertKeyPairToByteArray(rsa4096KP);
            String decoded1024KP = decodePlaintext(rsa1024KeyPair); String decoded2048KP = decodePlaintext(rsa2048KeyPair); String decoded4096KP = decodePlaintext(rsa4096KeyPair);
            saveDataToFile(decoded1024KP, rsa1024KeyFilePath); saveDataToFile(decoded2048KP, rsa2048KeyFilePath); saveDataToFile(decoded4096KP, rsa4096KeyFilePath);
            // Encrypting plaintext
            byte[] rsa1024Encrypted = rsaEncrypt(rsa1024KP, plaintext); byte[] rsa2048Encrypted = rsaEncrypt(rsa2048KP, plaintext); byte[] rsa4096Encrypted = rsaEncrypt(rsa4096KP, plaintext);
            String rsa1024DecodeEncrypted = decodeEncrypted(rsa1024Encrypted); String rsa2048DecodeEncrypted = decodeEncrypted(rsa1024Encrypted); String rsa4096DecodeEncrypted = decodeEncrypted(rsa1024Encrypted);
            saveDataToFile(rsa1024DecodeEncrypted, rsa1024EncryptFilePath); saveDataToFile(rsa2048DecodeEncrypted, rsa2048EncryptFilePath); saveDataToFile(rsa4096DecodeEncrypted, rsa4096EncryptFilePath);
            // Decrypting ciphertext
            byte[] rsa1024Decrypted = rsaDecrypt(rsa1024KP, rsa1024Encrypted); byte[] rsa2048Decrypted = rsaDecrypt(rsa2048KP, rsa2048Encrypted); byte[] rsa4096Decrypted = rsaDecrypt(rsa4096KP, rsa4096Encrypted);
            String rsa1024DecodeDecrypted = decodeDecrypted(rsa1024Decrypted); String rsa2048DecodeDecrypted = decodeDecrypted(rsa2048Decrypted); String rsa4096DecodeDecrypted = decodeDecrypted(rsa4096Decrypted);
            saveDataToFile(rsa1024DecodeDecrypted, decrypt1024FilePath); saveDataToFile(rsa2048DecodeDecrypted, decrypt2048FilePath); saveDataToFile(rsa4096DecodeDecrypted, decrypt4096FilePath);
            saveByteArrayComparisonResult(rsa1024Decrypted, plaintext, verify1024EncryptFilePath); saveByteArrayComparisonResult(rsa2048Decrypted, plaintext, verify2048EncryptFilePath); saveByteArrayComparisonResult(rsa4096Decrypted, plaintext, verify4096EncryptFilePath);
            // Signing ciphertext
            byte[] rsa1024SignedCiphertext = rsaSign(rsa1024KP, rsa1024Encrypted); byte[] rsa2048SignedCiphertext = rsaSign(rsa2048KP, rsa2048Encrypted); byte[] rsa4096SignedCiphertext = rsaSign(rsa4096KP, rsa4096Encrypted);
            String rsa1024DecodeSignedCiphertext = decodeEncryptedSign(rsa1024SignedCiphertext); String rsa2048DecodeSignedCiphertext = decodeEncryptedSign(rsa2048SignedCiphertext); String rsa4096DecodeSignedCiphertext = decodeEncryptedSign(rsa4096SignedCiphertext);
            saveDataToFile(rsa1024DecodeSignedCiphertext, sig1024FilePath); saveDataToFile(rsa2048DecodeSignedCiphertext, sig2048FilePath); saveDataToFile(rsa4096DecodeSignedCiphertext, sig4096FilePath);
            // Verifying signatures
            boolean rsa1024Verify = rsaVerify(rsa1024KP, rsa1024Encrypted, rsa1024SignedCiphertext); boolean rsa2048Verify = rsaVerify(rsa2048KP, rsa2048Encrypted, rsa2048SignedCiphertext); boolean rsa4096Verify = rsaVerify(rsa4096KP, rsa4096Encrypted, rsa4096SignedCiphertext);
            saveVerificationResult(rsa1024Verify, verify1024FilePath); saveVerificationResult(rsa2048Verify, verify2048FilePath); saveVerificationResult(rsa4096Verify, verify4096FilePath);
        }
    }
}

