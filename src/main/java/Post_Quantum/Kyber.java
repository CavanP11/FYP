package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.openjdk.jmh.annotations.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@SuppressWarnings("unused")
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class Kyber {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPair k512KP; private static KeyPair k768KP; private static KeyPair k1024KP;
    private static KeyPair k512AesKP; private static KeyPair k768AesKP; private static KeyPair k1024AesKP;

    private static KeyPairGenerator k512KPG; private static KeyPairGenerator k768KPG; private static KeyPairGenerator k1024KPG;
    private static KeyPairGenerator k512AesKPG; private static KeyPairGenerator k768AesKPG; private static KeyPairGenerator k1024AesKPG;

    private static Cipher k512CipherWrap; private static Cipher k512CipherUnwrap;
    private static Cipher k768CipherWrap; private static Cipher k768CipherUnwrap;
    private static Cipher k1024CipherWrap; private static Cipher k1024CipherUnwrap;
    private static Cipher k512AesCipherWrap; private static Cipher k512AesCipherUnwrap;
    private static Cipher k768AesCipherWrap; private static Cipher k768AesCipherUnwrap;
    private static Cipher k1024AesCipherWrap; private static Cipher k1024AesCipherUnwrap;

    private static byte[] k512WB; private static byte[] k768WB; private static byte[] k1024WB;
    private static byte[] k512AesWB; private static byte[] k768AesWB; private static byte[] k1024AesWB;

    private static final byte[] k512KB = new byte[16]; private static final byte[] k768KB = new byte[24]; private static final byte[] k1024KB = new byte[32];
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating KPGs for KPs
        k512KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC"); k512KPG.initialize(KyberParameterSpec.kyber512, new SecureRandom());
        k768KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC"); k768KPG.initialize(KyberParameterSpec.kyber768, new SecureRandom());
        k1024KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC"); k1024KPG.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
        k512AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC"); k512AesKPG.initialize(KyberParameterSpec.kyber512_aes, new SecureRandom());
        k768AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC"); k768AesKPG.initialize(KyberParameterSpec.kyber768_aes, new SecureRandom());
        k1024AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC"); k1024AesKPG.initialize(KyberParameterSpec.kyber1024_aes, new SecureRandom());
        // Generate KeyPairs from benchmark methods. *NB -> These runs are not benchmarked, so performance not impacted.
        k512KP = k512KeyGen(); k768KP = k768KeyGen(); k1024KP = k1024KeyGen();
        k512AesKP = k512AesKeyGen(); k768AesKP = k768AesKeyGen(); k1024AesKP = k1024AesKeyGen();
        // Creating Wrapped and Unwrapped Cipher Instances to Avoid "Cipher not initiated" Errors. Wrapped = Encrypted. Unwrapped = Decrypted
        k512CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC"); k512CipherWrap.init(Cipher.WRAP_MODE, k512KP.getPublic(), new SecureRandom());
        k512CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC"); k512CipherUnwrap.init(Cipher.UNWRAP_MODE, k512KP.getPrivate());
        k768CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC"); k768CipherWrap.init(Cipher.WRAP_MODE, k768KP.getPublic(), new SecureRandom());
        k768CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC"); k768CipherUnwrap.init(Cipher.UNWRAP_MODE, k768KP.getPrivate());
        k1024CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC"); k1024CipherWrap.init(Cipher.WRAP_MODE, k1024KP.getPublic(), new SecureRandom());
        k1024CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC"); k1024CipherUnwrap.init(Cipher.UNWRAP_MODE, k1024KP.getPrivate());
        k512AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC"); k512AesCipherWrap.init(Cipher.WRAP_MODE, k512AesKP.getPublic(), new SecureRandom());
        k512AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC"); k512AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k512AesKP.getPrivate());
        k768AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC"); k768AesCipherWrap.init(Cipher.WRAP_MODE, k768AesKP.getPublic(), new SecureRandom());
        k768AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC"); k768AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k768AesKP.getPrivate());
        k1024AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC"); k1024AesCipherWrap.init(Cipher.WRAP_MODE, k1024AesKP.getPublic(), new SecureRandom());
        k1024AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC"); k1024AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k1024AesKP.getPrivate());
        // Getting wrapped bytes from methods.
        k512WB = k512WrapKey(); k768WB = k768WrapKey(); k1024WB = k1024WrapKey();
        k512AesWB = k512AesWrapKey(); k768AesWB = k768AesWrapKey(); k1024AesWB = k1024AesWrapKey();
    }
    // ************************ \\
    // * Section 6: Kyber 512 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair k512KeyGen() {
        return k512KPG.generateKeyPair();
    }

    @Benchmark
    public void k512EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k512KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k512KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k512WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k512CipherWrap.wrap(new SecretKeySpec(k512KB, "AES"));
    }

    @Benchmark
    public static Key k512UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k512CipherUnwrap.unwrap(k512WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************ \\
    // * Section 7: Kyber 768 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair k768KeyGen() {
        return k768KPG.generateKeyPair();
    }

    @Benchmark
    public void k768EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k768KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k768KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k768WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k768CipherWrap.wrap(new SecretKeySpec(k768KB, "AES"));
    }

    @Benchmark
    public static Key k768UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k768CipherUnwrap.unwrap(k768WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************* \\
    // * Section 8: Kyber 1024 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair k1024KeyGen() {
        return k1024KPG.generateKeyPair();
    }

    @Benchmark
    public void k1024EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k1024KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k1024KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k1024WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k1024CipherWrap.wrap(new SecretKeySpec(k1024KB, "AES"));
    }

    @Benchmark
    public static Key k1024UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k1024CipherUnwrap.unwrap(k1024WB, "AES", Cipher.SECRET_KEY);
    }
    // **************************** \\
    // * Section 9: Kyber 512 AES * \\
    // **************************** \\
    @Benchmark
    public static KeyPair k512AesKeyGen() {
        return k512AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k512AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k512AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k512AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k512AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k512AesCipherWrap.wrap(new SecretKeySpec(k512KB, "AES"));
    }

    @Benchmark
    public static Key k512AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k512AesCipherUnwrap.unwrap(k512AesWB, "AES", Cipher.SECRET_KEY);
    }
    // ***************************** \\
    // * Section 10: Kyber 768 AES * \\
    // ***************************** \\
    @Benchmark
    public static KeyPair k768AesKeyGen() {
        return k768AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k768AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k768AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k768AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k768AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k768AesCipherWrap.wrap(new SecretKeySpec(k768KB, "AES"));
    }

    @Benchmark
    public static Key k768AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k768AesCipherUnwrap.unwrap(k768AesWB, "AES", Cipher.SECRET_KEY);
    }
    // ****************************** \\
    // * Section 11: Kyber 1024 AES * \\
    // ****************************** \\
    @Benchmark
    public static KeyPair k1024AesKeyGen() {
        return k1024AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k1024AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC");
        keyGen.init(new KEMGenerateSpec(k1024AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k1024AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k1024AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k1024AesCipherWrap.wrap(new SecretKeySpec(k1024KB, "AES"));
    }

    @Benchmark
    public static Key k1024AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k1024AesCipherUnwrap.unwrap(k1024AesWB, "AES", Cipher.SECRET_KEY);
    }
    // ************************************************************** \\
    // * Section 12: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
    public static byte[] kyberWrapKey(KeyPair kp, Cipher cipher, byte[] keyByte) throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());
        return cipher.wrap(new SecretKeySpec(keyByte, "AES"));
    }

    public static Key kyberUnwrapKey(KeyPair kp, Cipher cipher, byte[] keyByte) throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        return cipher.unwrap(keyByte, "AES", Cipher.SECRET_KEY);
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

    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Public Key:\n " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n\n" +
                "Private Key:\n " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n\n";
    }

    private static String getFilePath(String folderPath, String fileName) {
        return folderPath + File.separator + fileName;
    }

    public static String decodeSignature(byte[] signature) {
        return "Signature: " + Base64.getEncoder().encodeToString(signature);
    }

    public static void saveKeyComparisonResult(Key key1, byte[] keyBytes, String filePath) {
        boolean keysAreEqual = compareKeys(key1, keyBytes);
        String comparisonText = keysAreEqual ? "The keys are the same." : "The keys are different.";
        saveDataToFile(comparisonText, filePath);
    }

    public static boolean compareKeys(Key key1, byte[] keyBytes) {
        byte[] key1Bytes = key1.getEncoded();
        return Arrays.equals(key1Bytes, keyBytes);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/Kyber Benchmarks/";
        String k512FilePath = getFilePath(foldersPath, "Kyber-512/Keys.txt"); String k512SigFilePath = getFilePath(foldersPath, "Kyber-512/Signatures.txt"); String k512VerifyFilePath = getFilePath(foldersPath, "Kyber-512/VerifySignatures.txt");
        String k512AesFilePath = getFilePath(foldersPath, "Kyber-512-Aes/Keys.txt"); String k512AesSigFilePath = getFilePath(foldersPath, "Kyber-512-Aes/Signatures.txt"); String k512AesVerifyFilePath = getFilePath(foldersPath, "Kyber-512-Aes/VerifySignatures.txt");
        String k768FilePath = getFilePath(foldersPath, "Kyber-768/Keys.txt"); String k768SigFilePath = getFilePath(foldersPath, "Kyber-768/Signatures.txt"); String k768VerifyFilePath = getFilePath(foldersPath, "Kyber-768/VerifySignatures.txt");
        String k768AesFilePath = getFilePath(foldersPath, "Kyber-768-Aes/Keys.txt"); String k768AesSigFilePath = getFilePath(foldersPath, "Kyber-768-Aes/Signatures.txt"); String k768AesVerifyFilePath = getFilePath(foldersPath, "Kyber-768-Quantum/Aes/VerifySignatures.txt");
        String k1024FilePath = getFilePath(foldersPath, "Kyber-1024/Keys.txt"); String k1024SigFilePath = getFilePath(foldersPath, "Kyber-1024/Signatures.txt"); String k1024VerifyFilePath = getFilePath(foldersPath, "Kyber-1024/VerifySignatures.txt");
        String k1024AesFilePath = getFilePath(foldersPath, "Kyber-1024-Aes/Keys.txt"); String k1024AesSigFilePath = getFilePath(foldersPath, "Kyber-1024-Aes/Signatures.txt"); String k1024AesVerifyFilePath = getFilePath(foldersPath, "Kyber-1024-Aes/VerifySignatures.txt");
        final byte[] k512KB = new byte[16]; final byte[] k768KB = new byte[24]; final byte[] k1024KB = new byte[32];
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            // Creating KPGs for key pairs
            k512KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC"); k512KPG.initialize(KyberParameterSpec.kyber512, new SecureRandom());
            k512AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC"); k512AesKPG.initialize(KyberParameterSpec.kyber512_aes, new SecureRandom());
            k768KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC"); k768KPG.initialize(KyberParameterSpec.kyber768, new SecureRandom());
            k768AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC"); k768AesKPG.initialize(KyberParameterSpec.kyber768_aes, new SecureRandom());
            k1024KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC"); k1024KPG.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
            k1024AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC"); k1024AesKPG.initialize(KyberParameterSpec.kyber1024_aes, new SecureRandom());
            // Creating key pairs
            KeyPair k512KP = k512KPG.generateKeyPair(); KeyPair k768KP = k768KPG.generateKeyPair(); KeyPair k1024KP = k1024KPG.generateKeyPair();
            KeyPair k512AesKP = k512AesKPG.generateKeyPair(); KeyPair k768AesKP = k768AesKPG.generateKeyPair(); KeyPair k1024AesKP = k1024AesKPG.generateKeyPair();
            String k512keysString = getKeysAsString(k512KP); String k768keysString = getKeysAsString(k768KP); String k1024keysString = getKeysAsString(k1024KP);
            String k512AeskeysString = getKeysAsString(k512AesKP); String k768AeskeysString = getKeysAsString(k768AesKP); String k1024AeskeysString = getKeysAsString(k1024AesKP);
            saveDataToFile(k512keysString, k512FilePath); saveDataToFile(k768keysString, k768FilePath); saveDataToFile(k1024keysString, k1024FilePath);
            saveDataToFile(k512AeskeysString, k512AesFilePath); saveDataToFile(k768AeskeysString, k768AesFilePath); saveDataToFile(k1024AeskeysString, k1024AesFilePath);
            // Creating ciphers
            Cipher k512Cipher = Cipher.getInstance(KyberParameterSpec.kyber512.getName(), "BCPQC"); Cipher k512AesCipher = Cipher.getInstance(KyberParameterSpec.kyber512_aes.getName(), "BCPQC");
            Cipher k768Cipher = Cipher.getInstance(KyberParameterSpec.kyber768.getName(), "BCPQC"); Cipher k768AesCipher = Cipher.getInstance(KyberParameterSpec.kyber768_aes.getName(), "BCPQC");
            Cipher k1024Cipher = Cipher.getInstance(KyberParameterSpec.kyber1024.getName(), "BCPQC"); Cipher k1024AesCipher = Cipher.getInstance(KyberParameterSpec.kyber1024_aes.getName(), "BCPQC");
            // Wrapping Key
            byte[] wrappedK512Key = kyberWrapKey(k512KP, k512Cipher, k512KB); byte[] wrappedK768Key = kyberWrapKey(k768KP, k768Cipher, k768KB); byte[] wrappedK1024Key = kyberWrapKey(k1024KP, k1024Cipher, k1024KB);
            byte[] wrappedK512AesKey = kyberWrapKey(k512AesKP, k512AesCipher, k512KB); byte[] wrappedK768AesKey = kyberWrapKey(k768AesKP, k768AesCipher, k768KB); byte[] wrappedK1024AesKey = kyberWrapKey(k1024AesKP, k1024AesCipher, k1024KB);
            String k512DecodedSignature = decodeSignature(wrappedK512Key); String k768DecodedSignature = decodeSignature(wrappedK768Key); String k1024DecodedSignature = decodeSignature(wrappedK1024Key);
            String k512AesDecodedSignature = decodeSignature(wrappedK512AesKey); String k768AesDecodedSignature = decodeSignature(wrappedK768AesKey); String k1024AesDecodedSignature = decodeSignature(wrappedK1024AesKey);
            saveDataToFile(k512DecodedSignature, k512SigFilePath); saveDataToFile(k768DecodedSignature, k768SigFilePath); saveDataToFile(k1024DecodedSignature, k1024SigFilePath);
            saveDataToFile(k512AesDecodedSignature, k512AesSigFilePath); saveDataToFile(k768AesDecodedSignature, k768AesSigFilePath); saveDataToFile(k1024AesDecodedSignature, k1024AesSigFilePath);
            // Unwrapping Key
            Key unWrapped512Key = kyberUnwrapKey(k512KP, k512Cipher, wrappedK512Key); Key unWrapped768Key = kyberUnwrapKey(k768KP, k768Cipher, wrappedK768Key); Key unWrapped1024Key = kyberUnwrapKey(k1024KP, k1024Cipher, wrappedK1024Key);
            Key unWrapped512AesKey = kyberUnwrapKey(k512AesKP, k512AesCipher, wrappedK512AesKey); Key unWrapped768AesKey = kyberUnwrapKey(k768AesKP, k768AesCipher, wrappedK768AesKey); Key unWrapped1024AesKey = kyberUnwrapKey(k1024AesKP, k1024AesCipher, wrappedK1024AesKey);
            saveKeyComparisonResult(unWrapped512Key, k512KB, k512VerifyFilePath); saveKeyComparisonResult(unWrapped768Key, k768KB, k768VerifyFilePath); saveKeyComparisonResult(unWrapped1024Key, k1024KB, k1024VerifyFilePath);
            saveKeyComparisonResult(unWrapped512AesKey, k512KB, k512AesVerifyFilePath); saveKeyComparisonResult(unWrapped768AesKey, k768KB, k768AesVerifyFilePath); saveKeyComparisonResult(unWrapped1024AesKey, k1024KB, k1024AesVerifyFilePath);
        }

    }
}
