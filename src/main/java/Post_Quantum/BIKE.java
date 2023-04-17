package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.openjdk.jmh.annotations.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.assertTrue;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 2)
@Fork(1)
@State(Scope.Benchmark)
public class BIKE {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator bike128KPG; private static KeyPairGenerator bike192KPG; private static KeyPairGenerator bike256KPG;

    private static KeyPair bike128KP; private static KeyPair bike192KP; private static KeyPair bike256KP;

    private static Cipher bike128CipherWrap; private static Cipher bike128CipherUnwrap;
    private static Cipher bike192CipherWrap; private static Cipher bike192CipherUnwrap;
    private static Cipher bike256CipherWrap; private static Cipher bike256CipherUnwrap;

    private static byte[] bike128WB; private static byte[] bike192WB; private static byte[] bike256WB;

    private static Key key;
    // ******************** \\
    // * Section 4: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        key = new SecretKeySpec(keyBytes, "AES");
        // Creating KPGs for key pairs
        bike128KPG = KeyPairGenerator.getInstance("BIKE", "BCPQC"); bike128KPG.initialize(BIKEParameterSpec.bike128, new SecureRandom());
        bike192KPG = KeyPairGenerator.getInstance("BIKE", "BCPQC"); bike192KPG.initialize(BIKEParameterSpec.bike192, new SecureRandom());
        bike256KPG = KeyPairGenerator.getInstance("BIKE", "BCPQC"); bike256KPG.initialize(BIKEParameterSpec.bike256, new SecureRandom());
        // Generating key pairs
        bike128KP = bike128KeyGenerator(); bike192KP = bike192KeyGenerator(); bike256KP = bike256KeyGenerator();
        // Creating cipher instances to wrap key
        bike128CipherWrap = Cipher.getInstance("BIKE", "BCPQC"); bike128CipherWrap.init(Cipher.WRAP_MODE, bike128KP.getPublic());
        bike192CipherWrap = Cipher.getInstance("BIKE", "BCPQC"); bike192CipherWrap.init(Cipher.WRAP_MODE, bike192KP.getPublic());
        bike256CipherWrap = Cipher.getInstance("BIKE", "BCPQC"); bike256CipherWrap.init(Cipher.WRAP_MODE, bike256KP.getPublic());
        // Creating wrapped key
        bike128WB = bike128WrapKey(); bike192WB = bike192WrapKey(); bike256WB = bike256WrapKey();
        // Creating cipher instances to unwrap key
        bike128CipherUnwrap = Cipher.getInstance("BIKE", "BCPQC"); bike128CipherUnwrap.init(Cipher.UNWRAP_MODE, bike128KP.getPrivate());
        bike192CipherUnwrap = Cipher.getInstance("BIKE", "BCPQC"); bike192CipherUnwrap.init(Cipher.UNWRAP_MODE, bike192KP.getPrivate());
        bike256CipherUnwrap = Cipher.getInstance("BIKE", "BCPQC"); bike256CipherUnwrap.init(Cipher.UNWRAP_MODE, bike256KP.getPrivate());
    }
    // ************************ \\
    // * Section 5: BIKE 128 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair bike128KeyGenerator() {
        return bike128KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike128WrapKey() throws Exception {
        return bike128CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike128UnwrapKey() throws Exception {
        return bike128CipherUnwrap.unwrap(bike128WB, "AES", Cipher.SECRET_KEY);
    }

    @Benchmark
    public static void bike128KeyEncapsulation() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("BIKE", "BCPQC");
        keyGen.init(new KEMGenerateSpec(bike128KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(bike128KP.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
    // *********************** \\
    // * Section 6: BIKE 192 * \\
    // *********************** \\
    @Benchmark
    public static KeyPair bike192KeyGenerator() {
        return bike192KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike192WrapKey() throws Exception {
        return bike192CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike192UnwrapKey() throws Exception {
        return bike192CipherUnwrap.unwrap(bike192WB, "AES", Cipher.SECRET_KEY);
    }

    @Benchmark
    public static void bike192KeyEncapsulation() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("BIKE", "BCPQC");
        keyGen.init(new KEMGenerateSpec(bike192KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(bike192KP.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
    // ************************ \\
    // * Section 7: BIKE 256 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair bike256KeyGenerator() {
        return bike256KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike256WrapKey() throws Exception {
        return bike256CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike256UnwrapKey() throws Exception {
        return bike256CipherUnwrap.unwrap(bike256WB, "AES", Cipher.SECRET_KEY);
    }

    @Benchmark
    public static void bike256KeyEncapsulation() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("BIKE", "BCPQC");
        keyGen.init(new KEMGenerateSpec(bike256KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(bike256KP.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
    // ************************************************************* \\
    // * Section 8: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] bikeWrapKey(KeyPair kp, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("BIKE", "BCPQC");
        cipher.init(Cipher.WRAP_MODE, kp.getPublic());
        return cipher.wrap(key);
    }

    public static Key bikeUnwrapKey(KeyPair kp, byte[] wb) throws Exception {
        Cipher cipher = Cipher.getInstance("BIKE", "BCPQC");
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        return cipher.unwrap(wb, "AES", Cipher.SECRET_KEY);
    }

    public static boolean verifyEncap(SecretKeyWithEncapsulation key1, SecretKeyWithEncapsulation key2) {
        return Arrays.areEqual(key1.getEncoded(), key2.getEncoded());
    }

    public static void saveVerificationResult(boolean verify, String filePath) {
        String verificationText = verify ? "Encapsulation is valid" : "Encapsulation is not valid";
        saveDataToFile(verificationText, filePath);
    }

    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Bike Public Key:\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n\n" +
                "Bike Private Key:\n" + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n";
    }

    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
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

    private static void saveKeysToFile(SecretKeyWithEncapsulation key1, SecretKeyWithEncapsulation key2, String filePath) {
        try {
            File file = new File(filePath);
            File parent = file.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Couldn't create directory: " + parent);
            }
            FileWriter writer = new FileWriter(file, true);
            writer.write("Key 1:" + System.lineSeparator());
            writer.write(Base64.getEncoder().encodeToString(key1.getEncoded()) + System.lineSeparator() + System.lineSeparator());
            writer.write("Key 2:" + System.lineSeparator());
            writer.write(Base64.getEncoder().encodeToString(key2.getEncoded()) + System.lineSeparator() + System.lineSeparator());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String getFilePath(String folderPath, String fileName) {
        return folderPath + File.separator + fileName;
    }

    public static String keyToHexString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Hex.toHexString(keyBytes);
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

    private static String getKey(Key key) {
        return "Bike Wrapped Key:\n" + key + "\n\n";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String getKeys(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] pubKey = publicKey.getEncoded();
        byte[] privKey = privateKey.getEncoded();
        String result1 = new String(pubKey);
        String result2 = new String(privKey);
        return "Bike Public Key:\n" + result1 + "\n\n" +
                "Bike Private Key:\n" + result2 + "\n";
    }

    private static String getEncapKey(SecretKeyWithEncapsulation key1, SecretKeyWithEncapsulation key2) {
        String key1BytesHex = bytesToHex(key1.getEncoded());
        String key2BytesHex = bytesToHex(key2.getEncoded());
        return "Bike Encapsulation 1 Key:\n" + key1BytesHex + "\n\n" +
                "Bike Encapsulation 2 Key:\n" + key2BytesHex + "\n";
    }

    public static void saveKeyComparisonResult(Key key1, byte[] keyBytes, String filePath) {
        boolean keysAreEqual = compareKeys(key1, keyBytes);
        String comparisonText = keysAreEqual ? "The keys are the same." : "The keys are different.";
        saveDataToFile(comparisonText, filePath);
    }

    public static boolean compareKeys(Key key1, byte[] keyBytes) {
        byte[] key1Bytes = key1.getEncoded();
        return java.util.Arrays.equals(key1Bytes, keyBytes);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/BIKE Benchmarks/";
        // File locations for BIKE 128
        String file128Path = getFilePath(foldersPath, "BIKE-128/Encoded/Keys.txt"); String file128DecodedPath = getFilePath(foldersPath, "BIKE-128/Decoded/Decoded_Keys.txt");
        String wrapped128FilePath = getFilePath(foldersPath, "BIKE-128/Encoded/WrappedKey.txt"); String wrapped128DecodedFilePath = getFilePath(foldersPath, "BIKE-128/Decoded/Decoded_WrappedKey.txt");
        String unwrap128FilePath = getFilePath(foldersPath, "BIKE-128/Encoded/UnwrappedKey.txt"); String unwrap128DecodedFilePath = getFilePath(foldersPath, "BIKE-128/Decoded/Decoded_UnwrappedKey.txt");
        String encapFile128Path = getFilePath(foldersPath, "BIKE-128/Encoded/Encapsulation_Keys.txt"); String encapFile128DecodedPath = getFilePath(foldersPath, "BIKE-128/Decoded/Decoded_Encapsulation_Keys.txt");
        String unwrapVerifyFile128Path = getFilePath(foldersPath, "BIKE-128/VerifyWrapping.txt");
        String encapVerifyFile128Path = getFilePath(foldersPath, "BIKE-128/EncapsulationVerify.txt");
        // File locations for BIKE 192
        String file192Path = getFilePath(foldersPath, "BIKE-192/Encoded/Keys.txt"); String file192DecodedPath = getFilePath(foldersPath, "BIKE-192/Decoded/Decoded_Keys.txt");
        String wrapped192FilePath = getFilePath(foldersPath, "BIKE-192/Encoded/WrappedKey.txt"); String wrapped192DecodedFilePath = getFilePath(foldersPath, "BIKE-192/Decoded/Decoded_WrappedKey.txt");
        String unwrap192FilePath = getFilePath(foldersPath, "BIKE-192/Encoded/UnwrappedKey.txt"); String unwrap192DecodedFilePath = getFilePath(foldersPath, "BIKE-192/Decoded/Decoded_UnwrappedKey.txt");
        String encapFile192Path = getFilePath(foldersPath, "BIKE-192/Encoded/Encapsulation_Keys.txt"); String encapFile192DecodedPath = getFilePath(foldersPath, "BIKE-192/Decoded/Decoded_Encapsulation_Keys.txt");
        String unwrapVerifyFile192Path = getFilePath(foldersPath, "BIKE-192/VerifyWrapping.txt");
        String encapVerifyFile192Path = getFilePath(foldersPath, "BIKE-192/Encoded/EncapsulationVerify.txt");
        // File locations for BIKE 256
        String file256Path = getFilePath(foldersPath, "BIKE-256/Encoded/Keys.txt"); String file256DecodedPath = getFilePath(foldersPath, "BIKE-256/Decoded/Decoded_Keys.txt");
        String wrapped256FilePath = getFilePath(foldersPath, "BIKE-256/Encoded/WrappedKey.txt"); String wrapped256DecodedFilePath = getFilePath(foldersPath, "BIKE-256/Decoded/Decoded_WrappedKey.txt");
        String unwrap256FilePath = getFilePath(foldersPath, "BIKE-256/Encoded/UnwrappedKey.txt"); String unwrap256DecodedFilePath = getFilePath(foldersPath, "BIKE-256/Decoded/Decoded_UnwrappedKey.txt");
        String encapFile256Path = getFilePath(foldersPath, "BIKE-256/Encoded/Encapsulation_Keys.txt"); String encapFile256DecodedPath = getFilePath(foldersPath, "BIKE-256/Decoded/Decoded_Encapsulation_Keys.txt");
        String unwrapVerifyFile256Path = getFilePath(foldersPath, "BIKE-256/VerifyWrapping.txt");
        String encapVerifyFile256Path = getFilePath(foldersPath, "BIKE-256/EncapsulationVerify.txt");
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        Key key = new SecretKeySpec(keyBytes, "AES");
        for (int i = 0; i < 3; i++) {
            // Creating KPGs for key pairs
            KeyPairGenerator kpg128 = KeyPairGenerator.getInstance("BIKE", "BCPQC"); KeyPairGenerator kpg192 = KeyPairGenerator.getInstance("BIKE","BCPQC"); KeyPairGenerator kpg256 = KeyPairGenerator.getInstance("BIKE", "BCPQC");
            kpg128.initialize(BIKEParameterSpec.bike128, new SecureRandom()); kpg192.initialize(BIKEParameterSpec.bike192, new SecureRandom()); kpg256.initialize(BIKEParameterSpec.bike256, new SecureRandom());
            // Creating key pairs
            KeyPair kp128 = kpg128.generateKeyPair(); KeyPair kp192 = kpg192.generateKeyPair(); KeyPair kp256 = kpg256.generateKeyPair();
            String keys128String = getKeysAsString(kp128); String keys192String = getKeysAsString(kp192); String keys256String = getKeysAsString(kp256);
            saveDataToFile(keys128String, file128DecodedPath); saveDataToFile(keys192String, file192DecodedPath); saveDataToFile(keys256String, file256DecodedPath);
            String key128 = getKeys(kp128); String key192 = getKeys(kp192); String key256 = getKeys(kp256);
            saveDataToFile(key128, file128Path); saveDataToFile(key192, file192Path); saveDataToFile(key256, file256Path);
            // Wrapping keyBytes
            byte[] bike128WB = bikeWrapKey(kp128, key); byte[] bike192WB = bikeWrapKey(kp192, key); byte[] bike256WB = bikeWrapKey(kp256, key);
            String hash128HexString = byteArrayToHexString(bike128WB); String hash192HexString = byteArrayToHexString(bike192WB); String hash256HexString = byteArrayToHexString(bike256WB);
            writeBytesToFile(bike128WB, wrapped128FilePath); writeBytesToFile(bike192WB, wrapped192FilePath); writeBytesToFile(bike256WB, wrapped256FilePath);
            saveDataToFile(hash128HexString, wrapped128DecodedFilePath); saveDataToFile(hash192HexString, wrapped192DecodedFilePath); saveDataToFile(hash256HexString, wrapped256DecodedFilePath);
            // Unwrapping keyBytes
            Key unwrap128Bytes = bikeUnwrapKey(kp128, bike128WB); Key unwrap192Bytes = bikeUnwrapKey(kp192, bike192WB); Key unwrap256Bytes = bikeUnwrapKey(kp256, bike256WB);
            String un128Wrapped = keyToHexString(unwrap128Bytes); String un192Wrapped = keyToHexString(unwrap192Bytes); String un256Wrapped = keyToHexString(unwrap256Bytes);
            saveDataToFile(un128Wrapped, unwrap128DecodedFilePath); saveDataToFile(un192Wrapped, unwrap192DecodedFilePath); saveDataToFile(un256Wrapped, unwrap256DecodedFilePath);
            // Encoded unwrapped bytes
            String unwrapped128Key = getKey(unwrap128Bytes); String unwrapped192Key = getKey(unwrap192Bytes); String unwrapped256Key = getKey(unwrap256Bytes);
            saveDataToFile(unwrapped128Key, unwrap128FilePath); saveDataToFile(unwrapped192Key, unwrap192FilePath); saveDataToFile(unwrapped256Key, unwrap256FilePath);
            // Unwrapping verification
            saveKeyComparisonResult(unwrap128Bytes, keyBytes, unwrapVerifyFile128Path); saveKeyComparisonResult(unwrap192Bytes, keyBytes, unwrapVerifyFile192Path); saveKeyComparisonResult(unwrap256Bytes, keyBytes, unwrapVerifyFile256Path);
            // Creating key gens
            KeyGenerator bike128keyGen = KeyGenerator.getInstance("BIKE", "BCPQC"); bike128keyGen.init(new KEMGenerateSpec(kp128.getPublic(), "AES"), new SecureRandom());
            KeyGenerator bike192keyGen = KeyGenerator.getInstance("BIKE", "BCPQC"); bike192keyGen.init(new KEMGenerateSpec(kp192.getPublic(), "AES"), new SecureRandom());
            KeyGenerator bike256keyGen = KeyGenerator.getInstance("BIKE", "BCPQC"); bike256keyGen.init(new KEMGenerateSpec(kp256.getPublic(), "AES"), new SecureRandom());
            // Encapsulating KP with key
            SecretKeyWithEncapsulation bike128Enc1 = (SecretKeyWithEncapsulation)bike128keyGen.generateKey(); SecretKeyWithEncapsulation bike192Enc1 = (SecretKeyWithEncapsulation)bike192keyGen.generateKey(); SecretKeyWithEncapsulation bike256Enc1 = (SecretKeyWithEncapsulation)bike256keyGen.generateKey();
            bike128keyGen.init(new KEMExtractSpec(kp128.getPrivate(), bike128Enc1.getEncapsulation(), "AES")); bike192keyGen.init(new KEMExtractSpec(kp192.getPrivate(), bike192Enc1.getEncapsulation(), "AES")); bike256keyGen.init(new KEMExtractSpec(kp256.getPrivate(), bike256Enc1.getEncapsulation(), "AES"));
            SecretKeyWithEncapsulation bike128Enc2 = (SecretKeyWithEncapsulation)bike128keyGen.generateKey(); SecretKeyWithEncapsulation bike192Enc2 = (SecretKeyWithEncapsulation)bike192keyGen.generateKey(); SecretKeyWithEncapsulation bike256Enc2 = (SecretKeyWithEncapsulation)bike256keyGen.generateKey();
            // Decoded encapsulation keys
            saveKeysToFile(bike128Enc1, bike128Enc2, encapFile128DecodedPath); saveKeysToFile(bike192Enc1, bike192Enc2, encapFile192DecodedPath); saveKeysToFile(bike256Enc1, bike256Enc2, encapFile256DecodedPath);
            // Verify encapsulation keys
            boolean bike128Verify = verifyEncap(bike128Enc1, bike128Enc2); boolean bike192Verify = verifyEncap(bike192Enc1, bike192Enc2); boolean bike256Verify = verifyEncap(bike256Enc1, bike256Enc2);
            saveVerificationResult(bike128Verify, encapVerifyFile128Path); saveVerificationResult(bike192Verify, encapVerifyFile192Path); saveVerificationResult(bike256Verify, encapVerifyFile256Path);
            // Encoded encapsulation keys
            String encap128 = getEncapKey(bike128Enc1, bike128Enc2); String encap192 = getEncapKey(bike192Enc1, bike192Enc2); String encap256 = getEncapKey(bike256Enc1, bike256Enc2);
            saveDataToFile(encap128, encapFile128Path); saveDataToFile(encap192, encapFile192Path); saveDataToFile(encap256, encapFile256Path);
        }
    }
}