package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
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
public class BIKE {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator bike128KPG; private static KeyPairGenerator bike192KPG; private static KeyPairGenerator bike256KPG;

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

        bike128KPG = KeyPairGenerator.getInstance("BIKE"); bike128KPG.initialize(BIKEParameterSpec.bike128, new SecureRandom());
        bike192KPG = KeyPairGenerator.getInstance("BIKE"); bike192KPG.initialize(BIKEParameterSpec.bike192, new SecureRandom());
        bike256KPG = KeyPairGenerator.getInstance("BIKE"); bike256KPG.initialize(BIKEParameterSpec.bike256, new SecureRandom());

        KeyPair bike128KP = bike128KeyGenerator();
        KeyPair bike192KP = bike192KeyGenerator();
        KeyPair bike256KP = bike256KeyGenerator();

        bike128CipherWrap = Cipher.getInstance("BIKE"); bike128CipherWrap.init(Cipher.WRAP_MODE, bike128KP.getPublic());
        bike192CipherWrap = Cipher.getInstance("BIKE"); bike192CipherWrap.init(Cipher.WRAP_MODE, bike192KP.getPublic());
        bike256CipherWrap = Cipher.getInstance("BIKE"); bike256CipherWrap.init(Cipher.WRAP_MODE, bike256KP.getPublic());
        bike128WB = bike128WrapKey(); bike192WB = bike192WrapKey(); bike256WB = bike256WrapKey();

        bike128CipherUnwrap = Cipher.getInstance("BIKE"); bike128CipherUnwrap.init(Cipher.UNWRAP_MODE, bike128KP.getPrivate());
        bike192CipherUnwrap = Cipher.getInstance("BIKE"); bike192CipherUnwrap.init(Cipher.UNWRAP_MODE, bike192KP.getPrivate());
        bike256CipherUnwrap = Cipher.getInstance("BIKE"); bike256CipherUnwrap.init(Cipher.UNWRAP_MODE, bike256KP.getPrivate());
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
    // ************************ \\
    // * Section 6: BIKE 256 * \\
    // ************************ \\
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
    // ************************************************************* \\
    // * Section 8: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Bike Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" +
                "Bike Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n";
    }

    public static String byteArrayToHexString(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static byte[] bikeWrapKey(KeyPair kp, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("BIKE");
        cipher.init(Cipher.WRAP_MODE, kp.getPublic());
        return cipher.wrap(key);
    }

    public static Key bikeUnwrapKey(KeyPair kp, byte[] wb) throws Exception {
        Cipher cipher = Cipher.getInstance("BIKE");
        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
        return cipher.unwrap(wb, "AES", Cipher.SECRET_KEY);
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

    public static String keyToHexString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Hex.toHexString(keyBytes);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/BIKE Benchmarks/";
        String file128Path = getFilePath(foldersPath, "BIKE128_Keys.txt"); String file192Path = getFilePath(foldersPath, "BIKE192_Keys.txt"); String file256Path = getFilePath(foldersPath, "BIKE256_Keys.txt");
        String wrapped128FilePath = getFilePath(foldersPath, "BIKE128_Wrapped.txt"); String wrapped192FilePath = getFilePath(foldersPath, "BIKE192_Wrapped.txt"); String wrapped256FilePath = getFilePath(foldersPath, "BIKE256_Wrapped.txt");
        String unwrap128FilePath = getFilePath(foldersPath, "BIKE128_Unwrapped.txt"); String unwrap192FilePath = getFilePath(foldersPath, "BIKE192_Unwrapped.txt"); String unwrap256FilePath = getFilePath(foldersPath, "BIKE256_Unwrapped.txt");
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        Key key = new SecretKeySpec(keyBytes, "AES");
        for (int i = 0; i < 3; i++) {
            // Creating KPGs for key pairs
            KeyPairGenerator kpg128 = KeyPairGenerator.getInstance("BIKE"); KeyPairGenerator kpg192 = KeyPairGenerator.getInstance("BIKE"); KeyPairGenerator kpg256 = KeyPairGenerator.getInstance("BIKE");
            kpg128.initialize(BIKEParameterSpec.bike128, new SecureRandom()); kpg192.initialize(BIKEParameterSpec.bike192, new SecureRandom()); kpg256.initialize(BIKEParameterSpec.bike256, new SecureRandom());
            // Creating key pairs
            KeyPair kp128 = kpg128.generateKeyPair(); KeyPair kp192 = kpg192.generateKeyPair(); KeyPair kp256 = kpg256.generateKeyPair();
            String keys128String = getKeysAsString(kp128); String keys192String = getKeysAsString(kp192); String keys256String = getKeysAsString(kp256);
            saveDataToFile(keys128String, file128Path); saveDataToFile(keys192String, file192Path); saveDataToFile(keys256String, file256Path);
            // Wrapping keyBytes
            byte[] bike128WB = bikeWrapKey(kp128, key); byte[] bike192WB = bikeWrapKey(kp192, key); byte[] bike256WB = bikeWrapKey(kp256, key);
            String hash128HexString = byteArrayToHexString(bike128WB); String hash192HexString = byteArrayToHexString(bike192WB); String hash256HexString = byteArrayToHexString(bike256WB);
            saveDataToFile(hash128HexString, wrapped128FilePath); saveDataToFile(hash192HexString, wrapped192FilePath); saveDataToFile(hash256HexString, wrapped256FilePath);
            // Unwrapping keyBytes
            Key unwrap128Bytes = bikeUnwrapKey(kp128, bike128WB); Key unwrap192Bytes = bikeUnwrapKey(kp192, bike192WB); Key unwrap256Bytes = bikeUnwrapKey(kp256, bike256WB);
            String un128Wrapped = keyToHexString(unwrap128Bytes); String un192Wrapped = keyToHexString(unwrap192Bytes); String un256Wrapped = keyToHexString(unwrap256Bytes);
            saveDataToFile(un128Wrapped, unwrap128FilePath); saveDataToFile(un192Wrapped, unwrap192FilePath); saveDataToFile(un256Wrapped, unwrap256FilePath);
        }
    }
}
