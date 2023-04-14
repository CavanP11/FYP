package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 6, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class TwoFish {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static byte[] ciphertext;

    private static IvParameterSpec iv;

    private static byte[] plaintext;

    private static Cipher cipher;

    private static SecretKey key;

    private static byte[] macKey;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"128", "192", "256"})
    static int keySize;

    @Param({"512", "1024", "2048"})
    static int plaintextSize;
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        cipher = Cipher.getInstance("Twofish/CBC/PKCS7Padding", "BC");
        // Generating key for TwoFish encryption/decryption
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Twofish", "BC");
        keyGenerator.init(keySize);
        key = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "Twofish");
        iv = new IvParameterSpec(new byte[16]);
        // Generating mac keys
        macKey = new byte[32];
        new SecureRandom().nextBytes(macKey);

        ciphertext = encrypt();
    }
    // ********************** \\
    // * Section 6: TwoFish * \\
    // ********************** \\
    @Benchmark
    public void keyGeneration() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGenerator = KeyGenerator.getInstance("TwoFish");
        keyGenerator.init(keySize);
        key = keyGenerator.generateKey();
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        Cipher cipher = Cipher.getInstance("Twofish/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(ciphertext);
        int padding = decrypted[decrypted.length - 1];
        return Arrays.copyOfRange(decrypted, 0, decrypted.length - padding);
    }

    @Benchmark
    public byte[] generateMAC() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        mac.update(plaintext);
        return mac.doFinal(plaintext);
    }
    // ************************************************************* \\
    // * Section 7: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] twoFishEncrypt(SecretKey key, Cipher cipher, IvParameterSpec iv, byte[] plaintext) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext);
    }

    public static byte[] twoFishDecrypt(SecretKey key, Cipher cipher, IvParameterSpec iv, byte[] ciphertext) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] twoFishGenerateMAC(byte[] macKey, byte[] ciphertext) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        mac.update(ciphertext);
        return mac.doFinal(ciphertext);
    }

    private static String getKeyAsString(SecretKey secretKey) {
        return "Secret Key:\n " + Base64.getEncoder().encodeToString(secretKey.getEncoded()) + "\n\n";
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

    private static String getFilePath(String folderPath, String fileName) {
        return folderPath + File.separator + fileName;
    }

    public static String decodeEncryption(byte[] encryption) {
        return "Encryption:\n" + Base64.getEncoder().encodeToString(encryption);
    }

    public static String decodeDecryption(byte[] decryption) {
        return "Decryption:\n" + Base64.getEncoder().encodeToString(decryption);
    }

    public static String decodePlaintext(byte[] decryption) {
        return "Plaintext:\n" + Base64.getEncoder().encodeToString(decryption);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("Twofish/CBC/PKCS7Padding", "BC");
        byte[] macKey = new byte[32];
        String foldersPath = "Benchmark Results/Pre-Quantum/TwoFish Benchmarks/";
        String twoFishFilePath = getFilePath(foldersPath, "Keys.txt");
        String twoFishPlaintextFilePath = getFilePath(foldersPath, "Plaintext/Plaintext.txt"); String twoFishDecodedPlaintextFilePath = getFilePath(foldersPath, "Plaintext/Decoded_Plaintext.txt");
        String twoFishEncryptFilePath = getFilePath(foldersPath, "Encryption/Encryption.txt"); String twoFishDecodedEncryptFilePath = getFilePath(foldersPath, "Encryption/Decoded_Encryption.txt");
        String twoFishDecryptFilePath = getFilePath(foldersPath, "Decryption/Decryption.txt"); String twoFishDecodedDecryptFilePath = getFilePath(foldersPath, "Decryption/Decoded_Decryption.txt");
        String twoFishMACFilePath = getFilePath(foldersPath, "Mac/MAC.txt"); String twoFishDecodedMACFilePath = getFilePath(foldersPath, "MAC/Decoded_MAC.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new SecureRandom().nextBytes(plaintext);
            // Generating key for TwoFish encryption/decryption
            KeyGenerator keyGen = KeyGenerator.getInstance("Twofish", "BC");
            keyGen.init(256);
            SecretKey key = new SecretKeySpec(keyGen.generateKey().getEncoded(), "Twofish");
            IvParameterSpec iv = new IvParameterSpec(new byte[16]);
            String keyString = getKeyAsString(key);
            saveDataToFile(keyString, twoFishFilePath);
            // Saving plaintext
            String twoFishDecodedPlaintext = decodePlaintext(plaintext);
            writeBytesToFile(plaintext, twoFishPlaintextFilePath);
            saveDataToFile(twoFishDecodedPlaintext, twoFishDecodedPlaintextFilePath);
            // Encrypting
            byte[] twoFishEncrypted = twoFishEncrypt(key, cipher, iv, plaintext);
            String twoFishDecodedEncryption = decodeEncryption(twoFishEncrypted);
            writeBytesToFile(twoFishEncrypted, twoFishEncryptFilePath);
            saveDataToFile(twoFishDecodedEncryption, twoFishDecodedEncryptFilePath);
            // Decrypting
            byte[] twoFishDecrypted = twoFishDecrypt(key, cipher, iv, twoFishEncrypted);
            String twoFishDecodedDecryption = decodeDecryption(twoFishDecrypted);
            writeBytesToFile(twoFishDecrypted, twoFishDecryptFilePath);
            saveDataToFile(twoFishDecodedDecryption, twoFishDecodedDecryptFilePath);
            // Generating MAC
            byte[] twoFishMAC = twoFishGenerateMAC(macKey, twoFishEncrypted);
            String twoFishDecodedMAC = decodeDecryption(twoFishMAC);
            writeBytesToFile(twoFishMAC, twoFishMACFilePath);
            saveDataToFile(twoFishDecodedMAC, twoFishDecodedMACFilePath);
        }
    }
}