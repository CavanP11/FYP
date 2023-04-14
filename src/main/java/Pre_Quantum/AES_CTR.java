package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
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
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class AES_CTR {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\

    private static BufferedBlockCipher encryptCipher;
    private static BufferedBlockCipher decryptCipher;

    private static int encryptOutputLength; private static int decryptOutputLength;
    private static byte[] encryptOutput; private static byte[] decryptOutput;

    private static byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"128", "192", "256"})
    static int keySize;

    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;
    // ************************ \\
    // * Section 5: Setup     * \\
    // ************************ \\
    @Setup
    public void setup() throws Exception {
        byte[] key = keyGeneration();
        SecureRandom random = new SecureRandom();
        // Creating plaintext
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        // Creating IV
        byte[] iv = new byte[16]; // 128-bit
        new SecureRandom().nextBytes(iv);
        // Creating block cipher to covert to stream cipher
        CipherParameters cipherParams = new ParametersWithIV(new KeyParameter(key), iv);
        AESEngine aesEngine = new AESEngine();
        SICBlockCipher ctrAESEngine = new SICBlockCipher(aesEngine);
        // Assigning stream cipher to ciphers
        encryptCipher = new BufferedBlockCipher(ctrAESEngine);
        encryptCipher.init(true, cipherParams);
        decryptCipher = new BufferedBlockCipher(ctrAESEngine);
        decryptCipher.init(false, cipherParams);

        encryptOutput = new byte[encryptCipher.getOutputSize(plaintext.length)];
        encryptOutputLength = encryptCipher.processBytes(plaintext, 0, plaintext.length, encryptOutput, 0);
        // Generating ciphertext
        byte[] ciphertext = encryption();

        decryptOutput = new byte[decryptCipher.getOutputSize(ciphertext.length)];
        decryptOutputLength = decryptCipher.processBytes(ciphertext, 0, ciphertext.length, decryptOutput, 0);
    }
    // ************************** \\
    // * Section 6: AES CTR     * \\
    // ************************** \\
    @Benchmark
    public static byte[] keyGeneration() {
        KeyGenerationParameters kgp = new KeyGenerationParameters(new SecureRandom(), keySize);
        CipherKeyGenerator ckg = new CipherKeyGenerator();
        ckg.init(kgp);
        return ckg.generateKey();
    }

    @Benchmark
    public byte[] encryption() throws Exception {
        encryptCipher.doFinal(encryptOutput, encryptOutputLength);
        return encryptOutput;
    }

    @Benchmark
    public byte[] decryption() throws Exception {
        decryptCipher.doFinal(decryptOutput, decryptOutputLength);
        return decryptOutput;
    }
    // ************************************************************* \\
    // * Section 7: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] aesEncryption(byte[] key, byte[] plaintext, byte[] iv) throws Exception {
        AESEngine engine = new AESEngine();
        SICBlockCipher ctrEngine = new SICBlockCipher(engine);
        BufferedBlockCipher cipher = new BufferedBlockCipher(ctrEngine);
        CipherParameters cipherParams = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, cipherParams);
        byte[] output = new byte[cipher.getOutputSize(plaintext.length)];
        int outputLength = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
        cipher.doFinal(output, outputLength);
        return output;
    }

    public static byte[] aesDecryption(byte[] key, byte[] ciphertext, byte[] iv) throws Exception {
        AESEngine engine = new AESEngine();
        SICBlockCipher ctrEngine = new SICBlockCipher(engine);
        BufferedBlockCipher cipher = new BufferedBlockCipher(ctrEngine);
        CipherParameters cipherParams = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(false, cipherParams);
        byte[] output = new byte[cipher.getOutputSize(ciphertext.length)];
        int outputLength = cipher.processBytes(ciphertext, 0, ciphertext.length, output, 0);
        cipher.doFinal(output, outputLength);
        return output;
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

    public static String decodeKey(byte[] key, byte[] iv) {
        return "Key:\n" + Base64.getEncoder().encodeToString(key) + "\n" +
                "IV:\n" + Base64.getEncoder().encodeToString(iv) + "\n";
    }

    public static String decodeEncrypted(byte[] text) {
        return "Encrypted plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static String decodeDecrypted(byte[] text) {
        return "Decrypted plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static String decodePlaintext(byte[] text) {
        return "Plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static void saveByteArrayComparisonResult(byte[] array1, byte[] array2, String filePath) {
        boolean arraysAreEqual = Arrays.equals(array1, array2);
        String comparisonText = arraysAreEqual ? "The decrypted ciphertext matches the plaintext." : "The decrypted ciphertext does not match the plaintext.";
        saveDataToFile(comparisonText, filePath);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Pre-Quantum/AES_CTR Benchmarks/";
        String plaintextFilePath = getFilePath(foldersPath, "AES-Plaintext.txt");
        String keyFile128Path = getFilePath(foldersPath, "AES-128/Keys.txt"); String keyFile192Path = getFilePath(foldersPath, "AES-192/Keys.txt"); String keyFile256Path = getFilePath(foldersPath, "AES-256/Keys.txt");
        String encrypt128FilePath = getFilePath(foldersPath, "AES-128/Encrypted.txt"); String encrypt192FilePath = getFilePath(foldersPath, "AES-192/Encrypted.txt"); String encrypt256FilePath = getFilePath(foldersPath, "AES-256/Encrypted.txt");
        String decrypt128FilePath = getFilePath(foldersPath, "AES-128/Decrypted.txt"); String decrypt192FilePath = getFilePath(foldersPath, "AES-192/Decrypted.txt"); String decrypt256FilePath = getFilePath(foldersPath, "AES-256/Decrypted.txt");
        String verify128FilePath = getFilePath(foldersPath, "AES-128/VerifyEncryption.txt"); String verify192FilePath = getFilePath(foldersPath, "AES-192/VerifyDecryption.txt"); String verify256FilePath = getFilePath(foldersPath, "AES-256/VerifyDecryption.txt");
        for (int i = 0; i < 3; i++) {
            // Random plaintext and IV
            SecureRandom random = new SecureRandom();
            byte[] plaintext = new byte[2048]; byte[] iv = new byte[16];
            new SecureRandom().nextBytes(plaintext); new SecureRandom().nextBytes(iv);
            String decodedPlaintext = decodePlaintext(plaintext);
            saveDataToFile(decodedPlaintext, plaintextFilePath);
            // Creating AES key
            KeyGenerationParameters aes128KPG = new KeyGenerationParameters(new SecureRandom(), 128); KeyGenerationParameters aes192KPG = new KeyGenerationParameters(new SecureRandom(), 192); KeyGenerationParameters aes256KPG = new KeyGenerationParameters(new SecureRandom(), 256);
            CipherKeyGenerator aes128CKG = new CipherKeyGenerator(); aes128CKG.init(aes128KPG); CipherKeyGenerator aes192CKG = new CipherKeyGenerator(); aes192CKG.init(aes192KPG); CipherKeyGenerator aes256CKG = new CipherKeyGenerator(); aes256CKG.init(aes256KPG);
            byte[] aes128Key = aes128CKG.generateKey(); byte[] aes192Key = aes128CKG.generateKey(); byte[] aes256Key = aes256CKG.generateKey();
            String decoded128Key = decodeKey(aes128Key, iv); String decoded192Key = decodeKey(aes192Key, iv); String decoded256Key = decodeKey(aes256Key, iv);
            saveDataToFile(decoded128Key, keyFile128Path); saveDataToFile(decoded192Key, keyFile192Path); saveDataToFile(decoded256Key, keyFile256Path);
            // Encrypting plaintext
            byte[] aes128Encrypted = aesEncryption(aes128Key, plaintext, iv); byte[] aes192Encrypted = aesEncryption(aes192Key, plaintext, iv); byte[] aes256Encrypted = aesEncryption(aes256Key, plaintext, iv);
            String aes128Decoded = decodeEncrypted(aes128Encrypted); String aes192Decoded = decodeEncrypted(aes192Encrypted); String aes256Decoded = decodeEncrypted(aes256Encrypted);
            saveDataToFile(aes128Decoded, encrypt128FilePath); saveDataToFile(aes192Decoded, encrypt192FilePath); saveDataToFile(aes256Decoded, encrypt256FilePath);
            // Decrypting plaintext
            byte[] aes128Decrypted = aesDecryption(aes128Key, aes128Encrypted, iv); byte[] aes192Decrypted = aesDecryption(aes192Key, aes192Encrypted, iv); byte[] aes256Decrypted = aesDecryption(aes256Key, aes256Encrypted, iv);
            String aes128Decoded2 = decodeDecrypted(aes128Decrypted); String aes192Decoded2 = decodeDecrypted(aes192Decrypted); String aes256Decoded2 = decodeDecrypted(aes256Decrypted);
            saveDataToFile(aes128Decoded2, decrypt128FilePath); saveDataToFile(aes192Decoded2, decrypt192FilePath); saveDataToFile(aes256Decoded2, decrypt256FilePath);
            saveByteArrayComparisonResult(aes128Decrypted, plaintext, verify128FilePath); saveByteArrayComparisonResult(aes192Decrypted, plaintext, verify192FilePath); saveByteArrayComparisonResult(aes256Decrypted, plaintext, verify256FilePath);
        }
    }
}