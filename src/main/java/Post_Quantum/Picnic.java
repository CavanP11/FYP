package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
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
public class Picnic {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private KeyPair l1fsKP; private KeyPair l3fsKP; private KeyPair l5fsKP;
    private KeyPair l1fullKP; private KeyPair l3fullKP; private KeyPair l5fullKP;

    private byte[] l1fsSignature; private byte[] l3fsSignature; private byte[] l5fsSignature;
    private byte[] l1fullSignature; private byte[] l3fullSignature; private byte[] l5fullSignature;

    private static KeyPairGenerator l1fsKPG; private static KeyPairGenerator l3fsKPG; private static KeyPairGenerator l5fsKPG;
    private static KeyPairGenerator l1fullKPG; private static KeyPairGenerator l3fullKPG; private static KeyPairGenerator l5fullKPG;

    private Signature l1fsSig; private Signature l3fsSig; private Signature l5fsSig;
    private Signature l1fullSig; private Signature l3fullSig; private Signature l5fullSig;

    private byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;
    @Param({"Picnic", "SHA3-512WITHPICNIC", "SHA512WITHPICNIC", "SHAKE256WITHPICNIC"})
    static String algorithm;
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        SecureRandom random = new SecureRandom();
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        // Creating signature of the current algorithm parameter
        l1fsSig = Signature.getInstance(algorithm, "BCPQC");
        l3fsSig = l1fsSig; l5fsSig = l1fsSig; l1fullSig = l1fsSig; l3fullSig = l1fsSig; l5fullSig = l1fsSig;
        // Creating KPG instances
        l1fsKPG = KeyPairGenerator.getInstance("Picnic", "BCPQC");
        l3fsKPG = l1fsKPG; l5fsKPG = l1fsKPG; l1fullKPG = l1fsKPG; l3fullKPG = l1fsKPG; l5fullKPG = l1fsKPG;
        // Initializing KPG with Picnic Parameter Specs
        l1fsKPG.initialize(PicnicParameterSpec.picnicl1fs, random); l3fsKPG.initialize(PicnicParameterSpec.picnicl3fs, random); l5fsKPG.initialize(PicnicParameterSpec.picnicl5fs, random);
        l1fullKPG.initialize(PicnicParameterSpec.picnicl1full, random); l3fullKPG.initialize(PicnicParameterSpec.picnicl3full, random); l5fullKPG.initialize(PicnicParameterSpec.picnicl5full, random);
        // Assigning KeyPairs from the corresponding KPG
        l1fsKP = l1fsKPG.generateKeyPair(); l3fsKP = l3fsKPG.generateKeyPair(); l5fsKP = l5fsKPG.generateKeyPair();
        l1fullKP = l5fsKPG.generateKeyPair(); l3fullKP = l3fsKPG.generateKeyPair(); l5fullKP = l5fsKPG.generateKeyPair();
        // Creating signatures using the signature benchmark classes. *NB -> These runs are not benchmarked, so performance not impacted.
        l1fsSignature = l1fsSign(); l3fsSignature = l3fsSign(); l5fsSignature = l5fsSign();
        l1fullSignature = l1fullSign(); l3fullSignature = l3fullSign(); l5fullSignature = l5fullSign();
    }
    // ************************** \\
    // * Section 6: Picnic L1FS * \\
    // ************************** \\
    @Benchmark
    public static KeyPair l1fsKeyGeneration() {
        return l1fsKPG.generateKeyPair();
    }
    @Benchmark
    public byte[] l1fsSign() throws Exception {
        l1fsSig.initSign(l1fsKP.getPrivate(), new SecureRandom());
        l1fsSig.update(plaintext, 0, plaintext.length);
        return l1fsSig.sign();
    }
    @Benchmark
    public boolean l1fsVerify() throws Exception {
        l1fsSig.initVerify(l1fsKP.getPublic());
        l1fsSig.update(plaintext, 0, plaintext.length);
        return l1fsSig.verify(l1fsSignature);
    }
    // ************************** \\
    // * Section 7: Picnic L3FS * \\
    // ************************** \\
    @Benchmark
    public static KeyPair l3fsKeyGeneration() {
        return l3fsKPG.generateKeyPair();
    }

    @Benchmark
    public byte[] l3fsSign() throws Exception {
        l3fsSig.initSign(l3fsKP.getPrivate(), new SecureRandom());
        l3fsSig.update(plaintext, 0, plaintext.length);
        return l3fsSig.sign();
    }

    @Benchmark
    public boolean l3fsVerify() throws Exception {
        l3fsSig.initVerify(l3fsKP.getPublic());
        l3fsSig.update(plaintext, 0, plaintext.length);
        return l3fsSig.verify(l3fsSignature);
    }
    // ************************** \\
    // * Section 8: Picnic L5FS * \\
    // ************************** \\
    @Benchmark
    public static KeyPair l5fsKeyGeneration() {
        return l5fsKPG.generateKeyPair();
    }

    @Benchmark
    public byte[] l5fsSign() throws Exception {
        l5fsSig.initSign(l5fsKP.getPrivate(), new SecureRandom());
        l5fsSig.update(plaintext, 0, plaintext.length);
        return l5fsSig.sign();
    }

    @Benchmark
    public boolean l5fsVerify() throws Exception {
        l5fsSig.initVerify(l5fsKP.getPublic());
        l5fsSig.update(plaintext, 0, plaintext.length);
        return l5fsSig.verify(l5fsSignature);
    }
    // **************************** \\
    // * Section 9: Picnic L1FULL * \\
    // **************************** \\
    @Benchmark
    public static KeyPair l1fullKeyGeneration() {
        return l1fullKPG.generateKeyPair();
    }

    @Benchmark
    public byte[] l1fullSign() throws Exception {
        l1fullSig.initSign(l1fullKP.getPrivate(), new SecureRandom());
        l1fullSig.update(plaintext, 0, plaintext.length);
        return l1fullSig.sign();
    }

    @Benchmark
    public boolean l1fullVerify() throws Exception {
        l1fullSig.initVerify(l5fullKP.getPublic());
        l1fullSig.update(plaintext, 0, plaintext.length);
        return l1fullSig.verify(l1fullSignature);
    }
    // ***************************** \\
    // * Section 10: Picnic L3FULL * \\
    // ***************************** \\
    @Benchmark
    public static KeyPair l3fullKeyGeneration() {
        return l3fullKPG.generateKeyPair();
    }

    @Benchmark
    public byte[] l3fullSign() throws Exception {
        l3fullSig.initSign(l3fullKP.getPrivate(), new SecureRandom());
        l3fullSig.update(plaintext, 0, plaintext.length);
        return l3fullSig.sign();
    }

    @Benchmark
    public boolean l3fullVerify() throws Exception {
        l3fullSig.initVerify(l3fullKP.getPublic());
        l3fullSig.update(plaintext, 0, plaintext.length);
        return l3fullSig.verify(l3fullSignature);
    }
    // ***************************** \\
    // * Section 11: Picnic L5FULL * \\
    // ***************************** \\
    @Benchmark
    public static KeyPair l5fullKeyGeneration() {
        return l5fullKPG.generateKeyPair();
    }

    @Benchmark
    public byte[] l5fullSign() throws Exception {
        l5fullSig.initSign(l5fullKP.getPrivate(), new SecureRandom());
        l5fullSig.update(plaintext, 0, plaintext.length);
        return l5fullSig.sign();
    }

    @Benchmark
    public boolean l5fullVerify() throws Exception {
        l5fullSig.initVerify(l5fullKP.getPublic());
        l5fullSig.update(plaintext, 0, plaintext.length);
        return l5fullSig.verify(l5fullSignature);
    }
    // ************************************************************** \\
    // * Section 12: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
    public static byte[] picnicSign(KeyPair kp, Signature signature, byte[] plaintext) throws Exception {
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean picnicVerify(KeyPair kp, Signature signature, byte[] sig, byte[] plaintext) throws Exception {
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
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

    public static void saveVerificationResult(boolean verify, String filePath) {
        String verificationText = verify ? "Signature is valid" : "Signature is not valid";
        saveDataToFile(verificationText, filePath);
    }

    private static String getKeys(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] pubKey = publicKey.getEncoded();
        byte[] privKey = privateKey.getEncoded();
        String result1 = new String(pubKey);
        String result2 = new String(privKey);
        return "Picnic Public Key:\n" + result1 + "\n\n" +
                "Picnic Private Key:\n" + result2 + "\n";
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Signature picnicSig = Signature.getInstance("PICNIC", "BCPQC");
        Signature sha3Sig = Signature.getInstance("SHA3-512WITHPICNIC", "BCPQC");
        Signature sha512Sig = Signature.getInstance("SHA512WITHPICNIC", "BCPQC");
        Signature shake256Sig = Signature.getInstance("SHAKE256WITHPICNIC", "BCPQC");
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/Picnic Benchmarks/";
        // Key file locations *NB -> All keys for different modes are the same.
        String l1fsFilePath = getFilePath(foldersPath, "Keys/L1FSKeys/Keys.txt"); String l1fsFilePathDecoded = getFilePath(foldersPath, "Keys/L1FSKeys/Decoded_Keys.txt");
        String l3fsFilePath = getFilePath(foldersPath, "Keys/L3FSKeys/Keys.txt"); String l3fsFilePathDecoded = getFilePath(foldersPath, "Keys/L3FSKeys/Decoded_Keys.txt");
        String l5fsFilePath = getFilePath(foldersPath, "Keys/L5FSKeys/Keys.txt"); String l5fsFilePathDecoded = getFilePath(foldersPath, "Keys/L5FSKeys/Decoded_Keys.txt");
        String l1fullFilePath = getFilePath(foldersPath, "Keys/L1FULLKeys/Keys.txt"); String l1fullFilePathDecoded = getFilePath(foldersPath, "Keys/L1FULLKeys/Decoded_Keys.txt");
        String l3fullFilePath = getFilePath(foldersPath, "Keys/L3FULLKeys/Keys.txt"); String l3fullFilePathDecoded = getFilePath(foldersPath, "Keys/L3FULLKeys/Decoded_Keys.txt");
        String l5fullFilePath = getFilePath(foldersPath, "Keys/L5FULLKeys/Keys.txt"); String l5fullFilePathDecoded = getFilePath(foldersPath, "Keys/L5FULLKeys/Decoded_Keys.txt");
        // Picnic file locations
        String l1fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FS/Encoded/Signatures.txt"); String l1fsSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L1FS/Decoded/Decoded_Signatures.txt");
        String l1fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FS/Encoded/Signatures.txt"); String l3fsSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L3FS/Decoded/Decoded_Signatures.txt");
        String l3fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FS/Encoded/Signatures.txt"); String l5fsSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L5FS/Decoded/Decoded_Signatures.txt");
        String l5fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FULL/Encoded/Signatures.txt");  String l1fullSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L1FULL/Decoded/Decoded_Signatures.txt");
        String l1fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FULL/Encoded/Signatures.txt"); String l3fullSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L3FULL/Decoded/Decoded_Signatures.txt");
        String l3fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FULL/Encoded/Signatures.txt"); String l5fullSigFilePicnicDecoded = getFilePath(foldersPath, "PICNIC/Picnic-L5FULL/Decoded/Decoded_Signatures.txt");
        String l5fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHA-3 file locations
        String l1fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FS/Encoded/Signatures.txt"); String l1fsSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FS/Decoded/Decoded_Signatures.txt");
        String l1fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FS/Encoded/Signatures.txt"); String l3fsSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FS/Decoded/Decoded_Signatures.txt");
        String l3fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FS/Encoded/Signatures.txt"); String l5fsSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FS/Decoded/Decoded_Signatures.txt");
        String l5fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FULL/Encoded/Signatures.txt"); String l1fullSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FULL/Decoded/Decoded_Signatures.txt");
        String l1fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FULL/Encoded/Signatures.txt"); String l3fullSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FULL/Decoded/Decoded_Signatures.txt");
        String l3fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FULL/Encoded/Signatures.txt"); String l5fullSigFileSha3Decoded = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FULL/Decoded/Decoded_Signatures.txt");
        String l5fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHA-512 file locations
        String l1fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FS/Encoded/Signatures.txt"); String l1fsSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FS/Decoded/Decoded_Signatures.txt");
        String l1fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FS/Encoded/Signatures.txt"); String l3fsSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FS/Decoded/Decoded_Signatures.txt");
        String l3fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FS/Encoded/Signatures.txt"); String l5fsSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FS/Decoded/Decoded_Signatures.txt");
        String l5fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FULL/Encoded/Signatures.txt"); String l1fullSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FULL/Decoded/Decoded_Signatures.txt");
        String l1fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FULL/Encoded/Signatures.txt"); String l3fullSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FULL/Decoded/Decoded_Signatures.txt");
        String l3fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FULL/Encoded/Signatures.txt"); String l5fullSigFileSha512Decoded = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FULL/Decoded/Decoded_Signatures.txt");
        String l5fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHAKE-256 file locations
        String l1fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FS/Encoded/Signatures.txt"); String l1fsSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FS/Decoded/Decoded_Signatures.txt");
        String l1fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FS/Encoded/Signatures.txt"); String l3fsSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FS/Decoded/Decoded_Signatures.txt");
        String l3fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FS/Encoded/Signatures.txt"); String l5fsSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FS/Decoded/Decoded_Signatures.txt");
        String l5fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FULL/Encoded/Signatures.txt"); String l1fullSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FULL/Decoded/Decoded_Signatures.txt");
        String l1fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FULL/Encoded/Signatures.txt"); String l3fullSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FULL/Decoded/Decoded_Signatures.txt");
        String l3fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FULL/Encoded/Signatures.txt"); String l5fullSigFileShake256Decoded = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FULL/Decoded/Decoded_Signatures.txt");
        String l5fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new SecureRandom().nextBytes(plaintext);
            // Creating signatures
            KeyPairGenerator l1fsKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l1fsKPG.initialize(PicnicParameterSpec.picnicl1fs, new SecureRandom());
            KeyPairGenerator l3fsKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l3fsKPG.initialize(PicnicParameterSpec.picnicl3fs, new SecureRandom());
            KeyPairGenerator l5fsKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l5fsKPG.initialize(PicnicParameterSpec.picnicl5fs, new SecureRandom());
            KeyPairGenerator l1fullKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l1fullKPG.initialize(PicnicParameterSpec.picnicl1full, new SecureRandom());
            KeyPairGenerator l3fullKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l3fullKPG.initialize(PicnicParameterSpec.picnicl3full, new SecureRandom());
            KeyPairGenerator l5fullKPG = KeyPairGenerator.getInstance("PICNIC", "BCPQC"); l5fullKPG.initialize(PicnicParameterSpec.picnicl5full, new SecureRandom());
            // Creating key pairs
            KeyPair l1fsKP = l1fsKPG.generateKeyPair(); KeyPair l3fsKP = l3fsKPG.generateKeyPair(); KeyPair l5fsKP = l5fsKPG.generateKeyPair();
            KeyPair l1fullKP = l1fullKPG.generateKeyPair(); KeyPair l3fullKP = l3fullKPG.generateKeyPair(); KeyPair l5fullKP = l5fullKPG.generateKeyPair();
            String l1fsKeysString = getKeysAsString(l1fsKP); String l3fsKeysString = getKeysAsString(l3fsKP); String l5fsKeysString = getKeysAsString(l5fsKP);
            String l1fullKeysString = getKeysAsString(l1fullKP); String l3fullKeysString = getKeysAsString(l3fullKP); String l5fullKeysString = getKeysAsString(l5fullKP);
            saveDataToFile(l1fsKeysString, l1fsFilePathDecoded);  saveDataToFile(l3fsKeysString, l3fsFilePathDecoded); saveDataToFile(l5fsKeysString, l5fsFilePathDecoded);
            saveDataToFile(l1fullKeysString, l1fullFilePathDecoded);  saveDataToFile(l3fullKeysString, l3fullFilePathDecoded); saveDataToFile(l5fullKeysString, l5fullFilePathDecoded);
            // Encoded key pairs
            String l1fsKPString = getKeys(l1fsKP); String l3fsKPString = getKeys(l3fsKP); String l5fsKPString = getKeys(l5fsKP);
            String l1fullKPString = getKeys(l1fullKP); String l3fullKPString = getKeys(l3fullKP); String l5fullKPString = getKeys(l5fullKP);
            saveDataToFile(l1fsKPString, l1fsFilePath); saveDataToFile(l3fsKPString, l3fsFilePath); saveDataToFile(l5fsKPString, l5fsFilePath);
            saveDataToFile(l1fullKPString, l1fullFilePath); saveDataToFile(l3fullKPString, l3fullFilePath); saveDataToFile(l5fullKPString, l5fullFilePath);
            // Creating PICNIC signature instances
            byte[] l1fsSigPicnic = picnicSign(l1fsKP, picnicSig, plaintext); byte[] l3fsSigPicnic = picnicSign(l3fsKP, picnicSig, plaintext); byte[] l5fsSigPicnic = picnicSign(l5fsKP, picnicSig, plaintext);
            byte[] l1fullSigPicnic = picnicSign(l1fullKP, picnicSig, plaintext); byte[] l3fullSigPicnic = picnicSign(l3fullKP, picnicSig, plaintext); byte[] l5fullSigPicnic = picnicSign(l5fullKP, picnicSig, plaintext);
            String l1fsDecodedSignaturePicnic = decodeSignature(l1fsSigPicnic); String l3fsDecodedSignaturePicnic = decodeSignature(l3fsSigPicnic); String l5fsDecodedSignaturePicnic = decodeSignature(l5fsSigPicnic);
            String l1fullDecodedSignaturePicnic = decodeSignature(l1fullSigPicnic); String l3fullDecodedSignaturePicnic = decodeSignature(l3fullSigPicnic); String l5fullDecodedSignaturePicnic = decodeSignature(l5fullSigPicnic);
            saveDataToFile(l1fsDecodedSignaturePicnic, l1fsSigFilePicnicDecoded); saveDataToFile(l3fsDecodedSignaturePicnic, l3fsSigFilePicnicDecoded); saveDataToFile(l5fsDecodedSignaturePicnic, l5fsSigFilePicnicDecoded);
            saveDataToFile(l1fullDecodedSignaturePicnic, l1fullSigFilePicnicDecoded); saveDataToFile(l3fullDecodedSignaturePicnic, l3fullSigFilePicnicDecoded); saveDataToFile(l5fullDecodedSignaturePicnic, l5fullSigFilePicnicDecoded);
            // Encoded PICNIC signatures
            writeBytesToFile(l1fsSigPicnic, l1fsSigFilePicnic); writeBytesToFile(l3fsSigPicnic, l3fsSigFilePicnic); writeBytesToFile(l5fsSigPicnic, l5fsSigFilePicnic);
            writeBytesToFile(l1fullSigPicnic, l1fullSigFilePicnic); writeBytesToFile(l3fullSigPicnic, l3fullSigFilePicnic); writeBytesToFile(l5fullSigPicnic, l5fullSigFilePicnic);
            // Creating SHA3-512WITHPICNIC signature instances
            byte[] l1fsSigSha3 = picnicSign(l1fsKP, sha3Sig, plaintext); byte[] l3fsSigSha3 = picnicSign(l3fsKP, sha3Sig, plaintext); byte[] l5fsSigSha3 = picnicSign(l5fsKP, sha3Sig, plaintext);
            byte[] l1fullSigSha3 = picnicSign(l1fullKP, sha3Sig, plaintext); byte[] l3fullSigSha3 = picnicSign(l3fullKP, sha3Sig, plaintext); byte[] l5fullSigSha3 = picnicSign(l5fullKP, sha3Sig, plaintext);
            String l1fsDecodedSignatureSha3 = decodeSignature(l1fsSigSha3); String l3fsDecodedSignatureSha3 = decodeSignature(l3fsSigSha3); String l5fsDecodedSignatureSha3 = decodeSignature(l5fsSigSha3);
            String l1fullDecodedSignatureSha3 = decodeSignature(l1fullSigSha3); String l3fullDecodedSignatureSha3 = decodeSignature(l3fullSigSha3); String l5fullDecodedSignatureSha3 = decodeSignature(l5fullSigSha3);
            saveDataToFile(l1fsDecodedSignatureSha3, l1fsSigFileSha3Decoded); saveDataToFile(l3fsDecodedSignatureSha3, l3fsSigFileSha3Decoded); saveDataToFile(l5fsDecodedSignatureSha3, l5fsSigFileSha3Decoded);
            saveDataToFile(l1fullDecodedSignatureSha3, l1fullSigFileSha3Decoded); saveDataToFile(l3fullDecodedSignatureSha3, l3fullSigFileSha3Decoded); saveDataToFile(l5fullDecodedSignatureSha3, l5fullSigFileSha3Decoded);
            // Encoded SHA3-512WITHPICNIC signatures
            writeBytesToFile(l1fsSigSha3, l1fsSigFileSha3); writeBytesToFile(l3fsSigSha3, l3fsSigFileSha3); writeBytesToFile(l5fsSigSha3, l5fsSigFileSha3);
            writeBytesToFile(l1fullSigSha3, l1fullSigFileSha3); writeBytesToFile(l3fullSigSha3, l3fullSigFileSha3); writeBytesToFile(l5fullSigSha3, l5fullSigFileSha3);
            // Creating SHA512WITHPICNIC signature instances
            byte[] l1fsSigSha512 = picnicSign(l1fsKP, sha512Sig, plaintext); byte[] l3fsSigSha512 = picnicSign(l3fsKP, sha512Sig, plaintext); byte[] l5fsSigSha512 = picnicSign(l5fsKP, sha512Sig, plaintext);
            byte[] l1fullSigSha512 = picnicSign(l1fullKP, sha512Sig, plaintext); byte[] l3fullSigSha512 = picnicSign(l3fullKP, sha512Sig, plaintext); byte[] l5fullSigSha512 = picnicSign(l5fullKP, sha512Sig, plaintext);
            String l1fsDecodedSignatureSha512 = decodeSignature(l1fsSigSha512); String l3fsDecodedSignatureSha512 = decodeSignature(l3fsSigSha512); String l5fsDecodedSignatureSha512 = decodeSignature(l5fsSigSha512);
            String l1fullDecodedSignatureSha512 = decodeSignature(l1fullSigSha512); String l3fullDecodedSignatureSha512 = decodeSignature(l3fullSigSha512); String l5fullDecodedSignatureSha512 = decodeSignature(l5fullSigSha512);
            saveDataToFile(l1fsDecodedSignatureSha512, l1fsSigFileSha512Decoded); saveDataToFile(l3fsDecodedSignatureSha512, l3fsSigFileSha512Decoded); saveDataToFile(l5fsDecodedSignatureSha512, l5fsSigFileSha512Decoded);
            saveDataToFile(l1fullDecodedSignatureSha512, l1fullSigFileSha512Decoded); saveDataToFile(l3fullDecodedSignatureSha512, l3fullSigFileSha512Decoded); saveDataToFile(l5fullDecodedSignatureSha512, l5fullSigFileSha512Decoded);
            // Encoded SHA512WITHPICNIC signatures
            writeBytesToFile(l1fsSigSha512, l1fsSigFileSha512); writeBytesToFile(l3fsSigSha3, l3fsSigFileSha512); writeBytesToFile(l5fsSigSha3, l5fsSigFileSha512);
            writeBytesToFile(l1fullSigSha512, l1fullSigFileSha512); writeBytesToFile(l3fullSigSha3, l3fullSigFileSha512); writeBytesToFile(l5fullSigSha3, l5fullSigFileSha512);
            // Creating SHAKE256WITHPICNIC signature instances
            byte[] l1fsSigShake256 = picnicSign(l1fsKP, shake256Sig, plaintext); byte[] l3fsSigShake256 = picnicSign(l3fsKP, shake256Sig, plaintext); byte[] l5fsSigShake256 = picnicSign(l5fsKP, shake256Sig, plaintext);
            byte[] l1fullSigShake256 = picnicSign(l1fullKP, shake256Sig, plaintext); byte[] l3fullSigShake256 = picnicSign(l3fullKP, shake256Sig, plaintext); byte[] l5fullSigShake256 = picnicSign(l5fullKP, shake256Sig, plaintext);
            String l1fsDecodedSignatureShake256 = decodeSignature(l1fsSigShake256); String l3fsDecodedSignatureShake256 = decodeSignature(l3fsSigShake256); String l5fsDecodedSignatureShake256 = decodeSignature(l5fsSigShake256);
            String l1fullDecodedSignatureShake256 = decodeSignature(l1fullSigShake256); String l3fullDecodedSignatureShake256 = decodeSignature(l3fullSigShake256); String l5fullDecodedSignatureShake256 = decodeSignature(l5fullSigShake256);
            saveDataToFile(l1fsDecodedSignatureShake256, l1fsSigFileShake256Decoded); saveDataToFile(l3fsDecodedSignatureShake256, l3fsSigFileShake256Decoded); saveDataToFile(l5fsDecodedSignatureShake256, l5fsSigFileShake256Decoded);
            saveDataToFile(l1fullDecodedSignatureShake256, l1fullSigFileShake256Decoded); saveDataToFile(l3fullDecodedSignatureShake256, l3fullSigFileShake256Decoded); saveDataToFile(l5fullDecodedSignatureShake256, l5fullSigFileShake256Decoded);
            // Encoded SHAKE256WITHPICNIC signatures
            writeBytesToFile(l1fsSigShake256, l1fsSigFileShake256); writeBytesToFile(l3fsSigShake256, l3fsSigFileShake256); writeBytesToFile(l5fsSigShake256, l5fsSigFileShake256);
            writeBytesToFile(l1fullSigShake256, l1fullSigFileShake256); writeBytesToFile(l3fullSigShake256, l3fullSigFileShake256); writeBytesToFile(l5fullSigShake256, l5fullSigFileShake256);
            // Verifying PICNIC signatures
            boolean l1fsPicnicVerify = picnicVerify(l1fsKP, picnicSig, l1fsSigPicnic, plaintext); boolean l3fsPicnicVerify = picnicVerify(l3fsKP, picnicSig, l3fsSigPicnic, plaintext); boolean l5fsPicnicVerify = picnicVerify(l5fsKP, picnicSig, l5fsSigPicnic, plaintext);
            boolean l1fullPicnicVerify = picnicVerify(l1fullKP, picnicSig, l1fullSigPicnic, plaintext); boolean l3fullPicnicVerify = picnicVerify(l3fullKP, picnicSig, l3fullSigPicnic, plaintext); boolean l5fullPicnicVerify = picnicVerify(l5fullKP, picnicSig, l5fullSigPicnic, plaintext);
            saveVerificationResult(l1fsPicnicVerify, l1fsVerifyFilePicnic); saveVerificationResult(l3fsPicnicVerify, l3fsVerifyFilePicnic); saveVerificationResult(l5fsPicnicVerify, l5fsVerifyFilePicnic);
            saveVerificationResult(l1fullPicnicVerify, l1fullVerifyFilePicnic); saveVerificationResult(l3fullPicnicVerify, l3fullVerifyFilePicnic); saveVerificationResult(l5fullPicnicVerify, l5fullVerifyFilePicnic);
            // Verifying SHA3-512WITHPICNIC signatures
            boolean l1fsSha3Verify = picnicVerify(l1fsKP, sha3Sig, l1fsSigSha3, plaintext); boolean l3fsSha3Verify = picnicVerify(l3fsKP, sha3Sig, l3fsSigSha3, plaintext); boolean l5fsSha3Verify = picnicVerify(l5fsKP, sha3Sig, l5fsSigSha3, plaintext);
            boolean l1fullSha3Verify = picnicVerify(l1fullKP, sha3Sig, l1fullSigSha3, plaintext); boolean l3fullSha3Verify = picnicVerify(l3fullKP, sha3Sig, l3fullSigSha3, plaintext); boolean l5fullSha3Verify = picnicVerify(l5fullKP, sha3Sig, l5fullSigSha3, plaintext);
            saveVerificationResult(l1fsSha3Verify, l1fsVerifyFileSha3); saveVerificationResult(l3fsSha3Verify, l3fsVerifyFileSha3); saveVerificationResult(l5fsSha3Verify, l5fsVerifyFileSha3);
            saveVerificationResult(l1fullSha3Verify, l1fullVerifyFileSha3); saveVerificationResult(l3fullSha3Verify, l3fullVerifyFileSha3); saveVerificationResult(l5fullSha3Verify, l5fullVerifyFileSha3);
            // Verifying SHA512WITHPICNIC signatures
            boolean l1fsSha512Verify = picnicVerify(l1fsKP, sha512Sig, l1fsSigSha512, plaintext); boolean l3fsSha512Verify = picnicVerify(l3fsKP, sha512Sig, l3fsSigSha512, plaintext); boolean l5fsSha512Verify = picnicVerify(l5fsKP, sha512Sig, l5fsSigSha512, plaintext);
            boolean l1fullSha512Verify = picnicVerify(l1fullKP, sha512Sig, l1fullSigSha512, plaintext); boolean l3fullSha512Verify = picnicVerify(l3fullKP, sha512Sig, l3fullSigSha512, plaintext); boolean l5fullSha512Verify = picnicVerify(l5fullKP, sha512Sig, l5fullSigSha512, plaintext);
            saveVerificationResult(l1fsSha512Verify, l1fsVerifyFileSha512); saveVerificationResult(l3fsSha512Verify, l3fsVerifyFileSha512); saveVerificationResult(l5fsSha512Verify, l5fsVerifyFileSha512);
            saveVerificationResult(l1fullSha512Verify, l1fullVerifyFileSha512); saveVerificationResult(l3fullSha512Verify, l3fullVerifyFileSha512); saveVerificationResult(l5fullSha512Verify, l5fullVerifyFileSha512);
            // Verifying SHAKE256WITHPICNIC signatures
            boolean l1fsShake256Verify = picnicVerify(l1fsKP, shake256Sig, l1fsSigShake256, plaintext); boolean l3fsShake256Verify = picnicVerify(l3fsKP, shake256Sig, l3fsSigShake256, plaintext); boolean l5fsShake256Verify = picnicVerify(l5fsKP, shake256Sig, l5fsSigShake256, plaintext);
            boolean l1fullShake256Verify = picnicVerify(l1fullKP, shake256Sig, l1fullSigShake256, plaintext); boolean l3fullShake256Verify = picnicVerify(l3fullKP, shake256Sig, l3fullSigShake256, plaintext); boolean l5fullShake256Verify = picnicVerify(l5fullKP, shake256Sig, l5fullSigShake256, plaintext);
            saveVerificationResult(l1fsShake256Verify, l1fsVerifyFileShake256); saveVerificationResult(l3fsShake256Verify, l3fsVerifyFileShake256); saveVerificationResult(l5fsShake256Verify, l5fsVerifyFileShake256);
            saveVerificationResult(l1fullShake256Verify, l1fullVerifyFileShake256); saveVerificationResult(l3fullShake256Verify, l3fullVerifyFileShake256); saveVerificationResult(l5fullShake256Verify, l5fullVerifyFileShake256);
        }
    }
}