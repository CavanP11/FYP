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
import java.security.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 2, time = 2 )
@Measurement(iterations = 4, time = 5)
@Threads(value=Threads.MAX)
@Fork(3)
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
    public static byte[] picnicSign(KeyPair kp, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("PICNIC", "BCPQC");
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean picnicVerify(KeyPair kp, byte[] sig, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("PICNIC", "BCPQC");
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
    }

    public static byte[] sha3Sign(KeyPair kp, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHA3-512WITHPICNIC", "BCPQC");
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean sha3Verify(KeyPair kp, byte[] sig, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHA3-512WITHPICNIC", "BCPQC");
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
    }

    public static byte[] sha512Sign(KeyPair kp, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHA512WITHPICNIC", "BCPQC");
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean sha512Verify(KeyPair kp, byte[] sig, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHA512WITHPICNIC", "BCPQC");
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
    }

    public static byte[] shake256Sign(KeyPair kp, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHAKE256WITHPICNIC", "BCPQC");
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean shake256Verify(KeyPair kp, byte[] sig, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHAKE256WITHPICNIC", "BCPQC");
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

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/Picnic Benchmarks/";
        // Key file locations *NB -> All keys for different modes are the same.
        String l1fsFilePath = getFilePath(foldersPath, "L1FS_Keys.txt");
        String l3fsFilePath = getFilePath(foldersPath, "L3FS_Keys.txt");
        String l5fsFilePath = getFilePath(foldersPath, "L5FS_Keys.txt");
        String l1fullFilePath = getFilePath(foldersPath, "L1FULL_Keys.txt");
        String l3fullFilePath = getFilePath(foldersPath, "L3FULL_Keys.txt");
        String l5fullFilePath = getFilePath(foldersPath, "L5FULL_Keys.txt");
        // Picnic file locations
        String l1fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FS/Signatures.txt"); String l1fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FS/Signatures.txt"); String l3fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FS/Signatures.txt"); String l5fsVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FULL/Signatures.txt"); String l1fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FULL/Signatures.txt"); String l3fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FULL/Signatures.txt"); String l5fullVerifyFilePicnic = getFilePath(foldersPath, "PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHA-3 file locations
        String l1fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FS/Signatures.txt"); String l1fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FS/Signatures.txt"); String l3fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FS/Signatures.txt"); String l5fsVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FULL/Signatures.txt"); String l1fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FULL/Signatures.txt"); String l3fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FULL/Signatures.txt"); String l5fullVerifyFileSha3 = getFilePath(foldersPath, "SHA3-512-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHA-512 file locations
        String l1fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FS/Signatures.txt"); String l1fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FS/Signatures.txt"); String l3fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FS/Signatures.txt"); String l5fsVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FULL/Signatures.txt"); String l1fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FULL/Signatures.txt"); String l3fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FULL/Signatures.txt"); String l5fullVerifyFileSha512 = getFilePath(foldersPath, "SHA-512-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        // SHAKE-256 file locations
        String l1fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FS/Signatures.txt"); String l1fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FS/VerifySignatures.txt");
        String l3fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FS/Signatures.txt"); String l3fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FS/VerifySignatures.txt");
        String l5fsSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FS/Signatures.txt"); String l5fsVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FS/VerifySignatures.txt");
        String l1fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FULL/Signatures.txt"); String l1fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L1FULL/VerifySignatures.txt");
        String l3fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FULL/Signatures.txt"); String l3fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L3FULL/VerifySignatures.txt");
        String l5fullSigFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FULL/Signatures.txt"); String l5fullVerifyFileShake256 = getFilePath(foldersPath, "SHAKE-256-WITH-PICNIC/Picnic-L5FULL/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
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
            saveDataToFile(l1fsKeysString, l1fsFilePath);  saveDataToFile(l3fsKeysString, l3fsFilePath); saveDataToFile(l5fsKeysString, l5fsFilePath);
            saveDataToFile(l1fullKeysString, l1fullFilePath);  saveDataToFile(l3fullKeysString, l3fullFilePath); saveDataToFile(l5fullKeysString, l5fullFilePath);
            // Creating PICNIC signature instances
            byte[] l1fsSigPicnic = picnicSign(l1fsKP, plaintext); byte[] l3fsSigPicnic = picnicSign(l3fsKP, plaintext); byte[] l5fsSigPicnic = picnicSign(l5fsKP, plaintext);
            byte[] l1fullSigPicnic = picnicSign(l1fullKP, plaintext); byte[] l3fullSigPicnic = picnicSign(l3fullKP, plaintext); byte[] l5fullSigPicnic = picnicSign(l5fullKP, plaintext);
            String l1fsDecodedSignaturePicnic = decodeSignature(l1fsSigPicnic); String l3fsDecodedSignaturePicnic = decodeSignature(l3fsSigPicnic); String l5fsDecodedSignaturePicnic = decodeSignature(l5fsSigPicnic);
            String l1fullDecodedSignaturePicnic = decodeSignature(l1fullSigPicnic); String l3fullDecodedSignaturePicnic = decodeSignature(l3fullSigPicnic); String l5fullDecodedSignaturePicnic = decodeSignature(l5fullSigPicnic);
            saveDataToFile(l1fsDecodedSignaturePicnic, l1fsSigFilePicnic); saveDataToFile(l3fsDecodedSignaturePicnic, l3fsSigFilePicnic); saveDataToFile(l5fsDecodedSignaturePicnic, l5fsSigFilePicnic);
            saveDataToFile(l1fullDecodedSignaturePicnic, l1fullSigFilePicnic); saveDataToFile(l3fullDecodedSignaturePicnic, l3fullSigFilePicnic); saveDataToFile(l5fullDecodedSignaturePicnic, l5fullSigFilePicnic);
            // Creating SHA3-512WITHPICNIC signature instances
            byte[] l1fsSigSha3 = sha3Sign(l1fsKP, plaintext); byte[] l3fsSigSha3 = sha3Sign(l3fsKP, plaintext); byte[] l5fsSigSha3 = sha3Sign(l5fsKP, plaintext);
            byte[] l1fullSigSha3 = sha3Sign(l1fullKP, plaintext); byte[] l3fullSigSha3 = sha3Sign(l3fullKP, plaintext); byte[] l5fullSigSha3 = sha3Sign(l5fullKP, plaintext);
            String l1fsDecodedSignatureSha3 = decodeSignature(l1fsSigSha3); String l3fsDecodedSignatureSha3 = decodeSignature(l3fsSigSha3); String l5fsDecodedSignatureSha3 = decodeSignature(l5fsSigSha3);
            String l1fullDecodedSignatureSha3 = decodeSignature(l1fullSigSha3); String l3fullDecodedSignatureSha3 = decodeSignature(l3fullSigSha3); String l5fullDecodedSignatureSha3 = decodeSignature(l5fullSigSha3);
            saveDataToFile(l1fsDecodedSignatureSha3, l1fsSigFileSha3); saveDataToFile(l3fsDecodedSignatureSha3, l3fsSigFileSha3); saveDataToFile(l5fsDecodedSignatureSha3, l5fsSigFileSha3);
            saveDataToFile(l1fullDecodedSignatureSha3, l1fullSigFileSha3); saveDataToFile(l3fullDecodedSignatureSha3, l3fullSigFileSha3); saveDataToFile(l5fullDecodedSignatureSha3, l5fullSigFileSha3);
            // Creating SHA512WITHPICNIC signature instances
            byte[] l1fsSigSha512 = sha512Sign(l1fsKP, plaintext); byte[] l3fsSigSha512 = sha512Sign(l3fsKP, plaintext); byte[] l5fsSigSha512 = sha512Sign(l5fsKP, plaintext);
            byte[] l1fullSigSha512 = sha512Sign(l1fullKP, plaintext); byte[] l3fullSigSha512 = sha512Sign(l3fullKP, plaintext); byte[] l5fullSigSha512 = sha512Sign(l5fullKP, plaintext);
            String l1fsDecodedSignatureSha512 = decodeSignature(l1fsSigSha512); String l3fsDecodedSignatureSha512 = decodeSignature(l3fsSigSha512); String l5fsDecodedSignatureSha512 = decodeSignature(l5fsSigSha512);
            String l1fullDecodedSignatureSha512 = decodeSignature(l1fullSigSha512); String l3fullDecodedSignatureSha512 = decodeSignature(l3fullSigSha512); String l5fullDecodedSignatureSha512 = decodeSignature(l5fullSigSha512);
            saveDataToFile(l1fsDecodedSignatureSha512, l1fsSigFileSha512); saveDataToFile(l3fsDecodedSignatureSha512, l3fsSigFileSha512); saveDataToFile(l5fsDecodedSignatureSha512, l5fsSigFileSha512);
            saveDataToFile(l1fullDecodedSignatureSha512, l1fullSigFileSha512); saveDataToFile(l3fullDecodedSignatureSha512, l3fullSigFileSha512); saveDataToFile(l5fullDecodedSignatureSha512, l5fullSigFileSha512);
            // Creating SHAKE256WITHPICNIC signature instances
            byte[] l1fsSigShake256 = shake256Sign(l1fsKP, plaintext); byte[] l3fsSigShake256 = shake256Sign(l3fsKP, plaintext); byte[] l5fsSigShake256 = shake256Sign(l5fsKP, plaintext);
            byte[] l1fullSigShake256 = shake256Sign(l1fullKP, plaintext); byte[] l3fullSigShake256 = shake256Sign(l3fullKP, plaintext); byte[] l5fullSigShake256 = shake256Sign(l5fullKP, plaintext);
            String l1fsDecodedSignatureShake256 = decodeSignature(l1fsSigShake256); String l3fsDecodedSignatureShake256 = decodeSignature(l3fsSigShake256); String l5fsDecodedSignatureShake256 = decodeSignature(l5fsSigShake256);
            String l1fullDecodedSignatureShake256 = decodeSignature(l1fullSigShake256); String l3fullDecodedSignatureShake256 = decodeSignature(l3fullSigShake256); String l5fullDecodedSignatureShake256 = decodeSignature(l5fullSigShake256);
            saveDataToFile(l1fsDecodedSignatureShake256, l1fsSigFileShake256); saveDataToFile(l3fsDecodedSignatureShake256, l3fsSigFileShake256); saveDataToFile(l5fsDecodedSignatureShake256, l5fsSigFileShake256);
            saveDataToFile(l1fullDecodedSignatureShake256, l1fullSigFileShake256); saveDataToFile(l3fullDecodedSignatureShake256, l3fullSigFileShake256); saveDataToFile(l5fullDecodedSignatureShake256, l5fullSigFileShake256);
            // Verifying PICNIC signatures
            Boolean l1fsPicnicVerify = picnicVerify(l1fsKP, l1fsSigPicnic, plaintext); Boolean l3fsPicnicVerify = picnicVerify(l3fsKP, l3fsSigPicnic, plaintext); Boolean l5fsPicnicVerify = picnicVerify(l5fsKP, l5fsSigPicnic, plaintext);
            Boolean l1fullPicnicVerify = picnicVerify(l1fullKP, l1fullSigPicnic, plaintext); Boolean l3fullPicnicVerify = picnicVerify(l3fullKP, l3fullSigPicnic, plaintext); Boolean l5fullPicnicVerify = picnicVerify(l5fullKP, l5fullSigPicnic, plaintext);
            saveVerificationResult(l1fsPicnicVerify, l1fsVerifyFilePicnic); saveVerificationResult(l3fsPicnicVerify, l3fsVerifyFilePicnic); saveVerificationResult(l5fsPicnicVerify, l5fsVerifyFilePicnic);
            saveVerificationResult(l1fullPicnicVerify, l1fullVerifyFilePicnic); saveVerificationResult(l3fullPicnicVerify, l3fullVerifyFilePicnic); saveVerificationResult(l5fullPicnicVerify, l5fullVerifyFilePicnic);
            // Verifying SHA3-512WITHPICNIC signatures
            Boolean l1fsSha3Verify = sha3Verify(l1fsKP, l1fsSigSha3, plaintext); Boolean l3fsSha3Verify = sha3Verify(l3fsKP, l3fsSigSha3, plaintext); Boolean l5fsSha3Verify = sha3Verify(l5fsKP, l5fsSigSha3, plaintext);
            Boolean l1fullSha3Verify = sha3Verify(l1fullKP, l1fullSigSha3, plaintext); Boolean l3fullSha3Verify = sha3Verify(l3fullKP, l3fullSigSha3, plaintext); Boolean l5fullSha3Verify = sha3Verify(l5fullKP, l5fullSigSha3, plaintext);
            saveVerificationResult(l1fsSha3Verify, l1fsVerifyFileSha3); saveVerificationResult(l3fsSha3Verify, l3fsVerifyFileSha3); saveVerificationResult(l5fsSha3Verify, l5fsVerifyFileSha3);
            saveVerificationResult(l1fullSha3Verify, l1fullVerifyFileSha3); saveVerificationResult(l3fullSha3Verify, l3fullVerifyFileSha3); saveVerificationResult(l5fullSha3Verify, l5fullVerifyFileSha3);
            // Verifying SHA512WITHPICNIC signatures
            Boolean l1fsSha512Verify = sha512Verify(l1fsKP, l1fsSigSha512, plaintext); Boolean l3fsSha512Verify = sha512Verify(l3fsKP, l3fsSigSha512, plaintext); Boolean l5fsSha512Verify = sha512Verify(l5fsKP, l5fsSigSha512, plaintext);
            Boolean l1fullSha512Verify = sha512Verify(l1fullKP, l1fullSigSha512, plaintext); Boolean l3fullSha512Verify = sha512Verify(l3fullKP, l3fullSigSha512, plaintext); Boolean l5fullSha512Verify = sha512Verify(l5fullKP, l5fullSigSha512, plaintext);
            saveVerificationResult(l1fsSha512Verify, l1fsVerifyFileSha512); saveVerificationResult(l3fsSha512Verify, l3fsVerifyFileSha512); saveVerificationResult(l5fsSha512Verify, l5fsVerifyFileSha512);
            saveVerificationResult(l1fullSha512Verify, l1fullVerifyFileSha512); saveVerificationResult(l3fullSha512Verify, l3fullVerifyFileSha512); saveVerificationResult(l5fullSha512Verify, l5fullVerifyFileSha512);
            // Verifying SHAKE256WITHPICNIC signatures
            Boolean l1fsShake256Verify = shake256Verify(l1fsKP, l1fsSigShake256, plaintext); Boolean l3fsShake256Verify = shake256Verify(l3fsKP, l3fsSigShake256, plaintext); Boolean l5fsShake256Verify = shake256Verify(l5fsKP, l5fsSigShake256, plaintext);
            Boolean l1fullShake256Verify = shake256Verify(l1fullKP, l1fullSigShake256, plaintext); Boolean l3fullShake256Verify = shake256Verify(l3fullKP, l3fullSigShake256, plaintext); Boolean l5fullShake256Verify = shake256Verify(l5fullKP, l5fullSigShake256, plaintext);
            saveVerificationResult(l1fsShake256Verify, l1fsVerifyFileShake256); saveVerificationResult(l3fsShake256Verify, l3fsVerifyFileShake256); saveVerificationResult(l5fsShake256Verify, l5fsVerifyFileShake256);
            saveVerificationResult(l1fullShake256Verify, l1fullVerifyFileShake256); saveVerificationResult(l3fullShake256Verify, l3fullVerifyFileShake256); saveVerificationResult(l5fullShake256Verify, l5fullVerifyFileShake256);
        }
    }
}