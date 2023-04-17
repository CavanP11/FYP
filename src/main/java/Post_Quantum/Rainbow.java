package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.interfaces.RainbowKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.assertEquals;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 2)
@Fork(1)
@State(Scope.Benchmark)
public class Rainbow {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator r3ClassicKPG; private static KeyPairGenerator r3CircumKPG; private static KeyPairGenerator r3CompKPG;
    private static KeyPairGenerator r5ClassicKPG; private static KeyPairGenerator r5CircumKPG; private static KeyPairGenerator r5CompKPG;

    private static KeyPair r3ClassicKP; private static KeyPair r3CircumKP; private static KeyPair r3CompKP;
    private static KeyPair r5ClassicKP; private static KeyPair r5CircumKP; private static KeyPair r5CompKP;

    private static Signature r3ClassicSig; private static Signature r3CircumSig; private static Signature r3CompSig;
    private static Signature r5ClassicSig; private static Signature r5CircumSig; private static Signature r5CompSig;

    private static byte[] r3ClassicSignature; private static byte[] r3CircumSignature; private static byte[] r3CompSignature;
    private static byte[] r5ClassicSignature; private static byte[] r5CircumSignature; private static byte[] r5CompSignature;

    private static byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        plaintext = new byte[plaintextSize];
        new SecureRandom().nextBytes(plaintext);
        // Creating KPGs
        r3ClassicKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r3ClassicKPG.initialize(RainbowParameterSpec.rainbowIIIclassic, new SecureRandom());
        r3CircumKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r3CircumKPG.initialize(RainbowParameterSpec.rainbowIIIcircumzenithal, new SecureRandom());
        r3CompKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r3CompKPG.initialize(RainbowParameterSpec.rainbowIIIcompressed, new SecureRandom());
        r5ClassicKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r5ClassicKPG.initialize(RainbowParameterSpec.rainbowVclassic, new SecureRandom());
        r5CircumKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r5CircumKPG.initialize(RainbowParameterSpec.rainbowVcircumzenithal, new SecureRandom());
        r5CompKPG = KeyPairGenerator.getInstance("Rainbow", "BCPQC"); r5CompKPG.initialize(RainbowParameterSpec.rainbowVcompressed, new SecureRandom());
        // Creating KPs
        r3ClassicKP = r3ClassicKeyGeneration(); r3CircumKP = r3CircumKeyGeneration(); r3CompKP = r3CompKeyGeneration();
        r5ClassicKP = r5ClassicKeyGeneration(); r5CircumKP = r5CircumKeyGeneration(); r5CompKP = r5CompKeyGeneration();
        // Creating signatures
        r3ClassicSig = Signature.getInstance("Rainbow", "BCPQC");
        r3CircumSig = Signature.getInstance("Rainbow", "BCPQC");
        r3CompSig = Signature.getInstance("Rainbow", "BCPQC");
        r5ClassicSig = Signature.getInstance("Rainbow", "BCPQC");
        r5CircumSig = Signature.getInstance("Rainbow", "BCPQC");
        r5CompSig = Signature.getInstance("Rainbow", "BCPQC");

        r3ClassicSignature = r3ClassicSign(); r3CircumSignature = r3CircumSign(); r3CompSignature = r3CompSign();
        r5ClassicSignature = r5ClassicSign(); r5CircumSignature = r5CircumSign(); r5CompSignature = r5CompSign();
    }
    // ********************************** \\
    // * Section 6: Rainbow III Classic * \\
    // ********************************** \\
    @Benchmark
    public static KeyPair r3ClassicKeyGeneration() {
        return r3ClassicKPG.generateKeyPair();
    }

    @Benchmark
    public void r3ClassicPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIclassic, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r3ClassicPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIclassic, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r3ClassicSign() throws Exception {
        r3ClassicSig.initSign(r3ClassicKP.getPrivate(), new SecureRandom());
        r3ClassicSig.update(plaintext, 0, plaintext.length);
        return r3ClassicSig.sign();
    }

    @Benchmark
    public boolean r3ClassicVerify() throws Exception {
        r3ClassicSig.initVerify(r3ClassicKP.getPublic());
        r3ClassicSig.update(plaintext, 0, plaintext.length);
        return r3ClassicSig.verify(r3ClassicSignature);
    }
    // ***************************************** \\
    // * Section 7: Rainbow III Circumzenithal * \\
    // ***************************************** \\
    @Benchmark
    public static KeyPair r3CircumKeyGeneration() {
        return r3CircumKPG.generateKeyPair();
    }

    @Benchmark
    public void r3CircumPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIcircumzenithal, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r3CircumPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIcircumzenithal, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r3CircumSign() throws Exception {
        r3CircumSig.initSign(r3CircumKP.getPrivate(), new SecureRandom());
        r3CircumSig.update(plaintext, 0, plaintext.length);
        return r3CircumSig.sign();
    }

    @Benchmark
    public boolean r3CircumVerify() throws Exception {
        r3CircumSig.initVerify(r3CircumKP.getPublic());
        r3CircumSig.update(plaintext, 0, plaintext.length);
        return r3CircumSig.verify(r3CircumSignature);
    }
    // ************************************* \\
    // * Section 8: Rainbow III Compressed * \\
    // ************************************* \\
    @Benchmark
    public static KeyPair r3CompKeyGeneration() {
        return r3CompKPG.generateKeyPair();
    }

    @Benchmark
    public void r3CompPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIcompressed, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r3CompPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowIIIcompressed, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r3CompSign() throws Exception {
        r3CompSig.initSign(r3CompKP.getPrivate(), new SecureRandom());
        r3CompSig.update(plaintext, 0, plaintext.length);
        return r3CompSig.sign();
    }

    @Benchmark
    public boolean r3CompVerify() throws Exception {
        r3CompSig.initVerify(r3CompKP.getPublic());
        r3CompSig.update(plaintext, 0, plaintext.length);
        return r3CompSig.verify(r3CompSignature);
    }
    // *********************************** \\
    // * Section 9: Rainbow V Compressed * \\
    // *********************************** \\
    @Benchmark
    public static KeyPair r5ClassicKeyGeneration() {
        return r5ClassicKPG.generateKeyPair();
    }

    @Benchmark
    public void r5ClassicPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVclassic, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r5ClassicPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVclassic, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r5ClassicSign() throws Exception {
        r5ClassicSig.initSign(r5ClassicKP.getPrivate(), new SecureRandom());
        r5ClassicSig.update(plaintext, 0, plaintext.length);
        return r5ClassicSig.sign();
    }

    @Benchmark
    public boolean r5ClassicVerify() throws Exception {
        r5ClassicSig.initVerify(r5ClassicKP.getPublic());
        r5ClassicSig.update(plaintext, 0, plaintext.length);
        return r5ClassicSig.verify(r5ClassicSignature);
    }
    // ************************************ \\
    // * Section 10: Rainbow V Compressed * \\
    // ************************************ \\
    @Benchmark
    public static KeyPair r5CircumKeyGeneration() {
        return r5CircumKPG.generateKeyPair();
    }

    @Benchmark
    public void r5CircumPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVcircumzenithal, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r5CircumPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVcircumzenithal, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r5CircumSign() throws Exception {
        r5CircumSig.initSign(r5CircumKP.getPrivate(), new SecureRandom());
        r5CircumSig.update(plaintext, 0, plaintext.length);
        return r5CircumSig.sign();
    }

    @Benchmark
    public boolean r5CircumVerify() throws Exception {
        r5CircumSig.initVerify(r5CircumKP.getPublic());
        r5CircumSig.update(plaintext, 0, plaintext.length);
        return r5CircumSig.verify(r5CircumSignature);
    }
    // ************************************ \\
    // * Section 11: Rainbow V Compressed * \\
    // ************************************ \\
    @Benchmark
    public static KeyPair r5CompKeyGeneration() {
        return r5CompKPG.generateKeyPair();
    }

    @Benchmark
    public void r5CompPublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVcompressed, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey pubKey2  = (RainbowKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public void r5CompPrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        kpg.initialize(RainbowParameterSpec.rainbowVcompressed, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();
        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");
        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        RainbowKey privKey2 = (RainbowKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public byte[] r5CompSign() throws Exception {
        r5CompSig.initSign(r5CompKP.getPrivate(), new SecureRandom());
        r5CompSig.update(plaintext, 0, plaintext.length);
        return r5CompSig.sign();
    }

    @Benchmark
    public boolean r5CompVerify() throws Exception {
        r5CompSig.initVerify(r5CompKP.getPublic());
        r5CompSig.update(plaintext, 0, plaintext.length);
        return r5CompSig.verify(r5CompSignature);
    }

    private static class RiggedRandom
            extends SecureRandom {
        public void nextBytes(byte[] bytes) {
            for (int i = 0; i != bytes.length; i++) {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }
    // ************************************************************** \\
    // * Section 12: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
    public static byte[] rainbowSign(KeyPair kp, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("RAINBOW", "BCPQC");
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean rainbowVerify(KeyPair kp, byte[] plaintext, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("RAINBOW", "BCPQC");
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
    }

    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Public Key:\n " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n\n" +
                "Private Key:\n " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n\n";
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

    public static String decodeSignature(byte[] signature) {
        return "Signature:\n" + Base64.getEncoder().encodeToString(signature);
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
        return "Kyber Public Key:\n" + result1 + "\n\n" +
                "Kyber Private Key:\n" + result2 + "\n";
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

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/Rainbow Benchmarks/";

        String r3ClassicFilePath = getFilePath(foldersPath, "Keys/Rainbow-III-Classic/Encoded/Keys.txt"); String r3ClassicFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-III-Classic/Decoded/Keys.txt");
        String r3ClassicSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-III-Classic/Encoded/Signatures.txt"); String r3ClassicSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-III-Classic/Decoded/Signatures.txt");
        String r3ClassicVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-III-Classic/VerifySignatures.txt");

        String r3CircumFilePath = getFilePath(foldersPath, "Keys/Rainbow-III-Circumzenithal/Encoded/Keys.txt"); String r3CircumFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-III-Circumzenithal/Decoded/Keys.txt");
        String r3CircumSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-III-Circumzenithal/Encoded/Signatures.txt"); String r3CircumSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-III-Circumzenithal/Decoded/Signatures.txt");
        String r3CircumVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-III-Circumzenithal/VerifySignatures.txt");

        String r3CompFilePath = getFilePath(foldersPath, "Keys/Rainbow-III-Compressed/Encoded/Keys.txt"); String r3CompFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-III-Compressed/Decoded/Keys.txt");
        String r3CompSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-III-Compressed/Encoded/Signatures.txt"); String r3CompSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-III-Compressed/Decoded/Signatures.txt");
        String r3CompVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-III-Compressed/VerifySignatures.txt");

        String r5ClassicFilePath = getFilePath(foldersPath, "Keys/Rainbow-V-Classic/Encoded/Keys.txt"); String r5ClassicFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-V-Classic/Decoded/Keys.txt");
        String r5ClassicSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-V-Classic/Encoded/Signatures.txt"); String r5ClassicSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-V-Classic/Decoded/Signatures.txt");
        String r5ClassicVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-V-Classic/VerifySignatures.txt");

        String r5CircumFilePath = getFilePath(foldersPath, "Keys/Rainbow-V-Circumzenithal/Encoded/Keys.txt"); String r5CircumFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-V-Circumzenithal/Decoded/Keys.txt");
        String r5CircumSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-V-Circumzenithal/Encoded/Signatures.txt"); String r5CircumSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-V-Circumzenithal/Decoded/Signatures.txt");
        String r5CircumVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-V-Circumzenithal/VerifySignatures.txt");

        String r5CompFilePath = getFilePath(foldersPath, "Keys/Rainbow-V-Compressed/Encoded/Keys.txt"); String r5CompFilePathDecoded = getFilePath(foldersPath, "Keys/Rainbow-V-Compressed/Decoded/Keys.txt");
        String r5CompSigFilePath = getFilePath(foldersPath, "Signatures/Rainbow-V-Compressed/Encoded/Signatures.txt"); String r5CompSigFilePathDecoded = getFilePath(foldersPath, "Signatures/Rainbow-V-Compressed/Decoded/Signatures.txt");
        String r5CompVerifyFilePath = getFilePath(foldersPath, "SignatureVerification/Rainbow-V-Compressed/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new SecureRandom().nextBytes(plaintext);
            // Creating KPGs for key pairs
            KeyPairGenerator r3ClassicKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r3ClassicKPG.initialize(RainbowParameterSpec.rainbowIIIclassic, new SecureRandom());
            KeyPairGenerator r3CircumKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r3CircumKPG.initialize(RainbowParameterSpec.rainbowIIIcircumzenithal, new SecureRandom());
            KeyPairGenerator r3CompKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r3CompKPG.initialize(RainbowParameterSpec.rainbowIIIcompressed, new SecureRandom());
            KeyPairGenerator r5ClassicKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r5ClassicKPG.initialize(RainbowParameterSpec.rainbowVclassic, new SecureRandom());
            KeyPairGenerator r5CircumKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r5CircumKPG.initialize(RainbowParameterSpec.rainbowVcircumzenithal, new SecureRandom());
            KeyPairGenerator r5CompKPG = KeyPairGenerator.getInstance("RAINBOW", "BCPQC"); r5CompKPG.initialize(RainbowParameterSpec.rainbowVcompressed, new SecureRandom());
            // Creating key pairs
            KeyPair r3ClassicKP = r3ClassicKPG.generateKeyPair(); KeyPair r3CircumKP = r3CircumKPG.generateKeyPair(); KeyPair r3CompKP = r3CompKPG.generateKeyPair();
            KeyPair r5ClassicKP = r5ClassicKPG.generateKeyPair(); KeyPair r5CircumKP = r5CircumKPG.generateKeyPair(); KeyPair r5CompKP = r5CompKPG.generateKeyPair();
            String r3ClassicKeysString = getKeysAsString(r3ClassicKP); String r3CircumKeysString = getKeysAsString(r3CircumKP); String r3CompKeysString = getKeysAsString(r3CompKP);
            String r5ClassicKeysString = getKeysAsString(r5ClassicKP); String r5CircumKeysString = getKeysAsString(r5CircumKP); String r5CompKeysString = getKeysAsString(r5CompKP);
            saveDataToFile(r3ClassicKeysString, r3ClassicFilePathDecoded); saveDataToFile(r3CircumKeysString, r3CircumFilePathDecoded); saveDataToFile(r3CompKeysString, r3CompFilePathDecoded);
            saveDataToFile(r5ClassicKeysString, r5ClassicFilePathDecoded); saveDataToFile(r5CircumKeysString, r5CircumFilePathDecoded); saveDataToFile(r5CompKeysString, r5CompFilePathDecoded);
            // Encoded key pairs
            String r3ClassicEnc = getKeys(r3ClassicKP); String r3CircumEnc = getKeys(r3CircumKP); String r3CompEnc = getKeys(r3CompKP);
            String r5ClassicEnc = getKeys(r5ClassicKP); String r5CircumEnc = getKeys(r5CircumKP); String r5CompEnc = getKeys(r5CompKP);
            saveDataToFile(r3ClassicEnc, r3ClassicFilePath); saveDataToFile(r3CircumEnc, r3CircumFilePath); saveDataToFile(r3CompEnc, r3CompFilePath);
            saveDataToFile(r5ClassicEnc, r5ClassicFilePath); saveDataToFile(r5CircumEnc, r5CircumFilePath); saveDataToFile(r5CompEnc, r5CompFilePath);
            // Signing plaintext
            byte[] r3ClassicSig = rainbowSign(r3ClassicKP, plaintext); byte[] r3CircumSig = rainbowSign(r3CircumKP, plaintext); byte[] r3CompSig = rainbowSign(r3CompKP, plaintext);
            byte[] r5ClassicSig = rainbowSign(r5ClassicKP, plaintext); byte[] r5CircumSig = rainbowSign(r5CircumKP, plaintext); byte[] r5CompSig = rainbowSign(r5CompKP, plaintext);
            String r3ClassicDecodedSignature = decodeSignature(r3ClassicSig);  String r3CircumDecodedSignature = decodeSignature(r3CircumSig);  String r3CompDecodedSignature = decodeSignature(r3CompSig);
            String r5ClassicDecodedSignature = decodeSignature(r5ClassicSig);  String r5CircumDecodedSignature = decodeSignature(r5CircumSig);  String r5CompDecodedSignature = decodeSignature(r5CompSig);
            saveDataToFile(r3ClassicDecodedSignature, r3ClassicSigFilePathDecoded); saveDataToFile(r3CircumDecodedSignature, r3CircumSigFilePathDecoded); saveDataToFile(r3CompDecodedSignature, r3CompSigFilePathDecoded);
            saveDataToFile(r5ClassicDecodedSignature, r5ClassicSigFilePathDecoded); saveDataToFile(r5CircumDecodedSignature, r5CircumSigFilePathDecoded); saveDataToFile(r5CompDecodedSignature, r5CompSigFilePathDecoded);
            // Encoded signatures
            writeBytesToFile(r3ClassicSig, r3ClassicSigFilePath);  writeBytesToFile(r3CircumSig, r3CircumSigFilePath);  writeBytesToFile(r3CompSig, r3CompSigFilePath);
            writeBytesToFile(r5ClassicSig, r5ClassicSigFilePath);  writeBytesToFile(r5CircumSig, r5CircumSigFilePath);  writeBytesToFile(r5CompSig, r5CompSigFilePath);
            // Verifying signatures
            boolean r3ClassicVerify = rainbowVerify(r3ClassicKP, plaintext, r3ClassicSig); boolean r3CircumVerify = rainbowVerify(r3CircumKP, plaintext, r3CircumSig); boolean r3CompVerify = rainbowVerify(r3CompKP, plaintext, r3CompSig);
            boolean r5ClassicVerify = rainbowVerify(r5ClassicKP, plaintext, r5ClassicSig); boolean r5CircumVerify = rainbowVerify(r5CircumKP, plaintext, r5CircumSig); boolean r5CompVerify = rainbowVerify(r5CompKP, plaintext, r5CompSig);
            saveVerificationResult(r3ClassicVerify, r3ClassicVerifyFilePath); saveVerificationResult(r3CircumVerify, r3CircumVerifyFilePath); saveVerificationResult(r3CompVerify, r3CompVerifyFilePath);
            saveVerificationResult(r5ClassicVerify, r5ClassicVerifyFilePath); saveVerificationResult(r5CircumVerify, r5CircumVerifyFilePath); saveVerificationResult(r5CompVerify, r5CompVerifyFilePath);
        }
    }
}