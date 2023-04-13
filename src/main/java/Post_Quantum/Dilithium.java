package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.io.*;
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
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class Dilithium {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator d2KPG; private static KeyPairGenerator d3KPG; private static KeyPairGenerator d5KPG;
    private static KeyPairGenerator d2AesKPG; private static KeyPairGenerator d3AesKPG; private static KeyPairGenerator d5AesKPG;

    private static KeyPair d2KP; private static KeyPair d3KP; private static KeyPair d5KP;
    private static KeyPair d2AesKP; private static KeyPair d3AesKP; private static KeyPair d5AesKP;

    private static KeyFactory d2KF; private static KeyFactory d3KF; private static KeyFactory d5KF;
    private static KeyFactory d2AesKF; private static KeyFactory d3AesKF; private static KeyFactory d5AesKF;

    private byte[] d2Signature; private byte[] d3Signature; private byte[] d5Signature;
    private byte[] d2AesSignature; private byte[] d3AesSignature; private byte[] d5AesSignature;

    private static Signature d2Sig; private static Signature d3Sig; private static Signature d5Sig;
    private static Signature d2AesSig; private static Signature d3AesSig; private static Signature d5AesSig;


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
        // Generating KPGs
        d2KPG = KeyPairGenerator.getInstance("DILITHIUM2", "BCPQC"); d2KPG.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom());
        d3KPG = KeyPairGenerator.getInstance("DILITHIUM3", "BCPQC"); d3KPG.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom());
        d5KPG = KeyPairGenerator.getInstance("DILITHIUM5", "BCPQC"); d5KPG.initialize(DilithiumParameterSpec.dilithium5, new SecureRandom());
        d2AesKPG = KeyPairGenerator.getInstance("DILITHIUM2-AES", "BCPQC"); d2AesKPG.initialize(DilithiumParameterSpec.dilithium2_aes, new SecureRandom());
        d3AesKPG = KeyPairGenerator.getInstance("DILITHIUM3-AES", "BCPQC"); d3AesKPG.initialize(DilithiumParameterSpec.dilithium3_aes, new SecureRandom());
        d5AesKPG = KeyPairGenerator.getInstance("DILITHIUM5-AES", "BCPQC"); d5AesKPG.initialize(DilithiumParameterSpec.dilithium5_aes, new SecureRandom());
        // Generating KP from KPGs
        d2KP = d2KeyGeneration(); d3KP = d3KeyGeneration(); d5KP = d5KeyGeneration();
        d2AesKP = d2AesKeyGeneration(); d3AesKP = d3AesKeyGeneration(); d5AesKP = d5AesKeyGeneration();
        // Creating signature instances
        d2Sig = Signature.getInstance("DILITHIUM2", "BCPQC"); d3Sig = Signature.getInstance("DILITHIUM3", "BCPQC"); d5Sig = Signature.getInstance("DILITHIUM5", "BCPQC");
        d2AesSig = Signature.getInstance("DILITHIUM2-AES", "BCPQC"); d3AesSig = Signature.getInstance("DILITHIUM3-AES", "BCPQC"); d5AesSig = Signature.getInstance("DILITHIUM5-AES", "BCPQC");
        // Creating signatures using the signature benchmark classes. *NB -> These runs are not benchmarked, so performance not impacted.
        d2Signature = d2Sign(); d3Signature = d3Sign(); d5Signature = d5Sign();
        d2AesSignature = d2AesSign(); d3AesSignature = d3AesSign(); d5AesSignature = d5AesSign();
        // Creating KF to do KP recovery
        d2KF = KeyFactory.getInstance("DILITHIUM2", "BCPQC"); d3KF = KeyFactory.getInstance("DILITHIUM3", "BCPQC"); d5KF = KeyFactory.getInstance("DILITHIUM5", "BCPQC");
        d2AesKF = KeyFactory.getInstance("DILITHIUM2-AES", "BCPQC"); d3AesKF = KeyFactory.getInstance("DILITHIUM3-AES", "BCPQC"); d5AesKF = KeyFactory.getInstance("DILITHIUM5-AES", "BCPQC");
    }
    // ************************** \\
    // * Section 6: Dilithium 2 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair d2KeyGeneration() {
        return d2KPG.generateKeyPair();
    }

    @Benchmark
    public void d2PrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d2KF.generatePrivate(new PKCS8EncodedKeySpec(d2KP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d2PublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d2KF.generatePublic(new X509EncodedKeySpec(d2KP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Public Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public static byte[] d2Sign() throws Exception {
        d2Sig.initSign(d2KP.getPrivate(), new SecureRandom());
        d2Sig.update(plaintext, 0, plaintext.length);
        return d2Sig.sign();
    }

    @Benchmark
    public boolean d2Verify() throws Exception {
        d2Sig.initVerify(d2KP.getPublic());
        d2Sig.update(plaintext, 0, plaintext.length);
        return d2Sig.verify(d2Signature);
    }
    // ************************** \\
    // * Section 7: Dilithium 3 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair d3KeyGeneration() {
        return d3KPG.generateKeyPair();
    }

    @Benchmark
    public void d3PrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d3KF.generatePrivate(new PKCS8EncodedKeySpec(d3KP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d3PublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d3KF.generatePublic(new X509EncodedKeySpec(d3KP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Public Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] d3Sign() throws Exception {
        d3Sig.initSign(d3KP.getPrivate(), new SecureRandom());
        d3Sig.update(plaintext, 0, plaintext.length);
        return d3Sig.sign();
    }

    @Benchmark
    public boolean d3Verify() throws Exception {
        d3Sig.initVerify(d3KP.getPublic());
        d3Sig.update(plaintext, 0, plaintext.length);
        return d3Sig.verify(d3Signature);
    }
    // ************************** \\
    // * Section 8: Dilithium 5 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair d5KeyGeneration() {
        return d5KPG.generateKeyPair();
    }

    @Benchmark
    public void d5PrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d5KF.generatePrivate(new PKCS8EncodedKeySpec(d5KP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d5PublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d5KF.generatePublic(new X509EncodedKeySpec(d5KP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Public Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] d5Sign() throws Exception {
        d5Sig.initSign(d5KP.getPrivate(), new SecureRandom());
        d5Sig.update(plaintext, 0, plaintext.length);
        return d5Sig.sign();
    }

    @Benchmark
    public boolean d5Verify() throws Exception {
        d5Sig.initVerify(d5KP.getPublic());
        d5Sig.update(plaintext, 0, plaintext.length);
        return d5Sig.verify(d5Signature);
    }
    // ****************************** \\
    // * Section 9: Dilithium 2 AES * \\
    // ****************************** \\
    @Benchmark
    public static KeyPair d2AesKeyGeneration() {
        return d2AesKPG.generateKeyPair();
    }

    @Benchmark
    public void d2AesPrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d2AesKF.generatePrivate(new PKCS8EncodedKeySpec(d2AesKP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d2AesPublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d2AesKF.generatePublic(new X509EncodedKeySpec(d2AesKP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] d2AesSign() throws Exception {
        d2AesSig.initSign(d2AesKP.getPrivate(), new SecureRandom());
        d2AesSig.update(plaintext, 0, plaintext.length);
        return d2AesSig.sign();
    }

    @Benchmark
    public boolean d2AesVerify() throws Exception {
        d2AesSig.initVerify(d2AesKP.getPublic());
        d2AesSig.update(plaintext, 0, plaintext.length);
        return d2AesSig.verify(d2AesSignature);
    }
    // ******************************* \\
    // * Section 10: Dilithium 3 AES * \\
    // ******************************* \\
    @Benchmark
    public static KeyPair d3AesKeyGeneration() {
        return d3AesKPG.generateKeyPair();
    }

    @Benchmark
    public void d3AesPrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d3AesKF.generatePrivate(new PKCS8EncodedKeySpec(d3AesKP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d3AesPublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d3AesKF.generatePublic(new X509EncodedKeySpec(d3AesKP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Public Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] d3AesSign() throws Exception {
        d3AesSig.initSign(d3AesKP.getPrivate(), new SecureRandom());
        d3AesSig.update(plaintext, 0, plaintext.length);
        return d3AesSig.sign();
    }

    @Benchmark
    public boolean d3AesVerify() throws Exception {
        d3AesSig.initVerify(d3AesKP.getPublic());
        d3AesSig.update(plaintext, 0, plaintext.length);
        return d3AesSig.verify(d3AesSignature);
    }
    // ******************************* \\
    // * Section 11: Dilithium 5 AES * \\
    // ******************************* \\
    @Benchmark
    public static KeyPair d5AesKeyGeneration() {
        return d5AesKPG.generateKeyPair();
    }

    @Benchmark
    public void d5AesPrivateKeyRecovery() throws Exception {
        // Creating Private Key
        DilithiumKey privKey = (DilithiumKey)d5AesKF.generatePrivate(new PKCS8EncodedKeySpec(d5AesKP.getPrivate().getEncoded()));
        // Serializing and writing the Private Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        // Deserializing and writing the Private Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey privKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Private Key with Serialized Private Key
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void d5AesPublicKeyRecovery() throws Exception {
        // Creating Public Key
        DilithiumKey pubKey = (DilithiumKey)d5AesKF.generatePublic(new X509EncodedKeySpec(d5AesKP.getPublic().getEncoded()));
        // Serializing and writing the Public Key
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        // Deserializing and writing the Public Key to new variable
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        DilithiumKey pubKey2 = (DilithiumKey)oIn.readObject();
        // Comparing original Public Key with Serialized Private Key
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] d5AesSign() throws Exception {
        d5AesSig.initSign(d5AesKP.getPrivate(), new SecureRandom());
        d5AesSig.update(plaintext, 0, plaintext.length);
        return d5AesSig.sign();
    }

    @Benchmark
    public boolean d5AesVerify() throws Exception {
        d5AesSig.initVerify(d5AesKP.getPublic());
        d5AesSig.update(plaintext, 0, plaintext.length);
        return d5AesSig.verify(d5AesSignature);
    }
    // ************************************************************** \\
    // * Section 12: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
    public static byte[] dilithiumSign(KeyPair kp, byte[] plaintext, Signature sig) throws Exception {
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    public static Boolean dilithiumVerify(KeyPair kp, byte[] sig, byte[] plaintext, Signature signature) throws Exception {
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
        return "Signature: " + Base64.getEncoder().encodeToString(signature);
    }

    public static void saveVerificationResult(boolean verify, String filePath) {
        String verificationText = verify ? "Signature is valid" : "Signature is not valid";
        saveDataToFile(verificationText, filePath);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/Dilithium Benchmarks/";
        String d2filePath = getFilePath(foldersPath, "Dilithium-2/Keys.txt"); String d2SigFilePath = getFilePath(foldersPath, "Dilithium-2/Signatures.txt"); String d2VerifyFilePath = getFilePath(foldersPath, "Dilithium-2/VerifySignatures.txt");
        String d3filePath = getFilePath(foldersPath, "Dilithium-3/Keys.txt"); String d3SigFilePath = getFilePath(foldersPath, "Dilithium-3/Signatures.txt"); String d3VerifyFilePath = getFilePath(foldersPath, "Dilithium-3/VerifySignatures.txt");
        String d5filePath = getFilePath(foldersPath, "Dilithium-5/Keys.txt"); String d5SigFilePath = getFilePath(foldersPath, "Dilithium-5/Signatures.txt"); String d5VerifyFilePath = getFilePath(foldersPath, "Dilithium-5/VerifySignatures.txt");
        String d2AesfilePath = getFilePath(foldersPath, "Dilithium-2-AES/Keys.txt"); String d2AesSigFilePath = getFilePath(foldersPath, "Dilithium-2-AES/Signatures.txt"); String d2AesVerifyFilePath = getFilePath(foldersPath, "Dilithium-2-AES/Verification.txt");
        String d3AesfilePath = getFilePath(foldersPath, "Dilithium-3-AES/Keys.txt"); String d3AesSigFilePath = getFilePath(foldersPath, "Dilithium-3-AES/Signatures.txt"); String d3AesVerifyFilePath = getFilePath(foldersPath, "Dilithium-3-AES/VerifySignatures.txt");
        String d5AesfilePath = getFilePath(foldersPath, "Dilithium-5-AES/Keys.txt"); String d5AesSigFilePath = getFilePath(foldersPath, "Dilithium-5-AES/Signatures.txt"); String d5AesVerifyFilePath = getFilePath(foldersPath, "Dilithium-5-AES/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            // Creating KPGs for key pairs
            KeyPairGenerator d2KPG = KeyPairGenerator.getInstance("DILITHIUM2", "BCPQC"); d2KPG.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom());
            KeyPairGenerator d3KPG = KeyPairGenerator.getInstance("DILITHIUM3", "BCPQC"); d3KPG.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom());
            KeyPairGenerator d5KPG = KeyPairGenerator.getInstance("DILITHIUM5", "BCPQC"); d5KPG.initialize(DilithiumParameterSpec.dilithium5, new SecureRandom());
            KeyPairGenerator d2AesKPG = KeyPairGenerator.getInstance("DILITHIUM2-AES", "BCPQC"); d2AesKPG.initialize(DilithiumParameterSpec.dilithium2_aes, new SecureRandom());
            KeyPairGenerator d3AesKPG = KeyPairGenerator.getInstance("DILITHIUM3-AES", "BCPQC"); d3AesKPG.initialize(DilithiumParameterSpec.dilithium3_aes, new SecureRandom());
            KeyPairGenerator d5AesKPG = KeyPairGenerator.getInstance("DILITHIUM5-AES", "BCPQC"); d5AesKPG.initialize(DilithiumParameterSpec.dilithium5_aes, new SecureRandom());
            // Creating key pairs
            KeyPair d2KP = d2KPG.generateKeyPair(); KeyPair d3KP = d3KPG.generateKeyPair(); KeyPair d5KP = d5KPG.generateKeyPair();
            KeyPair d2AesKP = d2AesKPG.generateKeyPair(); KeyPair d3AesKP = d3AesKPG.generateKeyPair(); KeyPair d5AesKP = d5AesKPG.generateKeyPair();
            String d2keysString = getKeysAsString(d2KP); String d3keysString = getKeysAsString(d3KP); String d5keysString = getKeysAsString(d5KP);
            String d2AeskeysString = getKeysAsString(d2AesKP); String d3AeskeysString = getKeysAsString(d3AesKP); String d5AeskeysString = getKeysAsString(d5AesKP);
            saveDataToFile(d2keysString, d2filePath); saveDataToFile(d3keysString, d3filePath); saveDataToFile(d5keysString, d5filePath);
            saveDataToFile(d2AeskeysString, d2AesfilePath); saveDataToFile(d3AeskeysString, d3AesfilePath); saveDataToFile(d5AeskeysString, d5AesfilePath);
            // Creating signature instances, "BCPQC"
            Signature d2SigInit = Signature.getInstance("DILITHIUM2", "BCPQC"); Signature d3SigInit = Signature.getInstance("DILITHIUM3", "BCPQC"); Signature d5SigInit = Signature.getInstance("DILITHIUM5", "BCPQC");
            Signature d2AesSigInit = Signature.getInstance("DILITHIUM2-AES", "BCPQC"); Signature d3AesSigInit = Signature.getInstance("DILITHIUM3-AES", "BCPQC"); Signature d5AesSigInit = Signature.getInstance("DILITHIUM5-AES", "BCPQC");
            // Creating signing instances
            byte[] d2Sig = dilithiumSign(d2KP, plaintext, d2SigInit); byte[] d3Sig = dilithiumSign(d3KP, plaintext, d3SigInit); byte[] d5Sig = dilithiumSign(d5KP, plaintext, d5SigInit);
            byte[] d2AesSig = dilithiumSign(d2AesKP, plaintext, d2AesSigInit); byte[] d3AesSig = dilithiumSign(d3AesKP, plaintext, d3AesSigInit); byte[] d5AesSig = dilithiumSign(d5AesKP, plaintext, d5AesSigInit);
            String d2DecodedSignature = decodeSignature(d2Sig); String d3DecodedSignature = decodeSignature(d3Sig); String d5DecodedSignature = decodeSignature(d5Sig);
            String d2AesDecodedSignature = decodeSignature(d2AesSig); String d3AesDecodedSignature = decodeSignature(d3AesSig); String d5AesDecodedSignature = decodeSignature(d5AesSig);
            saveDataToFile(d2DecodedSignature, d2SigFilePath); saveDataToFile(d3DecodedSignature, d3SigFilePath); saveDataToFile(d5DecodedSignature, d5SigFilePath);
            saveDataToFile(d2AesDecodedSignature, d2AesSigFilePath); saveDataToFile(d3AesDecodedSignature, d3AesSigFilePath); saveDataToFile(d5AesDecodedSignature, d5AesSigFilePath);
            // Verifying signatures
            Boolean d2Verify = dilithiumVerify(d2KP, d2Sig, plaintext, d2SigInit); Boolean d3Verify = dilithiumVerify(d3KP, d3Sig, plaintext, d3SigInit); Boolean d5Verify = dilithiumVerify(d5KP, d5Sig, plaintext, d5SigInit);
            Boolean d2AesVerify = dilithiumVerify(d2AesKP, d2AesSig, plaintext, d2AesSigInit); Boolean d3AesVerify = dilithiumVerify(d3AesKP, d3AesSig, plaintext, d3AesSigInit); Boolean d5AesVerify = dilithiumVerify(d5AesKP, d5AesSig, plaintext, d5AesSigInit);
            saveVerificationResult(d2Verify, d2VerifyFilePath); saveVerificationResult(d3Verify, d3VerifyFilePath); saveVerificationResult(d5Verify, d5VerifyFilePath);
            saveVerificationResult(d2AesVerify, d2AesVerifyFilePath); saveVerificationResult(d3AesVerify, d3AesVerifyFilePath); saveVerificationResult(d5AesVerify, d5AesVerifyFilePath);
        }
    }
}
