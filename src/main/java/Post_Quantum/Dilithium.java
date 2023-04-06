package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.interfaces.DilithiumKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    private static KeyPairGenerator d2KPG;    private static KeyPairGenerator d3KPG;    private static KeyPairGenerator d5KPG;
    private static KeyPairGenerator d2AesKPG; private static KeyPairGenerator d3AesKPG; private static KeyPairGenerator d5AesKPG;

    private static KeyPair d2KP;    private static KeyPair d3KP;    private static KeyPair d5KP;
    private static KeyPair d2AesKP; private static KeyPair d3AesKP; private static KeyPair d5AesKP;

    private static KeyFactory d2KF;    private static KeyFactory d3KF;    private static KeyFactory d5KF;
    private static KeyFactory d2AesKF; private static KeyFactory d3AesKF; private static KeyFactory d5AesKF;

    private byte[] d2Signature;    private byte[] d3Signature;    private byte[] d5Signature;
    private byte[] d2AesSignature; private byte[] d3AesSignature; private byte[] d5AesSignature;

    private Signature d2Sig;    private Signature d3Sig;    private Signature d5Sig;
    private Signature d2AesSig; private Signature d3AesSig; private Signature d5AesSig;

    private byte[] plaintext;

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
        // Creating signature instances
        d2Sig = Signature.getInstance("DILITHIUM2"); d3Sig = Signature.getInstance("DILITHIUM3"); d5Sig = Signature.getInstance("DILITHIUM5");
        d2AesSig = Signature.getInstance("DILITHIUM2-AES"); d3AesSig = Signature.getInstance("DILITHIUM3-AES"); d5AesSig = Signature.getInstance("DILITHIUM5-AES");
        // Creating KPG instances
        d2KPG = KeyPairGenerator.getInstance("DILITHIUM2"); d3KPG = KeyPairGenerator.getInstance("DILITHIUM3"); d5KPG = KeyPairGenerator.getInstance("DILITHIUM5");
        d2AesKPG = KeyPairGenerator.getInstance("DILITHIUM2-AES"); d3AesKPG = KeyPairGenerator.getInstance("DILITHIUM3-AES"); d5AesKPG = KeyPairGenerator.getInstance("DILITHIUM5-AES");
        // Initializing KPGs with Parameter Specs
        d2KPG.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom()); d3KPG.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom()); d5KPG.initialize(DilithiumParameterSpec.dilithium5, new SecureRandom());
        d2AesKPG.initialize(DilithiumParameterSpec.dilithium2_aes, new SecureRandom()); d3AesKPG.initialize(DilithiumParameterSpec.dilithium3_aes, new SecureRandom()); d5AesKPG.initialize(DilithiumParameterSpec.dilithium5_aes, new SecureRandom());
        // Generating KP from KPGs
        d2KP = d2KPG.generateKeyPair(); d3KP = d3KPG.generateKeyPair(); d5KP = d5KPG.generateKeyPair();
        d2AesKP = d2AesKPG.generateKeyPair(); d3AesKP = d3AesKPG.generateKeyPair(); d5AesKP = d5AesKPG.generateKeyPair();
        // Creating signatures using the signature benchmark classes. *NB -> These runs are not benchmarked, so performance not impacted.
        d2Signature = d2Sign(); d3Signature = d3Sign(); d5Signature = d5Sign();
        d2AesSignature = d2AesSign(); d3AesSignature = d3AesSign(); d5AesSignature = d5AesSign();
        // Creating KF to do KP recovery
        d2KF = KeyFactory.getInstance("DILITHIUM2"); d3KF = KeyFactory.getInstance("DILITHIUM3"); d5KF = KeyFactory.getInstance("DILITHIUM5");
        d2AesKF = KeyFactory.getInstance("DILITHIUM2-AES"); d3AesKF = KeyFactory.getInstance("DILITHIUM3-AES"); d5AesKF = KeyFactory.getInstance("DILITHIUM5-AES");
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
    public byte[] d2Sign() throws Exception {
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
}
