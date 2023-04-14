package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
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
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class SphincsPlus {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator sha128KeyGen; private static KeyPairGenerator sha192KeyGen; private static KeyPairGenerator sha256KeyGen;
    private static KeyPairGenerator haraka128KeyGen; private static KeyPairGenerator haraka192KeyGen; private static KeyPairGenerator haraka256KeyGen;
    private static KeyPairGenerator shake128KeyGen; private static KeyPairGenerator shake192KeyGen; private static KeyPairGenerator shake256KeyGen;

    private static KeyPair sha128Keypair; private static KeyPair sha192Keypair; private static KeyPair sha256Keypair;
    private static KeyPair haraka128Keypair; private static KeyPair haraka192Keypair; private static KeyPair haraka256Keypair;
    private static KeyPair shake128Keypair; private static KeyPair shake192Keypair; private static KeyPair shake256Keypair;

    private static byte[] sha128Signature; private static byte[] sha192Signature; private static byte[] sha256Signature;
    private static byte[] haraka128Signature; private static byte[] haraka192Signature; private static byte[] haraka256Signature;
    private static byte[] shake128Signature; private static byte[] shake192Signature; private static byte[] shake256Signature;

    private static Signature sig;
    private static byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    //@Param({"256", "512", "1024", "2048"})
    //static int plaintextSize;
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        plaintext = new byte[256];
        new SecureRandom().nextBytes(plaintext);

        sig = Signature.getInstance("SPHINCSPlus", "BCPQC");

        sha128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha128KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_128f, new SecureRandom());
        sha192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha192KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_192f, new SecureRandom());
        sha256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha256KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_256f, new SecureRandom());
        haraka128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka128KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_128f, new SecureRandom());
        haraka192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka192KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_192f, new SecureRandom());
        haraka256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka256KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_256f, new SecureRandom());
        shake128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake128KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_128f, new SecureRandom());
        shake192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake192KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_192f, new SecureRandom());
        shake256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake256KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_256f, new SecureRandom());

        sha128Keypair = sha128KeypairGeneration(); sha192Keypair = sha192KeypairGeneration(); sha256Keypair = sha256KeypairGeneration();
        haraka128Keypair = haraka128KeypairGeneration(); haraka192Keypair = haraka192KeypairGeneration(); haraka256Keypair = haraka256KeypairGeneration();
        shake128Keypair = shake128KeypairGeneration(); shake192Keypair = shake192KeypairGeneration(); shake256Keypair = shake256KeypairGeneration();

        sha128Signature = sha128Sign(); sha192Signature = sha192Sign(); sha256Signature = sha256Sign();
        haraka128Signature = haraka128Sign(); haraka192Signature = haraka192Sign(); haraka256Signature = haraka256Sign();
        shake128Signature = shake128Sign(); shake192Signature = shake192Sign(); shake256Signature = shake256Sign();
    }
    // ************************ \\
    // * Section 6: SHA-2 128 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair sha128KeypairGeneration() {
        return sha128KeyGen.generateKeyPair();
    }

    @Benchmark
    public void sha128PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void sha128PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] sha128Sign() throws Exception {
        sig.initSign(sha128Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean sha128Verify() throws Exception {
        sig.initVerify(sha128Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(sha128Signature);
    }
    // ************************ \\
    // * Section 7: SHA-2 192 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair sha192KeypairGeneration() {
        return sha192KeyGen.generateKeyPair();
    }

    @Benchmark
    public void sha192PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void sha192PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] sha192Sign() throws Exception {
        sig.initSign(sha192Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean sha192Verify() throws Exception {
        sig.initVerify(sha192Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(sha192Signature);
    }
    // ************************ \\
    // * Section 8: SHA-2 256 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair sha256KeypairGeneration() {
        return sha256KeyGen.generateKeyPair();
    }

    @Benchmark
    public void sha256PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void sha256PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] sha256Sign() throws Exception {
        sig.initSign(sha256Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean sha256Verify() throws Exception {
        sig.initVerify(sha256Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(sha256Signature);
    }
    // ************************* \\
    // * Section 9: Haraka 128 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair haraka128KeypairGeneration() {
        return haraka128KeyGen.generateKeyPair();
    }

    @Benchmark
    public void haraka128PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void haraka128PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] haraka128Sign() throws Exception {
        sig.initSign(haraka128Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean haraka128Verify() throws Exception {
        sig.initVerify(haraka128Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(haraka128Signature);
    }
    // ************************** \\
    // * Section 10: Haraka 192 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair haraka192KeypairGeneration() {
        return  haraka192KeyGen.generateKeyPair();
    }

    @Benchmark
    public void haraka192PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void haraka192PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] haraka192Sign() throws Exception {
        sig.initSign(haraka192Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean haraka192Verify() throws Exception {
        sig.initVerify(haraka192Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(haraka192Signature);
    }
    // ************************** \\
    // * Section 11: Haraka 256 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair haraka256KeypairGeneration() {
        return haraka256KeyGen.generateKeyPair();
    }

    @Benchmark
    public void haraka256PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void haraka256PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.haraka_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] haraka256Sign() throws Exception {
        sig.initSign(haraka256Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean haraka256Verify() throws Exception {
        sig.initVerify(haraka256Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(haraka256Signature);
    }
    // ************************* \\
    // * Section 12: Shake 128 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair shake128KeypairGeneration() {
        return shake128KeyGen.generateKeyPair();
    }

    @Benchmark
    public void shake128PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void shake128PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_128f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] shake128Sign() throws Exception {
        sig.initSign(shake128Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean shake128Verify() throws Exception {
        sig.initVerify(shake128Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(shake128Signature);
    }
    // ************************* \\
    // * Section 13: Shake 192 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair shake192KeypairGeneration() {
        return  shake192KeyGen.generateKeyPair();
    }

    @Benchmark
    public void shake192PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void shake192PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_192f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] shake192Sign() throws Exception {
        sig.initSign(shake192Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean shake192Verify() throws Exception {
        sig.initVerify(shake192Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(shake192Signature);
    }
    // ************************* \\
    // * Section 13: Shake 256 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair shake256KeypairGeneration() {
        return shake256KeyGen.generateKeyPair();
    }

    @Benchmark
    public void shake256PrivateKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(privKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(privKey, privKey2);
    }

    @Benchmark
    public void shake256PublicKeyRecovery() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
        kpg.initialize(SPHINCSPlusParameterSpec.shake_256f, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(pubKey);
        oOut.close();
        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();
        assertEquals(pubKey, pubKey2);
    }

    @Benchmark
    public byte[] shake256Sign() throws Exception {
        sig.initSign(shake256Keypair.getPrivate(), new SecureRandom());
        sig.update(plaintext, 0, plaintext.length);
        return sig.sign();
    }

    @Benchmark
    public boolean shake256Verify() throws Exception {
        sig.initVerify(shake256Keypair.getPublic());
        sig.update(plaintext, 0, plaintext.length);
        return sig.verify(shake256Signature);
    }
    // ************************************************************** \\
    // * Section 14: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************** \\
    public static byte[] sphincsSign(KeyPair kp, Signature signature, byte[] plaintext) throws Exception {
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static Boolean sphincsVerify(KeyPair kp, Signature signature, byte[] plaintext, byte[] sig) throws Exception {
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
        return "Public Key:\n" + result1 + "\n\n" +
                "Private Key:\n" + result2 + "\n";
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

    public static String decodePlaintext(byte[] text) {
        return "Plaintext:\n" + Base64.getEncoder().encodeToString(text);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
        // Creating files / folders
        String foldersPath = "Benchmark Results/Post-Quantum/SphincsPlus Benchmarks/";
        String FilePathPlaintext = getFilePath(foldersPath, "Plaintext/Plaintext.txt"); String FilePathPlaintextDecoded = getFilePath(foldersPath, "Plaintext/Decoded_Plaintext.txt");

        String sha128FilePath = getFilePath(foldersPath, "Keys/Sha-2-128/Encoded/Keys.txt"); String sha128FilePathDecoded = getFilePath(foldersPath, "Keys/Sha-2-128/Decoded/Keys.txt");
        String sha128SigFilePath = getFilePath(foldersPath, "Signatures/Sha-2-128/Encoded/Signatures.txt"); String sha128SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Sha-2-128/Decoded/Signatures.txt");
        String sha128VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Sha-2-128/VerifySignatures.txt");

        String sha192FilePath = getFilePath(foldersPath, "Keys/Sha-2-192/Encoded/Keys.txt"); String sha192FilePathDecoded = getFilePath(foldersPath, "Keys/Sha-2-192/Decoded/Keys.txt");
        String sha192SigFilePath = getFilePath(foldersPath, "Signatures/Sha-2-192/Encoded/Signatures.txt"); String sha192SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Sha-2-192/Decoded/Signatures.txt");
        String sha192VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Sha-2-192/VerifySignatures.txt");

        String sha256FilePath = getFilePath(foldersPath, "Keys/Sha-2-256/Encoded/Keys.txt"); String sha256FilePathDecoded = getFilePath(foldersPath, "Keys/Sha-2-256/Decoded/Keys.txt");
        String sha256SigFilePath = getFilePath(foldersPath, "Signatures/Sha-2-256/Encoded/Signatures.txt"); String sha256SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Sha-2-256/Decoded/Signatures.txt");
        String sha256VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Sha-2-256/VerifySignatures.txt");

        String haraka128FilePath = getFilePath(foldersPath, "Keys/Haraka-128/Encoded/Keys.txt"); String haraka128FilePathDecoded = getFilePath(foldersPath, "Keys/Haraka-128/Decoded/Keys.txt");
        String haraka128SigFilePath = getFilePath(foldersPath, "Signatures/Haraka-128/Encoded/Signatures.txt");  String haraka128SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Haraka-128/Decoded/Signatures.txt");
        String haraka128VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Haraka-128/VerifySignatures.txt");

        String haraka192FilePath = getFilePath(foldersPath, "Keys/Haraka-192/Encoded/Keys.txt"); String haraka192FilePathDecoded = getFilePath(foldersPath, "Keys/Haraka-192/Decoded/Keys.txt");
        String haraka192SigFilePath = getFilePath(foldersPath, "Signatures/Haraka-192/Encoded/Signatures.txt"); String haraka192SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Haraka-192/Decoded/Signatures.txt");
        String haraka192VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Haraka-192/VerifySignatures.txt");

        String haraka256FilePath = getFilePath(foldersPath, "Keys/Haraka-256/Encoded/Keys.txt"); String haraka256FilePathDecoded = getFilePath(foldersPath, "Keys/Haraka-256/Decoded/Keys.txt");
        String haraka256SigFilePath = getFilePath(foldersPath, "Signatures/Haraka-256/Encoded/Signatures.txt"); String haraka256SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Haraka-256/Decoded/Signatures.txt");
        String haraka256VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Haraka-256/VerifySignatures.txt");

        String shake128FilePath = getFilePath(foldersPath, "Keys/Shake-128/Encoded/Keys.txt"); String shake128FilePathDecoded = getFilePath(foldersPath, "Keys/Shake-128/Decoded/Keys.txt");
        String shake128SigFilePath = getFilePath(foldersPath, "Signatures/Shake-128/Encoded/Signatures.txt"); String shake128SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Shake-128/Decoded/Signatures.txt");
        String shake128VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Shake-128/VerifySignatures.txt");

        String shake192FilePath = getFilePath(foldersPath, "Keys/Shake-192/Encoded/Keys.txt"); String shake192FilePathDecoded = getFilePath(foldersPath, "Keys/Shake-192/Decoded/Keys.txt");
        String shake192SigFilePath = getFilePath(foldersPath, "Signatures/Shake-192/Encoded/Signatures.txt"); String shake192SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Shake-192/Decoded/Signatures.txt");
        String shake192VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Shake-192/VerifySignatures.txt");

        String shake256FilePath = getFilePath(foldersPath, "Keys/Shake-256/Encoded/Keys.txt"); String shake256FilePathDecoded = getFilePath(foldersPath, "Keys/Shake-256/Decoded/Keys.txt");
        String shake256SigFilePath = getFilePath(foldersPath, "Signatures/Shake-256/Encoded/Signatures.txt"); String shake256SigFilePathDecoded = getFilePath(foldersPath, "Signatures/Shake-256/Decoded/Signatures.txt");
        String shake256VerifyFilePathDecoded = getFilePath(foldersPath, "SignatureVerification/Shake-256/VerifySignatures.txt");
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = new byte[2048];
            new SecureRandom().nextBytes(plaintext);
            // Encoded plaintext
            writeBytesToFile(plaintext, FilePathPlaintext);
            // Decoded plaintext
            String decodedPlaintext = decodePlaintext(plaintext);
            saveDataToFile(decodedPlaintext, FilePathPlaintextDecoded);
            // Creating KPGs for key pairs
            KeyPairGenerator sha128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha128KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_128f, new SecureRandom());
            KeyPairGenerator sha192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha192KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_192f, new SecureRandom());
            KeyPairGenerator sha256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); sha256KeyGen.initialize(SPHINCSPlusParameterSpec.sha2_256f, new SecureRandom());
            KeyPairGenerator haraka128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka128KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_128f, new SecureRandom());
            KeyPairGenerator haraka192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka192KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_192f, new SecureRandom());
            KeyPairGenerator haraka256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); haraka256KeyGen.initialize(SPHINCSPlusParameterSpec.haraka_256f, new SecureRandom());
            KeyPairGenerator shake128KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake128KeyGen.initialize(SPHINCSPlusParameterSpec.shake_128f, new SecureRandom());
            KeyPairGenerator shake192KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake192KeyGen.initialize(SPHINCSPlusParameterSpec.shake_192f, new SecureRandom());
            KeyPairGenerator shake256KeyGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC"); shake256KeyGen.initialize(SPHINCSPlusParameterSpec.shake_256f, new SecureRandom());
            // Creating key pairs
            KeyPair sha128KP = sha128KeyGen.generateKeyPair(); KeyPair sha192KP = sha192KeyGen.generateKeyPair(); KeyPair sha256KP = sha256KeyGen.generateKeyPair();
            KeyPair haraka128KP = haraka128KeyGen.generateKeyPair(); KeyPair haraka192KP = haraka192KeyGen.generateKeyPair(); KeyPair haraka256KP = haraka256KeyGen.generateKeyPair();
            KeyPair shake128KP = shake128KeyGen.generateKeyPair(); KeyPair shake192KP = shake192KeyGen.generateKeyPair(); KeyPair shake256KP = shake256KeyGen.generateKeyPair();
            String sha128KeysString = getKeysAsString(sha128KP); String sha192KeysString = getKeysAsString(sha192KP); String sha256KeysString = getKeysAsString(sha256KP);
            String haraka128KeysString = getKeysAsString(haraka128KP); String haraka192KeysString = getKeysAsString(haraka192KP); String haraka256KeysString = getKeysAsString(haraka256KP);
            String shake128KeysString = getKeysAsString(shake128KP); String shake192KeysString = getKeysAsString(shake192KP); String shake256KeysString = getKeysAsString(shake256KP);
            saveDataToFile(sha128KeysString, sha128FilePathDecoded); saveDataToFile(sha192KeysString, sha192FilePathDecoded); saveDataToFile(sha256KeysString, sha256FilePathDecoded);
            saveDataToFile(haraka128KeysString, haraka128FilePathDecoded); saveDataToFile(haraka192KeysString, haraka192FilePathDecoded); saveDataToFile(haraka256KeysString, haraka256FilePathDecoded);
            saveDataToFile(shake128KeysString, shake128FilePathDecoded); saveDataToFile(shake192KeysString, shake192FilePathDecoded); saveDataToFile(shake256KeysString, shake256FilePathDecoded);
            // Encoded keys
            String sha128String = getKeys(sha128KP); String sha192String = getKeys(sha192KP); String sha256String = getKeys(sha256KP);
            String haraka128String = getKeys(haraka128KP); String haraka192String = getKeys(haraka192KP); String haraka256String = getKeys(haraka256KP);
            String shake128String = getKeys(shake128KP); String shake192String = getKeys(shake192KP); String shake256String = getKeys(shake256KP);
            saveDataToFile(sha128String, sha128FilePath); saveDataToFile(sha192String, sha192FilePath); saveDataToFile(sha256String, sha256FilePath);
            saveDataToFile(haraka128String, haraka128FilePath); saveDataToFile(haraka192String, haraka192FilePath); saveDataToFile(haraka256String, haraka256FilePath);
            saveDataToFile(shake128String,shake128FilePath); saveDataToFile(shake192String, shake192FilePath); saveDataToFile(shake256String, shake256FilePath);
            // Creating signing instances
            byte[] sha128Sig = sphincsSign(sha128KP, sig, plaintext); byte[] sha192Sig = sphincsSign(sha192KP, sig, plaintext); byte[] sha256Sig = sphincsSign(sha256KP, sig, plaintext);
            byte[] haraka128Sig = sphincsSign(haraka128KP, sig, plaintext); byte[] haraka192Sig = sphincsSign(haraka192KP, sig, plaintext); byte[] haraka256Sig = sphincsSign(haraka256KP, sig, plaintext);
            byte[] shake128Sig = sphincsSign(shake128KP, sig, plaintext); byte[] shake192Sig = sphincsSign(shake192KP, sig, plaintext); byte[] shake256Sig = sphincsSign(shake256KP, sig, plaintext);
            String sha128DecodedSignature = decodeSignature(sha128Sig); String sha192DecodedSignature = decodeSignature(sha192Sig); String sha256DecodedSignature = decodeSignature(sha256Sig);
            String haraka128DecodedSignature = decodeSignature(haraka128Sig); String haraka192DecodedSignature = decodeSignature(haraka192Sig); String haraka256DecodedSignature = decodeSignature(haraka256Sig);
            String shake128DecodedSignature = decodeSignature(shake128Sig); String shake192DecodedSignature = decodeSignature(shake192Sig); String shake256DecodedSignature = decodeSignature(shake256Sig);
            saveDataToFile(sha128DecodedSignature, sha128SigFilePathDecoded); saveDataToFile(sha192DecodedSignature, sha192SigFilePathDecoded); saveDataToFile(sha256DecodedSignature, sha256SigFilePathDecoded);
            saveDataToFile(haraka128DecodedSignature, haraka128SigFilePathDecoded); saveDataToFile(haraka192DecodedSignature, haraka192SigFilePathDecoded); saveDataToFile(haraka256DecodedSignature, haraka256SigFilePathDecoded);
            saveDataToFile(shake128DecodedSignature, shake128SigFilePathDecoded); saveDataToFile(shake192DecodedSignature, shake192SigFilePathDecoded); saveDataToFile(shake256DecodedSignature, shake256SigFilePathDecoded);
            // Encoded signatures
            writeBytesToFile(sha128Sig, sha128SigFilePath); writeBytesToFile(sha192Sig, sha192SigFilePath); writeBytesToFile(sha256Sig, sha256SigFilePath);
            writeBytesToFile(haraka128Sig, haraka128SigFilePath); writeBytesToFile(haraka192Sig, haraka192SigFilePath); writeBytesToFile(haraka256Sig, haraka256SigFilePath);
            writeBytesToFile(shake128Sig, shake128SigFilePath); writeBytesToFile(shake192Sig, shake192SigFilePath); writeBytesToFile(shake256Sig, shake256SigFilePath);
            // Verifying signatures
            Boolean sha128Verify = sphincsVerify(sha128KP, sig, plaintext, sha128Sig); Boolean sha192Verify = sphincsVerify(sha192KP, sig, plaintext, sha192Sig); Boolean sha256Verify = sphincsVerify(sha256KP, sig, plaintext, sha256Sig);
            Boolean haraka128Verify = sphincsVerify(haraka128KP, sig, plaintext, haraka128Sig); Boolean haraka192Verify = sphincsVerify(haraka192KP, sig, plaintext, haraka192Sig); Boolean haraka256Verify = sphincsVerify(haraka256KP, sig, plaintext, haraka256Sig);
            Boolean shake128Verify = sphincsVerify(shake128KP, sig, plaintext, shake128Sig); Boolean shake192Verify = sphincsVerify(shake192KP, sig, plaintext, shake192Sig); Boolean shake256Verify = sphincsVerify(shake256KP, sig, plaintext, shake256Sig);
            saveVerificationResult(sha128Verify, sha128VerifyFilePathDecoded); saveVerificationResult(sha192Verify, sha192VerifyFilePathDecoded); saveVerificationResult(sha256Verify, sha256VerifyFilePathDecoded);
            saveVerificationResult(haraka128Verify, haraka128VerifyFilePathDecoded); saveVerificationResult(haraka192Verify, haraka192VerifyFilePathDecoded); saveVerificationResult(haraka256Verify, haraka256VerifyFilePathDecoded);
            saveVerificationResult(shake128Verify, shake128VerifyFilePathDecoded); saveVerificationResult(shake192Verify, shake192VerifyFilePathDecoded); saveVerificationResult(shake256Verify, shake256VerifyFilePathDecoded);
        }
    }
}