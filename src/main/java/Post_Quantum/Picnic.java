package Post_Quantum;

// ********************** \\
// * Section 1: Imports * \\
// ********************** \\

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.security.*;
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
    @Param({"Picnic", "SHA3-512WITHPicnic", "SHA512WITHPicnic", "SHAKE256WITHPICNIC"})
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
        l1fsSig = Signature.getInstance(algorithm);
        l3fsSig = l1fsSig; l5fsSig = l1fsSig; l1fullSig = l1fsSig; l3fullSig = l1fsSig; l5fullSig = l1fsSig;
        // Creating KPG instances
        l1fsKPG = KeyPairGenerator.getInstance("Picnic");
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
}
