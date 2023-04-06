package Post_Quantum;

// **********************
// * Section 1: Imports *
// **********************

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.openjdk.jmh.annotations.*;
import java.security.*;
import java.util.concurrent.TimeUnit;

// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\

// ************************** \\
// * Section 3: Dilithium 5 * \\
// ************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1 )
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class Falcon {

    // ************************ \\
    // * Section 4: Variables * \\
    // ************************ \\
    private static KeyPairGenerator kpg; private static KeyPairGenerator kpg2;

    private KeyPair falcon512KP; private KeyPair falcon1024KP;

    private byte[] falcon512Signature; private byte[] falcon1024Signature;

    private Signature sig512; private Signature sig1024;

    private byte[] plaintext;

    // ************************* \\
    // * Section 5: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;

    // ************************ \\
    // * Section 6: Setup     * \\
    // ************************ \\

    @Setup
    public void setup() throws Exception {
        // Setting up starting variables
        Security.addProvider(new BouncyCastlePQCProvider());
        plaintext = new byte[plaintextSize];
        SecureRandom random = new SecureRandom();
        // Falcon 512 variables
        sig512 = Signature.getInstance("Falcon-512");
        kpg = KeyPairGenerator.getInstance("Falcon");
        kpg.initialize(FalconParameterSpec.falcon_512, random);
        // Falcon 1024 variables
        sig1024 = Signature.getInstance("Falcon-1024");
        kpg2 = KeyPairGenerator.getInstance("Falcon");
        kpg2.initialize(FalconParameterSpec.falcon_1024, random);
        // Using variables to call KPG class to go into verify() without impacting benchmarks
        falcon512KP = kpg.generateKeyPair(); falcon1024KP = kpg2.generateKeyPair();
        falcon512Signature = falcon512Sign(); falcon1024Signature = falcon1024Sign();
    }

    // ************************* \\
    // * Section 7: Falcon 512 * \\
    // ************************* \\

    @Benchmark
    public static KeyPair falcon512KeyGeneration() throws Exception {
        return kpg.generateKeyPair();
    }

    @Benchmark
    public byte[] falcon512Sign() throws Exception {
        sig512.initSign(falcon512KP.getPrivate(), new SecureRandom());
        sig512.update(plaintext, 0, plaintext.length);
        return sig512.sign();
    }

    @Benchmark
    public boolean falcon512Verify() throws Exception {
        sig512.initVerify(falcon512KP.getPublic());
        sig512.update(plaintext, 0, plaintext.length);
        return sig512.verify(falcon512Signature);
    }

    // ************************** \\
    // * Section 8: Falcon 1024 * \\
    // ************************** \\

    @Benchmark
    public static KeyPair falcon1024KeyGeneration() throws Exception {
        return kpg2.generateKeyPair();
    }

    @Benchmark
    public byte[] falcon1024Sign() throws Exception {
        sig1024.initSign(falcon1024KP.getPrivate(), new SecureRandom());
        sig1024.update(plaintext, 0, plaintext.length);
        return sig1024.sign();
    }

    @Benchmark
    public boolean falcon1024Verify() throws Exception {
        sig1024.initVerify(falcon1024KP.getPublic());
        sig1024.update(plaintext, 0, plaintext.length);
        return sig1024.verify(falcon1024Signature);
    }
}