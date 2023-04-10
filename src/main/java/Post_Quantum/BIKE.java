package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
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
public class BIKE {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator bike128KPG; private static KeyPairGenerator bike192KPG; private static KeyPairGenerator bike256KPG;

    private static KeyPair bike128KP; private static KeyPair bike192KP; private static KeyPair bike256KP;

    private static Cipher bike128CipherWrap; private static Cipher bike128CipherUnwrap;
    private static Cipher bike192CipherWrap; private static Cipher bike192CipherUnwrap;
    private static Cipher bike256CipherWrap; private static Cipher bike256CipherUnwrap;

    private static byte[] keyBytes;

    private static byte[] bike128WB; private static byte[] bike192WB; private static byte[] bike256WB;

    private static Key key;
    // ******************** \\
    // * Section 4: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        key = new SecretKeySpec(keyBytes, "AES");

        bike128KPG = KeyPairGenerator.getInstance("BIKE"); bike128KPG.initialize(BIKEParameterSpec.bike128, new SecureRandom());
        bike192KPG = KeyPairGenerator.getInstance("BIKE"); bike192KPG.initialize(BIKEParameterSpec.bike192, new SecureRandom());
        bike256KPG = KeyPairGenerator.getInstance("BIKE"); bike256KPG.initialize(BIKEParameterSpec.bike256, new SecureRandom());

        bike128KP = bike128KeyGenerator(); bike192KP = bike192KeyGenerator(); bike256KP = bike256KeyGenerator();

        bike128CipherWrap = Cipher.getInstance("BIKE"); bike128CipherWrap.init(Cipher.WRAP_MODE, bike128KP.getPublic());
        bike192CipherWrap = Cipher.getInstance("BIKE"); bike192CipherWrap.init(Cipher.WRAP_MODE, bike192KP.getPublic());
        bike256CipherWrap = Cipher.getInstance("BIKE"); bike256CipherWrap.init(Cipher.WRAP_MODE, bike256KP.getPublic());
        bike128WB = bike128WrapKey(); bike192WB = bike192WrapKey(); bike256WB = bike256WrapKey();

        bike128CipherUnwrap = Cipher.getInstance("BIKE"); bike128CipherUnwrap.init(Cipher.UNWRAP_MODE, bike128KP.getPrivate());
        bike192CipherUnwrap = Cipher.getInstance("BIKE"); bike192CipherUnwrap.init(Cipher.UNWRAP_MODE, bike192KP.getPrivate());
        bike256CipherUnwrap = Cipher.getInstance("BIKE"); bike256CipherUnwrap.init(Cipher.UNWRAP_MODE, bike256KP.getPrivate());
    }
    // ************************ \\
    // * Section 5: BIKE 128 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair bike128KeyGenerator() {
        return bike128KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike128WrapKey() throws Exception {
        return bike128CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike128UnwrapKey() throws Exception {
        return bike128CipherUnwrap.unwrap(bike128WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************ \\
    // * Section 6: BIKE 256 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair bike192KeyGenerator() {
        return bike192KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike192WrapKey() throws Exception {
        return bike192CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike192UnwrapKey() throws Exception {
        return bike192CipherUnwrap.unwrap(bike192WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************ \\
    // * Section 7: BIKE 256 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair bike256KeyGenerator() {
        return bike256KPG.generateKeyPair();
    }

    @Benchmark
    public static byte[] bike256WrapKey() throws Exception {
        return bike256CipherWrap.wrap(key);
    }

    @Benchmark
    public static Key bike256UnwrapKey() throws Exception {
        return bike256CipherUnwrap.unwrap(bike256WB, "AES", Cipher.SECRET_KEY);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(BIKE.class.getSimpleName())
                .resultFormat(ResultFormatType.CSV)
                .result("BIKE.csv")
                .build();
        new Runner(opt).run();
    }
}
