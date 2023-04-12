package Post_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@SuppressWarnings("unused")
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class Kyber {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPair k512KP; private static KeyPair k768KP; private static KeyPair k1024KP;
    private static KeyPair k512AesKP; private static KeyPair k768AesKP; private static KeyPair k1024AesKP;

    private static KeyPairGenerator k512KPG; private static KeyPairGenerator k768KPG; private static KeyPairGenerator k1024KPG;
    private static KeyPairGenerator k512AesKPG; private static KeyPairGenerator k768AesKPG; private static KeyPairGenerator k1024AesKPG;

    private static Cipher k512CipherWrap; private static Cipher k512CipherUnwrap;
    private static Cipher k768CipherWrap; private static Cipher k768CipherUnwrap;
    private static Cipher k1024CipherWrap; private static Cipher k1024CipherUnwrap;
    private static Cipher k512AesCipherWrap; private static Cipher k512AesCipherUnwrap;
    private static Cipher k768AesCipherWrap; private static Cipher k768AesCipherUnwrap;
    private static Cipher k1024AesCipherWrap; private static Cipher k1024AesCipherUnwrap;

    private static byte[] k512WB; private static byte[] k768WB; private static byte[] k1024WB;
    private static byte[] k512AesWB; private static byte[] k768AesWB; private static byte[] k1024AesWB;

    private static final byte[] k512KB = new byte[16]; private static final byte[] k768KB = new byte[24]; private static final byte[] k1024KB = new byte[32];
    private static final byte[] k512AesKB = new byte[16]; private static final byte[] k768AesKB = new byte[24]; private static final byte[] k1024AesKB = new byte[32];
    // ******************** \\
    // * Section 5: Setup * \\
    // ******************** \\
    @Setup
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        // Creating KPGs for KPs
        k512KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512.getName()); k512KPG.initialize(KyberParameterSpec.kyber512, new SecureRandom());
        k768KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768.getName()); k768KPG.initialize(KyberParameterSpec.kyber768, new SecureRandom());
        k1024KPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024.getName()); k1024KPG.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
        k512AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber512_aes.getName()); k512AesKPG.initialize(KyberParameterSpec.kyber512_aes, new SecureRandom());
        k768AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber768_aes.getName()); k768AesKPG.initialize(KyberParameterSpec.kyber768_aes, new SecureRandom());
        k1024AesKPG = KeyPairGenerator.getInstance(KyberParameterSpec.kyber1024_aes.getName()); k1024AesKPG.initialize(KyberParameterSpec.kyber1024_aes, new SecureRandom());
        // Generate KeyPairs from benchmark methods. *NB -> These runs are not benchmarked, so performance not impacted.
        k512KP = k512KeyGen(); k768KP = k768KeyGen(); k1024KP = k1024KeyGen();
        k512AesKP = k512AesKeyGen(); k768AesKP = k768AesKeyGen(); k1024AesKP = k1024AesKeyGen();
        // Creating Wrapped and Unwrapped Cipher Instances to Avoid "Cipher not initiated" Errors. Wrapped = Encrypted. Unwrapped = Decrypted
        k512CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber512.getName()); k512CipherWrap.init(Cipher.WRAP_MODE, k512KP.getPublic(), new SecureRandom());
        k512CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber512.getName()); k512CipherUnwrap.init(Cipher.UNWRAP_MODE, k512KP.getPrivate());
        k768CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber768.getName()); k768CipherWrap.init(Cipher.WRAP_MODE, k768KP.getPublic(), new SecureRandom());
        k768CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber768.getName()); k768CipherUnwrap.init(Cipher.UNWRAP_MODE, k768KP.getPrivate());
        k1024CipherWrap = Cipher.getInstance(KyberParameterSpec.kyber1024.getName()); k1024CipherWrap.init(Cipher.WRAP_MODE, k1024KP.getPublic(), new SecureRandom());
        k1024CipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber1024.getName()); k1024CipherUnwrap.init(Cipher.UNWRAP_MODE, k1024KP.getPrivate());
        k512AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber512_aes.getName()); k512AesCipherWrap.init(Cipher.WRAP_MODE, k512AesKP.getPublic(), new SecureRandom());
        k512AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber512_aes.getName()); k512AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k512AesKP.getPrivate());
        k768AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber768_aes.getName()); k768AesCipherWrap.init(Cipher.WRAP_MODE, k768AesKP.getPublic(), new SecureRandom());
        k768AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber768_aes.getName()); k768AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k768AesKP.getPrivate());
        k1024AesCipherWrap = Cipher.getInstance(KyberParameterSpec.kyber1024_aes.getName()); k1024AesCipherWrap.init(Cipher.WRAP_MODE, k1024AesKP.getPublic(), new SecureRandom());
        k1024AesCipherUnwrap = Cipher.getInstance(KyberParameterSpec.kyber1024_aes.getName()); k1024AesCipherUnwrap.init(Cipher.UNWRAP_MODE, k1024AesKP.getPrivate());
        // Getting wrapped bytes from methods.
        k512WB = k512WrapKey(); k768WB = k768WrapKey(); k1024WB = k1024WrapKey();
        k512AesWB = k512AesWrapKey(); k768AesWB = k768AesWrapKey(); k1024AesWB = k1024AesWrapKey();
    }
    // ************************ \\
    // * Section 6: Kyber 512 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair k512KeyGen() {
        return k512KPG.generateKeyPair();
    }

    @Benchmark
    public void k512EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber512.getName());
        keyGen.init(new KEMGenerateSpec(k512KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k512KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k512WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k512CipherWrap.wrap(new SecretKeySpec(k512KB, "AES"));
    }

    @Benchmark
    public static Key k512UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k512CipherUnwrap.unwrap(k512WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************ \\
    // * Section 7: Kyber 768 * \\
    // ************************ \\
    @Benchmark
    public static KeyPair k768KeyGen() {
        return k768KPG.generateKeyPair();
    }

    @Benchmark
    public void k768EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber768.getName());
        keyGen.init(new KEMGenerateSpec(k768KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k768KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k768WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k768CipherWrap.wrap(new SecretKeySpec(k768KB, "AES"));
    }

    @Benchmark
    public static Key k768UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k768CipherUnwrap.unwrap(k768WB, "AES", Cipher.SECRET_KEY);
    }
    // ************************* \\
    // * Section 8: Kyber 1024 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair k1024KeyGen() {
        return k1024KPG.generateKeyPair();
    }

    @Benchmark
    public void k1024EncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber1024.getName());
        keyGen.init(new KEMGenerateSpec(k1024KP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k1024KP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k1024WrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k1024CipherWrap.wrap(new SecretKeySpec(k1024KB, "AES"));
    }

    @Benchmark
    public static Key k1024UnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k1024CipherUnwrap.unwrap(k1024WB, "AES", Cipher.SECRET_KEY);
    }
    // **************************** \\
    // * Section 9: Kyber 512 AES * \\
    // **************************** \\
    @Benchmark
    public static KeyPair k512AesKeyGen() {
        return k512AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k512AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber512_aes.getName());
        keyGen.init(new KEMGenerateSpec(k512AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k512AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k512AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k512AesCipherWrap.wrap(new SecretKeySpec(k512AesKB, "AES"));
    }

    @Benchmark
    public static Key k512AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k512AesCipherUnwrap.unwrap(k512AesWB, "AES", Cipher.SECRET_KEY);
    }
    // ***************************** \\
    // * Section 10: Kyber 768 AES * \\
    // ***************************** \\
    @Benchmark
    public static KeyPair k768AesKeyGen() {
        return k768AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k768AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber768_aes.getName());
        keyGen.init(new KEMGenerateSpec(k768AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k768AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k768AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k768AesCipherWrap.wrap(new SecretKeySpec(k768AesKB, "AES"));
    }

    @Benchmark
    public static Key k768AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k768AesCipherUnwrap.unwrap(k768AesWB, "AES", Cipher.SECRET_KEY);
    }
    // ****************************** \\
    // * Section 11: Kyber 1024 AES * \\
    // ****************************** \\
    @Benchmark
    public static KeyPair k1024AesKeyGen() {
        return k1024AesKPG.generateKeyPair();
    }

    @Benchmark
    public void k1024AesEncapsulatedKeyGen() throws Exception {
        // Generate encoded keys from previously generated key pairs.
        KeyGenerator keyGen = KeyGenerator.getInstance(KyberParameterSpec.kyber1024_aes.getName());
        keyGen.init(new KEMGenerateSpec(k1024AesKP.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation pubEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
        keyGen.init(new KEMExtractSpec(k1024AesKP.getPrivate(), pubEnc.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation privEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    @Benchmark
    public static byte[] k1024AesWrapKey() throws Exception {
        // Wrap the keys (Encrypt the keys with AES)
        return k1024AesCipherWrap.wrap(new SecretKeySpec(k1024AesKB, "AES"));
    }

    @Benchmark
    public static Key k1024AesUnwrapKey() throws Exception {
        // Unwrap the keys (Decrypt the keys with AES)
        return k1024AesCipherUnwrap.unwrap(k1024AesWB, "AES", Cipher.SECRET_KEY);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(Kyber.class.getSimpleName())
                .resultFormat(ResultFormatType.CSV)
                .result("BIKE.csv")
                .build();
        new Runner(opt).run();
    }
}
