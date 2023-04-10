package Pre_Quantum;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import java.math.BigInteger;
import java.security.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1)
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class RSA {

    @Param({"1024", "2048", "4096"})
    static int keySize;

    @Param({"117", "245", "501"})
    static int plaintextSize;

    private static AsymmetricCipherKeyPair aKP;
    private byte[] plaintext;
    private RSAEngine encryptEngine;
    private RSAEngine decryptEngine;
    private byte[] signature;
    private byte[] encrypted;

    @Setup
    public void setup() throws Exception {
        // Generating a random plaintext
        SecureRandom random = new SecureRandom();
        plaintext = new byte[plaintextSize];
        random.nextBytes(plaintext);
        // Generate KP for engines
        aKP = generateKey();
        // Getting ready for encryption
        encryptEngine = new RSAEngine(); encryptEngine.init(true, aKP.getPublic());
        decryptEngine = new RSAEngine(); decryptEngine.init(false, aKP.getPrivate());
        // Use these in other methods
        signature = sign(); encrypted = encrypt();
    }

    @Benchmark
    public byte[] encrypt() {
        return encryptEngine.processBlock(plaintext, 0 , plaintext.length);
    }

    @Benchmark
    public byte[] decrypt() {
        return decryptEngine.processBlock(encrypted, 0, encrypted.length);
    }

    @Benchmark
    public AsymmetricCipherKeyPair generateKey() {
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), keySize, 80));
        return kpg.generateKeyPair();
    }

    @Benchmark
    public byte[] sign() throws CryptoException {
        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        signer.init(true, aKP.getPrivate());
        signer.update(plaintext, 0, plaintext.length);
        return signer.generateSignature();
    }

    @Benchmark
    public boolean verify() {
        PSSSigner verifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
        verifier.init(false, aKP.getPublic());
        verifier.update(plaintext, 0, plaintext.length);
        return verifier.verifySignature(signature);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(RSA.class.getSimpleName())
                .resultFormat(ResultFormatType.CSV)
                .result("RSA.csv")
                .build();
        new Runner(opt).run();
    }
}

