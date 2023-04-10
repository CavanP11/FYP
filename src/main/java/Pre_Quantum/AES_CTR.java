package Pre_Quantum;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import java.security.SecureRandom;
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
public class AES_CTR {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static byte[] iv;

    private static BufferedBlockCipher encryptCipher;
    private static BufferedBlockCipher decryptCipher;

    private static int encryptOutputLength; private static int decryptOutputLength;
    private static byte[] encryptOutput; private static byte[] decryptOutput;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"128", "192", "256"})
    static int keySize;

    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;
    // ************************ \\
    // * Section 5: Setup     * \\
    // ************************ \\
    @Setup
    public void setup() throws Exception {
        byte[] key = keyGeneration();
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[plaintextSize];
        random.nextBytes(plaintext);

        byte[] iv = new byte[16]; // 128-bit
        random.nextBytes(iv);

        CipherParameters cipherParams = new ParametersWithIV(new KeyParameter(key), iv);
        AESEngine aesEngine = new AESEngine();
        SICBlockCipher ctrAESEngine = new SICBlockCipher(aesEngine);
        encryptCipher = new BufferedBlockCipher(ctrAESEngine);
        encryptCipher.init(true, cipherParams);

        decryptCipher = new BufferedBlockCipher(ctrAESEngine);
        decryptCipher.init(false, cipherParams);

        encryptOutput = new byte[encryptCipher.getOutputSize(plaintext.length)];
        encryptOutputLength = encryptCipher.processBytes(plaintext, 0, plaintext.length, encryptOutput, 0);

        byte[] ciphertext = encryption();

        decryptOutput = new byte[decryptCipher.getOutputSize(ciphertext.length)];
        decryptOutputLength = decryptCipher.processBytes(ciphertext, 0, ciphertext.length, decryptOutput, 0);


    }
    // ************************** \\
    // * Section 6: AES CTR     * \\
    // ************************** \\
    @Benchmark
    public static byte[] keyGeneration() {
        KeyGenerationParameters kgp = new KeyGenerationParameters(new SecureRandom(), keySize);
        CipherKeyGenerator ckg = new CipherKeyGenerator();
        ckg.init(kgp);
        return ckg.generateKey();
    }

    @Benchmark
    public byte[] encryption() throws Exception {
        encryptCipher.doFinal(encryptOutput, encryptOutputLength);
        return encryptOutput;
    }

    @Benchmark
    public byte[] decryption() throws Exception {
        decryptCipher.doFinal(decryptOutput, decryptOutputLength);
        return decryptOutput;
    }
}
