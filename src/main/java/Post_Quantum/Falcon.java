package Post_Quantum;
// **********************
// * Section 1: Imports *
// **********************
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
// ********************************** \\
// * Section 2: Benchmark Variables * \\
// ********************************** \\
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 1, time = 1 )
@Measurement(iterations = 1, time = 1)
@Threads(value=Threads.MAX)
@Fork(1)
@State(Scope.Benchmark)
public class Falcon {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static KeyPairGenerator f512KPG; private static KeyPairGenerator f1024KPG;

    private KeyPair falcon512KP; private KeyPair falcon1024KP;

    private static Signature f512Sig; private static Signature f1024Sig;

    private static byte[] falcon512Signature; private static byte[] falcon1024Signature;

    private static byte[] plaintext;
    // ************************* \\
    // * Section 4: Parameters * \\
    // ************************* \\
    @Param({"256", "512", "1024", "2048"})
    static int plaintextSize;
    // ************************ \\
    // * Section 5: Setup     * \\
    // ************************ \\
    @Setup
    public void setup() throws Exception {
        // Setting up starting variables
        Security.addProvider(new BouncyCastlePQCProvider());
        plaintext = new byte[plaintextSize];
        SecureRandom random = new SecureRandom();
        // Creating KGPs for KPs
        f512KPG = KeyPairGenerator.getInstance("Falcon"); f512KPG.initialize(FalconParameterSpec.falcon_512, new SecureRandom());
        f1024KPG = KeyPairGenerator.getInstance("Falcon"); f1024KPG.initialize(FalconParameterSpec.falcon_1024, new SecureRandom());
        // Creating KPs
        falcon512KP = falcon512KeyGeneration(); falcon1024KP = falcon1024KeyGeneration();
        // Creating Sig instances
        f512Sig = Signature.getInstance("Falcon-512"); f1024Sig = Signature.getInstance("Falcon-1024");
        // Using variables to call KPG class to go into verify() without impacting benchmarks
        falcon512Signature = falcon512Sign(); falcon1024Signature = falcon1024Sign();
    }
    // ************************* \\
    // * Section 6: Falcon 512 * \\
    // ************************* \\
    @Benchmark
    public static KeyPair falcon512KeyGeneration() throws Exception {
        return f512KPG.generateKeyPair();
    }

    @Benchmark
    public byte[] falcon512Sign() throws Exception {
        f512Sig.initSign(falcon512KP.getPrivate(), new SecureRandom());
        f512Sig.update(plaintext, 0, plaintext.length);
        return f512Sig.sign();
    }

    @Benchmark
    public boolean falcon512Verify() throws Exception {
        f512Sig.initVerify(falcon512KP.getPublic());
        f512Sig.update(plaintext, 0, plaintext.length);
        return f512Sig.verify(falcon512Signature);
    }
    // ************************** \\
    // * Section 7: Falcon 1024 * \\
    // ************************** \\
    @Benchmark
    public static KeyPair falcon1024KeyGeneration() throws Exception {
        return f1024KPG.generateKeyPair();
    }

    @Benchmark
    public byte[] falcon1024Sign() throws Exception {
        f1024Sig.initSign(falcon1024KP.getPrivate(), new SecureRandom());
        f1024Sig.update(plaintext, 0, plaintext.length);
        return f1024Sig.sign();
    }

    @Benchmark
    public boolean falcon1024Verify() throws Exception {
        f1024Sig.initVerify(falcon1024KP.getPublic());
        f1024Sig.update(plaintext, 0, plaintext.length);
        return f1024Sig.verify(falcon1024Signature);
    }
    // ************************************************************* \\
    // * Section 8: Printing Out Keys, Signatures and Verification * \\
    // ************************************************************* \\
    public static byte[] falconSign(KeyPair kp, byte[] plaintext, Signature signature) throws Exception {
        signature.initSign(kp.getPrivate(), new SecureRandom());
        signature.update(plaintext, 0, plaintext.length);
        return signature.sign();
    }

    public static boolean falconVerify(KeyPair kp, byte[] sig, byte[] plaintext, Signature signature) throws Exception {
        signature.initVerify(kp.getPublic());
        signature.update(plaintext, 0, plaintext.length);
        return signature.verify(sig);
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

    private static String getKeysAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return "Public Key:\n " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n\n" +
                "Private Key:\n " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n\n";
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
        String foldersPath = "Benchmark Results/Falcon Benchmarks/";
        String f512filePath = getFilePath(foldersPath, "Falcon512_Keys.txt"); String f512SigFilePath = getFilePath(foldersPath, "Falcon512_Signatures.txt"); String f512VerifyFilePath = getFilePath(foldersPath, "Falcon512_Verification.txt");
        String f1024filePath = getFilePath(foldersPath, "Falcon1024_Keys.txt"); String f1024SigFilePath = getFilePath(foldersPath, "Falcon1024_Signatures.txt"); String f1024VerifyFilePath = getFilePath(foldersPath, "Falcon1024_Verification.txt");
        byte[] plaintext = new byte[2048];

        for (int i = 0; i < 3; i++) {
            // Creating signatures
            Signature f512SigInit = Signature.getInstance("Falcon-512"); Signature f1024SigInit = Signature.getInstance("Falcon-1024");
            KeyPairGenerator f512KPG = KeyPairGenerator.getInstance("Falcon"); f512KPG.initialize(FalconParameterSpec.falcon_512, new SecureRandom());
            KeyPairGenerator f1024KPG = KeyPairGenerator.getInstance("Falcon"); f1024KPG.initialize(FalconParameterSpec.falcon_1024, new SecureRandom());
            // Creating key pairs
            KeyPair f512KP = f512KPG.generateKeyPair(); KeyPair f1024KP = f1024KPG.generateKeyPair();
            String f512keysString = getKeysAsString(f512KP); String f1024keysString = getKeysAsString(f1024KP);
            saveDataToFile(f512keysString, f512filePath);  saveDataToFile(f1024keysString, f1024filePath);
            // Creating signature instances
            byte[] f512Sig = falconSign(f512KP, plaintext, f512SigInit); byte[] f1024Sig = falconSign(f1024KP, plaintext, f1024SigInit);
            String f512DecodedSignature = decodeSignature(f512Sig); String f1024DecodedSignature = decodeSignature(f1024Sig);
            saveDataToFile(f512DecodedSignature, f512SigFilePath); saveDataToFile(f1024DecodedSignature, f1024SigFilePath);
            // Verifying signatures
            Boolean f512Verify = falconVerify(f512KP, f512Sig, plaintext, f512SigInit); Boolean f1024Verify = falconVerify(f1024KP, f1024Sig, plaintext, f1024SigInit);
            saveVerificationResult(f512Verify, f512VerifyFilePath); saveVerificationResult(f1024Verify, f1024VerifyFilePath);
        }
    }
}