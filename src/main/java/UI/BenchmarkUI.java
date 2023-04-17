package UI;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import Post_Quantum.*;
import Pre_Quantum.*;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.profile.WinPerfAsmProfiler;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import javax.swing.*;
import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import java.io.File;

public class BenchmarkUI {
    // *************************************** \\
    // * Section 2: Adding UI customisation. * \\
    // *************************************** \\
    private static void setLookAndFeel() {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
            // Custom dark theme
            UIManager.put("control", new Color(64, 64, 64));
            UIManager.put("info", new Color(64, 64, 64));
            UIManager.put("nimbusAlertYellow", new Color(248, 187, 0));
            UIManager.put("nimbusBase", new Color(18, 30, 49));
            UIManager.put("nimbusDisabledText", new Color(159, 159, 159));
            UIManager.put("nimbusFocus", new Color(115, 164, 209));
            UIManager.put("nimbusGreen", new Color(176, 179, 50));
            UIManager.put("nimbusInfoBlue", new Color(66, 139, 221));
            UIManager.put("nimbusLightBackground", new Color(18, 30, 49));
            UIManager.put("nimbusOrange", new Color(191, 98, 4));
            UIManager.put("nimbusRed", new Color(169, 46, 34));
            UIManager.put("nimbusSelectedText", new Color(255, 255, 255));
            UIManager.put("nimbusSelectionBackground", new Color(104, 93, 156));
            UIManager.put("text", new Color(230, 230, 230));

        } catch (Exception e) {
            System.err.println("Failed to set Look and Feel to Nimbus.");
        }
    }
    // ******************************************** \\
    // * Section 3: Creating the page for main UI * \\
    // ******************************************** \\
    public static JPanel createPageOne() {
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        // Create and position labels
        JLabel label = new JLabel("Algorithm Benchmarking");
        label.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 5, 0);
        panel.add(label, gbc);
        // Create combo boxes to select algorithms
        String[] algorithms = {"CRYSTALS-Kyber", "CRYSTALS-Dilithium", "Falcon", "Picnic", "BIKE", "Sphincs+", "Rainbow", "AES-CTR", "Sha3", "SHA256-EC", "RSA", "TwoFish"};
        JComboBox<String> comboBox1 = new JComboBox<>(algorithms);
        JComboBox<String> comboBox2 = new JComboBox<>(algorithms);
        Dimension preferredSize = new Dimension(200, 30);
        comboBox1.setPreferredSize(preferredSize);
        comboBox2.setPreferredSize(preferredSize);
        JButton runButton = new JButton("Run Benchmarks");
        runButton.setMargin(new Insets(10, 20, 10, 20));
        Font font = new Font("Arial", Font.PLAIN, 16);
        comboBox1.setFont(font);
        comboBox2.setFont(font);
        runButton.setFont(font);
        // Positioning variables
        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.insets = new Insets(0, 0, 0, 5);
        panel.add(comboBox1, gbc);
        gbc.gridx = 1;
        gbc.insets = new Insets(0, 5, 0, 0);
        panel.add(comboBox2, gbc);
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 0, 0);
        panel.add(runButton, gbc);

        // Set up the button event listener
        runButton.addActionListener(e -> {
            String algorithm1 = (String) comboBox1.getSelectedItem();
            String algorithm2 = (String) comboBox2.getSelectedItem();

            System.out.println("Running benchmarks for: " + algorithm1 + " and " + algorithm2);
            // Call the benchmark methods based on the selected algorithms
            JCheckBox stackProfilerCheckBox = new JCheckBox("Include Stack Profiler", false); JCheckBox gcProfilerCheckBox = new JCheckBox("Include GC Profiler", false); JCheckBox asmProfilerCheckBox = new JCheckBox("Include ASM Profiler", false);
            JCheckBox stackProfilerCheckBox2 = new JCheckBox("Include Stack Profiler", false); JCheckBox gcProfilerCheckBox2 = new JCheckBox("Include GC Profiler", false); JCheckBox asmProfilerCheckBox2 = new JCheckBox("Include ASM Profiler", false);
            Object[] message = {
                    "This is for algorithm 1.\n*NB* Make sure you are running as Administrator to use profilers.\nOptional Profiles may increase benchmarking times.",
                    stackProfilerCheckBox,
                    gcProfilerCheckBox,
                    asmProfilerCheckBox
            };
            Object[] message2 = {
                    "This is for algorithm 2.\n*NB* If using ASM, make sure to run as Administrator.\nOptional Profiles may increase benchmarking times.",
                    stackProfilerCheckBox2,
                    gcProfilerCheckBox2,
                    asmProfilerCheckBox2
            };
            Window topLevelWindow = SwingUtilities.windowForComponent(panel);
            JOptionPane.showOptionDialog(
                    topLevelWindow,
                    message,
                    "Confirm",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"OK"},
                    "default"
            );
            JOptionPane.showOptionDialog(
                    topLevelWindow,
                    message2,
                    "Confirm",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"OK"},
                    "default"
            );
            boolean includeStackProfiler = stackProfilerCheckBox.isSelected(); boolean includeGCProfiler = gcProfilerCheckBox.isSelected(); boolean includeASMProfiler = asmProfilerCheckBox.isSelected();
            boolean includeStackProfiler2 = stackProfilerCheckBox2.isSelected(); boolean includeGCProfiler2 = gcProfilerCheckBox2.isSelected(); boolean includeASMProfiler2 = asmProfilerCheckBox2.isSelected();
            // Create 2 option builders for benchmarks options
            OptionsBuilder builder = (OptionsBuilder) new OptionsBuilder()
                    .resultFormat(ResultFormatType.CSV);
            OptionsBuilder builder2 = (OptionsBuilder) new OptionsBuilder()
                    .resultFormat(ResultFormatType.CSV);
            // Check if profilers are created
            if (includeStackProfiler) {
                builder.addProfiler(StackProfiler.class);
            }
            if (includeStackProfiler2) {
                builder2.addProfiler(StackProfiler.class);
            }
            if (includeGCProfiler) {
                builder.addProfiler(GCProfiler.class);
            }
            if (includeGCProfiler2) {
                builder2.addProfiler(GCProfiler.class);
            }
            if (includeASMProfiler) {
                builder.addProfiler(WinPerfAsmProfiler.class);
            }
            if (includeASMProfiler2) {
                builder2.addProfiler(WinPerfAsmProfiler.class);
            }
            // Switch to get options for selected algorithms
            switch (Objects.requireNonNull(algorithm1)) {
                case "Falcon" -> {
                    try {
                        Falcon.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Falcon.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Falcon Benchmarks/Falcon_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Sphincs+" -> {
                    try {
                        SphincsPlus.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(SphincsPlus.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/SphincsPlus Benchmarks/SphincsPlus_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Rainbow" -> {
                    try {
                        Rainbow.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Rainbow.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Rainbow Benchmarks/Rainbow_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "PICNIC" -> {
                    try {
                        Picnic.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Picnic.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Picnic Benchmarks/Picnic_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Dilithium" -> {
                    try {
                        Dilithium.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Dilithium.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Dilithium Benchmarks/Dilithium_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Kyber" -> {
                    try {
                        Kyber.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Kyber.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Kyber Benchmarks/Kyber_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "BIKE" -> {
                    try {
                        BIKE.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(BIKE.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/BIKE Benchmarks/BIKE_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "AES-CTR" -> {
                    try {
                        AES_CTR.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(AES_CTR.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/AES_CTR Benchmarks/AES-CTR_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA256-EC" -> {
                    try {
                        SHA256_ECDSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(SHA256_ECDSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/SHA256-EC Benchmarks/SHA256-EC_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "RSA" -> {
                    try {
                        RSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(RSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/RSA Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA3" -> {
                    try {
                        Sha3.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Sha3.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/Sha3-EC Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "TwoFish" -> {
                    try {
                        TwoFish.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(TwoFish.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/TwoFish Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm1);
            }
            switch (Objects.requireNonNull(algorithm2)) {
                case "Falcon" -> {
                    try {
                        Falcon.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Falcon.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Falcon Benchmarks/Falcon_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Sphincs+" -> {
                    try {
                        SphincsPlus.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(SphincsPlus.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/SphincsPlus Benchmarks/SphincsPlus_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Rainbow" -> {
                    try {
                        Rainbow.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Rainbow.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Rainbow Benchmarks/Rainbow_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "PICNIC" -> {
                    try {
                        Picnic.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Picnic.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Picnic Benchmarks/Picnic_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Dilithium" -> {
                    try {
                        Dilithium.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Dilithium.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Dilithium Benchmarks/Dilithium_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Kyber" -> {
                    try {
                        Kyber.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Kyber.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Kyber Benchmarks/Kyber_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "BIKE" -> {
                    try {
                        BIKE.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(BIKE.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/BIKE Benchmarks/BIKE_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "AES-CTR" -> {
                    try {
                        AES_CTR.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(AES_CTR.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/AES_CTR Benchmarks/AES-CTR_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA256-EC" -> {
                    try {
                        SHA256_ECDSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(SHA256_ECDSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/SHA256-EC Benchmarks/SHA256-EC_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "RSA" -> {
                    try {
                        RSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(RSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/RSA Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA3" -> {
                    try {
                        Sha3.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(Sha3.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/Sha3-EC Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "TwoFish" -> {
                    try {
                        TwoFish.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder2.include(TwoFish.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/TwoFish Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm2);
            }
        });
        return panel;
    }
    // ******************************************** \\
    // * Section 4: Creating the page for main UI * \\
    // ******************************************** \\
    public static JPanel createPageTwo() {
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        // Creating and position labels
        JLabel label = new JLabel("Algorithm Benchmarking");
        label.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 5, 0);
        panel.add(label, gbc);
        // Create combo boxes to select algorithms
        String[] algorithms = {"CRYSTALS-Kyber", "CRYSTALS-Dilithium", "Falcon", "Picnic", "BIKE", "Sphincs+", "Rainbow", "AES-CTR", "Sha3", "SHA256-EC", "RSA", "TwoFish"};
        JComboBox<String> comboBox1 = new JComboBox<>(algorithms);
        Dimension preferredSize = new Dimension(200, 30);
        comboBox1.setPreferredSize(preferredSize);
        JButton runButton = new JButton("Run Benchmarks");
        runButton.setMargin(new Insets(10, 20, 10, 20));
        Font font = new Font("Arial", Font.PLAIN, 16);
        comboBox1.setFont(font);
        runButton.setFont(font);
        // Positioning variables
        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.insets = new Insets(0, 0, 0, 5);
        panel.add(comboBox1, gbc);
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 0, 0);
        panel.add(runButton, gbc);

        // Set up the button event listener
        runButton.addActionListener(e -> {
            String algorithm1 = (String) comboBox1.getSelectedItem();

            System.out.println("Running benchmarks for: " + algorithm1);
            // Call the benchmark methods based on the selected algorithms
            JCheckBox stackProfilerCheckBox = new JCheckBox("Include Stack Profiler", false);
            JCheckBox gcProfilerCheckBox = new JCheckBox("Include GC Profiler", false);
            JCheckBox asmProfilerCheckBox = new JCheckBox("Include ASM Profiler", false);
            Object[] message = {
                    "This is for algorithm 1.\n*NB* Make sure you are running as Administrator to use profilers.\nOptional Profiles may increase benchmarking times.",
                    stackProfilerCheckBox,
                    gcProfilerCheckBox,
                    asmProfilerCheckBox
            };

            Window topLevelWindow = SwingUtilities.windowForComponent(panel);
            JOptionPane.showOptionDialog(
                    topLevelWindow,
                    message,
                    "Confirm",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"OK"},
                    "default"
            );
            boolean includeStackProfiler = stackProfilerCheckBox.isSelected(); boolean includeGCProfiler = gcProfilerCheckBox.isSelected(); boolean includeASMProfiler = asmProfilerCheckBox.isSelected();
            // Creating option builder for benchmark options
            OptionsBuilder builder = (OptionsBuilder) new OptionsBuilder()
                    .resultFormat(ResultFormatType.CSV);
            // Check if profilers are selected
            if (includeStackProfiler) {
                builder.addProfiler(StackProfiler.class);
            }
            if (includeGCProfiler) {
                builder.addProfiler(GCProfiler.class);
            }
            if (includeASMProfiler) {
                builder.addProfiler(WinPerfAsmProfiler.class);
            }
            // Switch to get options for selected algorithms
            switch (Objects.requireNonNull(algorithm1)) {
                case "Falcon" -> {
                    try {
                        Falcon.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Falcon.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Falcon Benchmarks/Falcon_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Sphincs+" -> {
                    try {
                        SphincsPlus.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(SphincsPlus.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/SphincsPlus Benchmarks/SphincsPlus_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Rainbow" -> {
                    try {
                        Rainbow.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Rainbow.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Rainbow Benchmarks/Rainbow_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "PICNIC" -> {
                    try {
                        Picnic.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Picnic.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Picnic Benchmarks/Picnic_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Dilithium" -> {
                    try {
                        Dilithium.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Dilithium.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Dilithium Benchmarks/Dilithium_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Kyber" -> {
                    try {
                        Kyber.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Kyber.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/Kyber Benchmarks/Kyber_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "BIKE" -> {
                    try {
                        BIKE.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(BIKE.class.getSimpleName())
                            .result("Benchmark Results/Post-Quantum/BIKE Benchmarks/BIKE_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "AES-CTR" -> {
                    try {
                        AES_CTR.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(AES_CTR.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/AES_CTR Benchmarks/AES-CTR_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA256-EC" -> {
                    try {
                        SHA256_ECDSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(SHA256_ECDSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/SHA256-EC Benchmarks/SHA256-EC_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "RSA" -> {
                    try {
                        RSA.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(RSA.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/RSA Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "SHA3" -> {
                    try {
                        Sha3.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(Sha3.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/Sha3-EC Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "TwoFish" -> {
                    try {
                        TwoFish.main(new String[0]);
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                    builder.include(TwoFish.class.getSimpleName())
                            .result("Benchmark Results/Pre-Quantum/TwoFish Benchmarks/RSA_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm1);
            }
        });
        return panel;
    }
    public static JPanel createPageFour() {
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        JButton runButton = new JButton("Run Benchmarks");
        runButton.setMargin(new Insets(10, 20, 10, 20));
        Font font = new Font("Arial", Font.PLAIN, 16);
        runButton.setFont(font);
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 0, 0);
        panel.add(runButton, gbc);
        runButton.addActionListener(e -> {
            System.out.println("Running all benchmarks");

            JCheckBox stackProfilerCheckBox = new JCheckBox("Include Stack Profiler", false);
            JCheckBox gcProfilerCheckBox = new JCheckBox("Include GC Profiler", false);
            JCheckBox asmProfilerCheckBox = new JCheckBox("Include ASM Profiler", false);
            Object[] message = {
                    "This is for all algorithms.\n*NB* Make sure you are running as Administrator to use profilers.\nOptional Profiles may increase benchmarking times.",
                    stackProfilerCheckBox,
                    gcProfilerCheckBox,
                    asmProfilerCheckBox
            };

            Window topLevelWindow = SwingUtilities.windowForComponent(panel);
            JOptionPane.showOptionDialog(
                    topLevelWindow,
                    message,
                    "Confirm",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    new String[]{"OK"},
                    "default"
            );

            boolean includeStackProfiler = stackProfilerCheckBox.isSelected();
            boolean includeGCProfiler = gcProfilerCheckBox.isSelected();
            boolean includeASMProfiler = asmProfilerCheckBox.isSelected();


            String[] algorithms = {"Falcon", "PICNIC", "Dilithium", "Kyber", "BIKE", "SphincsPlus", "Rainbow", "AES", "SHA256", "RSA", "SHA3", "TwoFish"};

            // Add the fully qualified class names here, replace "your_package_name" with the actual package name
            String[] classNames = {
                    "Post_Quantum.Falcon",
                    "Post_Quantum.Picnic",
                    "Post_Quantum.Dilithium",
                    "Post_Quantum.Kyber",
                    "Post_Quantum.BIKE",
                    "Post_Quantum.SphincsPlus",
                    "Post_Quantum.Rainbow",
                    "Pre_Quantum.AES_CTR",
                    "Pre_Quantum.SHA256_ECDSA",
                    "Pre_Quantum.RSA",
                    "Pre_Quantum.Sha3",
                    "Pre_Quantum.TwoFish"
            };

            String[] resultFiles = {
                    "Falcon_Benchmarks.csv",
                    "Picnic_Benchmarks.csv",
                    "Dilithium_Benchmarks.csv",
                    "Kyber_Benchmarks.csv",
                    "BIKE_Benchmarks.csv",
                    "SphincsPlus_Benchmarks.csv",
                    "Rainbow_Benchmarks.csv",
                    "AES-CTR_Benchmarks.csv",
                    "SHA256-EC_Benchmarks.csv",
                    "RSA_Benchmarks.csv",
                    "SHA3_Benchmarks.csv",
                    "TwoFish_Benchmarks.csv",
            };

            File benchmarkResultsDirectory = new File("Benchmark Results");
            if (!benchmarkResultsDirectory.exists()) {
                if (!benchmarkResultsDirectory.mkdirs()) {
                    System.err.println("Unable to create Benchmark Results directory.");
                }
            }

            for (int i = 0; i < algorithms.length; i++) {
                System.out.println("Running benchmarks for: " + algorithms[i]);
                String className = classNames[i];
                String resultFile = resultFiles[i];
                String subFolder = algorithms[i].contains("-") ? algorithms[i].substring(0, algorithms[i].indexOf("-")) : algorithms[i];
                File algorithmDirectory = new File(new File(benchmarkResultsDirectory, (i < 7 ? "Post-Quantum" : "Pre-Quantum")), subFolder + " Benchmarks");
                if (!algorithmDirectory.exists()) {
                    if (!algorithmDirectory.mkdirs()) {
                        System.err.println("Unable to create " + algorithmDirectory.getPath() + " directory.");
                    }
                }

                // Create a new OptionsBuilder for each benchmark
                OptionsBuilder builder = (OptionsBuilder) new OptionsBuilder()
                        .resultFormat(ResultFormatType.CSV);

                // Check if profilers are selected
                if (includeStackProfiler) {
                    builder.addProfiler(StackProfiler.class);
                }
                if (includeGCProfiler) {
                    builder.addProfiler(GCProfiler.class);
                }
                if (includeASMProfiler) {
                    builder.addProfiler(WinPerfAsmProfiler.class);
                }

                // Call main method of the benchmark class
                try {
                    Class<?> clazz = Class.forName(className);
                    Method mainMethod = clazz.getMethod("main", String[].class);
                    String[] mainArgs = new String[0];
                    mainMethod.invoke(null, (Object) mainArgs);
                } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
                    ex.printStackTrace();
                }

                builder.include(className)
                        .result("Benchmark Results/" + (i < 5 ? "Post-Quantum/" : "Pre-Quantum/") + subFolder + " Benchmarks/" + resultFile);
                Options options = builder.build();
                try {
                    new Runner(options).run();
                } catch (RunnerException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        return panel;
    }
}