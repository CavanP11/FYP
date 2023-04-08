package UI;

import Post_Quantum.Dilithium;
import Post_Quantum.Falcon;
import Post_Quantum.Picnic;
import Testing.Kyber;
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

public class BenchmarkUI {
    private JComboBox<String> comboBox1;
    private JComboBox<String> comboBox2;

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

    public static JPanel createPageOne() {
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        JLabel label = new JLabel("Algorithm Benchmarking");
        label.setFont(new Font("Arial", Font.BOLD, 16));
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 5, 0);
        panel.add(label, gbc);

        String[] algorithms = {"Falcon", "Picnic", "CRYSTALS-Kyber", "CRYSTALS-Dilithium"};
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
            // Call the appropriate benchmark methods based on the selected algorithms
            JCheckBox stackProfilerCheckBox = new JCheckBox("Include Stack Profiler", false);
            JCheckBox gcProfilerCheckBox = new JCheckBox("Include GC Profiler", false);
            JCheckBox asmProfilerCheckBox = new JCheckBox("Include ASM Profiler", false);
            JCheckBox stackProfilerCheckBox2 = new JCheckBox("Include Stack Profiler", false);
            JCheckBox gcProfilerCheckBox2 = new JCheckBox("Include GC Profiler", false);
            JCheckBox asmProfilerCheckBox2 = new JCheckBox("Include ASM Profiler", false);
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

            OptionsBuilder builder = (OptionsBuilder) new OptionsBuilder()
                    .resultFormat(ResultFormatType.CSV);
            OptionsBuilder builder2 = (OptionsBuilder) new OptionsBuilder()
                    .resultFormat(ResultFormatType.CSV);

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
            switch (algorithm1) {
                case "Falcon" -> {
                    builder.include(Falcon.class.getSimpleName())
                            .result("Falcon_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Picnic" -> {
                    builder.include(Picnic.class.getSimpleName())
                            .result("Picnic_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Dilithium" -> {
                    builder.include(Dilithium.class.getSimpleName())
                            .result("Dilithium_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Kyber" -> {
                    builder.include(Kyber.class.getSimpleName())
                            .result("Kyber_Benchmarks.csv");
                    Options options = builder.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm1);
            }
            switch (algorithm2) {
                case "Falcon" -> {
                    builder2.include(Falcon.class.getSimpleName())
                            .result("Falcon_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "Picnic" -> {
                    builder2.include(Picnic.class.getSimpleName())
                            .result("Picnic_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Dilithium" -> {
                    builder2.include(Dilithium.class.getSimpleName())
                            .result("Dilithium_Benchmarks.csv");
                    Options options = builder2.build();
                    try {
                        new Runner(options).run();
                    } catch (RunnerException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                case "CRYSTALS-Kyber" -> {
                    builder2.include(Kyber.class.getSimpleName())
                            .result("Kyber_Benchmarks.csv");
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

}
