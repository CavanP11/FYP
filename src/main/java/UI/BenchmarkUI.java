package UI;

import Post_Quantum.Dilithium;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.Falcon;
import org.bouncycastle.pqc.jcajce.provider.Picnic;
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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.Security;

public class BenchmarkUI {
    private JFrame frame;
    private JComboBox<String> comboBox1;
    private JComboBox<String> comboBox2;

    public BenchmarkUI() {
        initialize();
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastlePQCProvider());
        EventQueue.invokeLater(() -> {
            try {
                BenchmarkUI window = new BenchmarkUI();
                window.frame.setVisible(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void initialize() {
        // Set up the UI components
        frame = new JFrame("Algorithm Benchmarking");
        frame.setBounds(100, 100, 400, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(new FlowLayout());

        comboBox1 = new JComboBox<>();
        comboBox2 = new JComboBox<>();
        JButton runButton = new JButton("Run Benchmarks");

        frame.getContentPane().add(comboBox1);
        frame.getContentPane().add(comboBox2);
        frame.getContentPane().add(runButton);

        // Add available algorithms to the combo boxes
        String[] algorithms = {"Falcon", "Picnic", "CRYSTALS-Kyber", "CRYSTALS-Dilithium"};
        for (String algorithm : algorithms) {
            comboBox1.addItem(algorithm);
            comboBox2.addItem(algorithm);
        }

        // Set up the button event listener
        runButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedAlgorithm1 = (String) comboBox1.getSelectedItem();
                String selectedAlgorithm2 = (String) comboBox2.getSelectedItem();
                try {
                    assert selectedAlgorithm1 != null;
                    runBenchmarks(selectedAlgorithm1, selectedAlgorithm2);
                } catch (RunnerException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
    }

    private void runBenchmarks(String algorithm1, String algorithm2) throws RunnerException {
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
        int result = JOptionPane.showOptionDialog(
                frame,
                message,
                "Confirm",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                new String[]{"OK"},
                "default"
        );
        int result2 = JOptionPane.showOptionDialog(
                frame,
                message2,
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
        boolean includeStackProfiler2 = stackProfilerCheckBox2.isSelected();
        boolean includeGCProfiler2 = gcProfilerCheckBox2.isSelected();
        boolean includeASMProfiler2 = asmProfilerCheckBox2.isSelected();

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
                        .result("Falcon_Benchmarks.cvs");
                Options options = builder.build();
                new Runner(options).run();
                break;
            }
            case "Picnic" -> {
                builder.include(Picnic.class.getSimpleName())
                        .result("Picnic_Benchmarks.cvs");
                Options options = builder.build();
                new Runner(options).run();
                break;
            }
            case "CRYSTALS-Dilithium" -> {
                builder.include(Dilithium.class.getSimpleName())
                        .result("Dilithium_Benchmarks.cvs");
                Options options = builder.build();
                new Runner(options).run();
                break;
            }
            /* case "CRYSTALS-Kyber" -> {
                builder.include(Kyber.class.getSimpleName())
                        .result("Kyber_Benchmarks.cvs");
                break;
            } */
            default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm1);
        }
        switch (algorithm2) {
            case "Falcon" -> {
                builder.include(Falcon.class.getSimpleName())
                        .result("Falcon_Benchmarks.cvs");
                Options options = builder2.build();
                new Runner(options).run();
                break;
            }
            case "Picnic" -> {
                builder.include(Picnic.class.getSimpleName())
                        .result("Picnic_Benchmarks.cvs");
                Options options = builder2.build();
                new Runner(options).run();
                break;
            }
            case "CRYSTALS-Dilithium" -> {
                builder.include(Dilithium.class.getSimpleName())
                        .result("Dilithium_Benchmarks.cvs");
                Options options = builder2.build();
                new Runner(options).run();
                break;
            }
            /* case "CRYSTALS-Kyber" -> {
                builder.include(Kyber.class.getSimpleName())
                        .result("Kyber_Benchmarks.cvs");
                break;
            } */
            default -> throw new IllegalArgumentException("Invalid algorithm selected: " + algorithm2);
        }
    }
}
