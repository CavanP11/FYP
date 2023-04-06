package Testing;

import com.opencsv.CSVReader;
import com.opencsv.bean.CsvToBean;
import com.opencsv.bean.CsvToBeanBuilder;
import com.opencsv.bean.HeaderColumnNameMappingStrategy;
import org.knowm.xchart.*;
import org.knowm.xchart.internal.chartpart.Chart;
import org.knowm.xchart.style.Styler;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

public class JMHPlotter {

    private static XChartPanel<CategoryChart> chartPanel;
    
    public static class JMHResult {
        private String benchmark;
        private double score;

        // Getters and setters
        public String getBenchmark() {
            return benchmark;
        }

        public void setBenchmark(String benchmark) {
            this.benchmark = benchmark;
        }

        public double getScore() {
            return score;
        }

        public void setScore(double score) {
            this.score = score;
        }
        public String getShortBenchmarkName() {
            String[] parts = benchmark.split("\\.");
            return parts[parts.length - 1];
        }
    }


    public static List<JMHResult> readJMHCSV(String filePath) throws FileNotFoundException {
        CSVReader csvReader = new CSVReader(new FileReader(filePath));
        HeaderColumnNameMappingStrategy<JMHResult> strategy = new HeaderColumnNameMappingStrategy<>();
        strategy.setType(JMHResult.class);
        CsvToBean<JMHResult> csvToBean = new CsvToBeanBuilder<JMHResult>(csvReader)
                .withType(JMHResult.class)
                .withMappingStrategy(strategy)
                .withIgnoreLeadingWhiteSpace(true)
                .build();
        return csvToBean.parse();
    }

    public static void plotJMHResults(List<List<JMHResult>> resultsList) {
        CategoryChart chart = new CategoryChartBuilder()
                .width(800)
                .height(600)
                .title("JMH Benchmark Results")
                .xAxisTitle("Benchmarks")
                .yAxisTitle("Score (ops/s)")
                .build();

        chart.getStyler().setLegendPosition(Styler.LegendPosition.InsideNW);
        chart.getStyler().setXAxisLabelRotation(45);

        JButton addButton = new JButton("Add A File");
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("CSV files", "csv");
                fileChooser.setFileFilter(csvFilter);

                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        List<JMHResult> newResults = readJMHCSV(selectedFile.getAbsolutePath());
                        resultsList.add(newResults);
                        updateChart(chart, resultsList);
                        chartPanel.revalidate();
                        chartPanel.repaint();
                    } catch (FileNotFoundException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });

        JButton saveButton = new JButton("Save Chart");
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                FileNameExtensionFilter pngFilter = new FileNameExtensionFilter("PNG files", "png");
                fileChooser.setFileFilter(pngFilter);

                int returnValue = fileChooser.showSaveDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        BitmapEncoder.saveBitmap(chart, selectedFile.getAbsolutePath(), BitmapEncoder.BitmapFormat.PNG);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        });

        chartPanel = new XChartPanel<>(chart);
        JFrame frame = new JFrame("JMH Benchmark Results");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(chartPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(addButton);
        buttonPanel.add(saveButton);
        frame.add(buttonPanel, BorderLayout.SOUTH);

        frame.pack();
        frame.setVisible(true);
    }
    public static void updateChart(CategoryChart chart, List<List<JMHResult>> resultsList) {
        chart.removeSeries("Series 1");
        chart.removeSeries("Series 2");
        chart.removeSeries("Series 3");
        // Add more lines if you expect more than three series

        int seriesIndex = 0;
        for (List<JMHResult> results : resultsList) {
            List<String> benchmarkNames = new ArrayList<>();
            List<Double> scores = new ArrayList<>();
            for (JMHResult result : results) {
                benchmarkNames.add(result.getShortBenchmarkName());
                scores.add(result.getScore());
            }
            chart.addSeries("Series " + seriesIndex, benchmarkNames, scores);
        }
        chartPanel.revalidate();
        chartPanel.repaint();
    }
    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    List<List<JMHResult>> resultsList = new ArrayList<>();
                    plotJMHResults(resultsList);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}




