package Testing;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import org.knowm.xchart.*;
import org.knowm.xchart.style.markers.SeriesMarkers;


import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JMHPlotter {

    private static XYChart chart;

    public static void main(String[] args) {
        chart = new XYChartBuilder()
                .width(800)
                .height(600)
                .title("Benchmark Results")
                .xAxisTitle("X Axis")
                .yAxisTitle("Score")
                .build();

        SwingWrapper<XYChart> swingWrapper = new SwingWrapper<>(chart);
        final JFrame frame = swingWrapper.displayChart();

        JButton addButton = new JButton(new AbstractAction("Add File") {
            @Override
            public void actionPerformed(ActionEvent e) {
                addFile(frame);
            }
        });
        addButton.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton saveButton = new JButton(new AbstractAction("Save Graph") {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveGraph();
            }
        });
        saveButton.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.add(addButton);
        buttonPanel.add(saveButton);

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(buttonPanel, BorderLayout.NORTH);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static void addFile(JFrame frame) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select a CSV file");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("CSV files", "csv");
        fileChooser.addChoosableFileFilter(filter);
        // Set the default starting folder
        String userHome = System.getProperty("user.home");
        File defaultFolder = new File(userHome);
        fileChooser.setCurrentDirectory(defaultFolder);

        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            List<Double> xData = new ArrayList<>();
            List<Double> yData = new ArrayList<>();

            try (CSVReader reader = new CSVReader(new FileReader(selectedFile))) {
                List<String[]> records = reader.readAll();
                String[] headerRow = records.remove(0);

                int scoreColumnIndex = -1;
                for (int i = 0; i < headerRow.length; i++) {
                    if (headerRow[i].equalsIgnoreCase("score")) {
                        scoreColumnIndex = i;
                        break;
                    }
                }

                if (scoreColumnIndex != -1) {
                    int rowIndex = 1;
                    for (String[] record : records) {
                        xData.add((double) rowIndex);
                        yData.add(Double.parseDouble(record[scoreColumnIndex]));
                        rowIndex++;
                    }
                } else {
                    System.err.println("Score column not found.");
                }
                addSeriesToChart(xData, yData, selectedFile.getName(), frame);
            } catch (IOException | CsvException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No file selected.");
        }
    }

    private static void addSeriesToChart(List<Double> xData, List<Double> yData, String seriesName, JFrame frame) {
        XYSeries series = chart.addSeries(seriesName, xData, yData);
        series.setMarker(SeriesMarkers.CIRCLE);
        series.setLineColor(Color.BLUE);

        // Update the chart's container
        frame.revalidate();
        frame.repaint();
    }

    private static void saveGraph() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save graph as PNG");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("PNG Images", "png");
        fileChooser.addChoosableFileFilter(filter);
        fileChooser.setFileFilter(filter);
        fileChooser.setAcceptAllFileFilterUsed(false);

        int returnValue = fileChooser.showSaveDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File outputFile = fileChooser.getSelectedFile();
            if (!outputFile.getName().toLowerCase().endsWith(".png")) {
                outputFile = new File(outputFile.getParentFile(), outputFile.getName() + ".png");
            }

            try {
                BitmapEncoder.saveBitmap(chart, outputFile.getAbsolutePath(), BitmapEncoder.BitmapFormat.PNG);
                System.out.println("Graph saved successfully.");
            } catch (IOException e) {
                System.err.println("Failed to save graph.");
                e.printStackTrace();
            }
        } else {
            System.out.println("Save operation cancelled.");
        }
    }
}