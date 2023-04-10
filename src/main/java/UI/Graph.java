package UI;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import org.knowm.xchart.*;
import org.knowm.xchart.style.markers.SeriesMarkers;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
// ********************** \\
// * Section 2: Imports * \\
// ********************** \\
public class Graph {
    // ************************ \\
    // * Section 3: Variables * \\
    // ************************ \\
    private static XYChart chart;
    // ************************************ \\
    // * Section 4: Setting customisation * \\
    // ************************************ \\
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
    // * Section 5: Creating the page for main UI * \\
    // ******************************************** \\
    public static JPanel createPageThree() {
        // Call customisation
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(5, 0, 5, 0);
        // Create initial chart
        chart = new XYChartBuilder()
                .width(800)
                .height(600)
                .title("Benchmark Results")
                .xAxisTitle("X Axis")
                .yAxisTitle("Score")
                .build();
        // Create buttons and align to panels
        JButton displayButton = new JButton("Display Graph");
        displayButton.addActionListener(e -> createGraphFrame(chart));
        displayButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(displayButton, gbc);
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.add(displayButton);
        panel.add(buttonPanel, gbc);
        return panel;
    }
    // *********************************** \\
    // * Section 6: Creating graph frame * \\
    // *********************************** \\
    private static void createGraphFrame(XYChart chart) {
        JFrame frame = new JFrame();
        frame.setTitle("JMH Plotter");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        // Update chart panel
        JPanel chartPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                chart.paint(g2, getWidth(), getHeight());
                g2.dispose();
            }
        };
        chartPanel.setPreferredSize(new Dimension(800, 600));
        frame.add(chartPanel, BorderLayout.CENTER);
        // Add buttons to graph and customise
        JButton addButton = new JButton("Add File");
        addButton.addActionListener(e -> addFile(chart, chartPanel));
        JButton saveButton = new JButton("Save Graph");
        saveButton.addActionListener(e -> saveGraph());
        JPanel buttonPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 5, 5, 5);
        buttonPanel.add(addButton, gbc);
        gbc.gridx = 1;
        buttonPanel.add(saveButton, gbc);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
    // *********************************************************** \\
    // * Section 7: Adding button to allow user to select a file * \\
    // *********************************************************** \\
    private static void addFile(XYChart chart, JPanel chartPanel) {
        // Create file choosers
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select a CSV file");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);
        // Filtering based off file extensions
        FileNameExtensionFilter filter = new FileNameExtensionFilter("CSV files", "csv");
        fileChooser.addChoosableFileFilter(filter);
        // Starting location when choosing a file
        String userHome = System.getProperty("user.home");
        File defaultFolder = new File(userHome);
        fileChooser.setCurrentDirectory(defaultFolder);
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            List<Double> xData = new ArrayList<>();
            List<Double> yData = new ArrayList<>();
            // Read the file in
            try (CSVReader reader = new CSVReader(new FileReader(selectedFile))) {
                List<String[]> records = reader.readAll();
                String[] headerRow = records.remove(0);
                // Count column headers to get to the score
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
                // Update chart with 'score' value from file.
                addSeriesToChart(xData, yData, selectedFile.getName(), chart, chartPanel);
            } catch (IOException | CsvException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No file selected.");
        }
    }
    // ************************************************* \\
    // * Section 8: Adding data and updating the chart * \\
    // ************************************************* \\
    private static void addSeriesToChart(List<Double> xData, List<Double> yData, String seriesName, XYChart chart, JPanel chartPanel) {
        XYSeries series = chart.addSeries(seriesName, xData, yData);
        series.setMarker(SeriesMarkers.CIRCLE);
        series.setLineColor(Color.BLUE);
        // Update the chart's container
        chart.getStyler().setPlotContentSize(0.95);
        chart.getStyler().setLegendVisible(true);
        // Update the chart and repaint the panel
        updateChart(chartPanel);
    }
    // *********************************** \\
    // * Section 9: Saving the chart * \\
    // *********************************** \\
    private static void saveGraph() {
        // Create file chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save graph as PNG");
        // Filter file to save as a PNG
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
    // ************************************************************** \\
    // * Section 10: Method to repaint the chart when first loading * \\
    // ************************************************************** \\
    public static void updateChart(JPanel chartPanel) {
        chartPanel.repaint();
    }
}