package UI;
// ********************** \\
// * Section 1: Imports * \\
// ********************** \\
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class UI {
    // ************************ \\
    // * Section 2: Variables * \\
    // ************************ \\
    private static final String INITIAL_UI = "initialUI";
    private static final String PAGE_ONE = "pageOne";
    private static final String PAGE_TWO = "pageTwo";
    private static final String PAGE_THREE = "pageThree";
    private static final String PAGE_FOUR = "pageFour";

    private static JButton button1;
    private static JButton button2;
    private static JButton button3;
    // ************************************* \\
    // * Section 3: Creating customisation * \\
    // ************************************* \\
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
    // ******************************* \\
    // * Section 4: Creating main UI * \\
    // ******************************* \\
    private static JPanel createInitialUI() {
        // Creating panel & customisation
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        panel.setBackground(new Color(60, 63, 65));
        // Creating label
        JLabel label = new JLabel("Please select a benchmarking option:");
        label.setFont(new Font("Arial", Font.BOLD, 16));
        label.setForeground(Color.WHITE);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 0, 20, 0);
        panel.add(label, gbc);
        // Creating button options
        button1 = new JButton("One Algorithm");
        button2 = new JButton("Two Algorithms");
        button3 = new JButton("All Algorithms");
        // Customising buttons
        Font buttonFont = new Font("Arial", Font.PLAIN, 18);
        button1.setFont(buttonFont);
        button2.setFont(buttonFont);
        button3.setFont(buttonFont);
        Dimension buttonSize = new Dimension(175, 50);
        button1.setPreferredSize(buttonSize);
        button2.setPreferredSize(buttonSize);
        button3.setPreferredSize(buttonSize);
        Color buttonBgColor = new Color(100, 100, 100);
        Color buttonFgColor = Color.WHITE;
        button1.setBackground(buttonBgColor);
        button1.setForeground(buttonFgColor);
        button2.setBackground(buttonBgColor);
        button2.setForeground(buttonFgColor);
        button3.setBackground(buttonBgColor);
        button3.setForeground(buttonFgColor);
        gbc.gridwidth = 1;
        gbc.gridy = 1;
        gbc.gridx = 0;
        gbc.insets = new Insets(0, 0, 0, 5);
        panel.add(button1, gbc);
        gbc.gridx = 1;
        gbc.insets = new Insets(0, 5, 0, 0);
        panel.add(button2, gbc);
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 0, 0, 0);
        panel.add(button3, gbc);
        return panel;
    }
    // *************************************** \\
    // * Section 5: Creating / calling menus * \\
    // *************************************** \\
    public static void main(String[] args) {
        // Creating home UI
        JFrame frame = new JFrame("Home Page");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 500);
        // Creating navbar
        JPanel navPanel = new JPanel();
        navPanel.setBackground(new Color(50, 50, 50));
        navPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        // Adding home buttom
        JButton homeButton = new JButton("Home");
        homeButton.setForeground(Color.WHITE);
        homeButton.setBackground(new Color(100, 100, 100));
        homeButton.setFont(new Font("Arial", Font.PLAIN, 14));
        homeButton.setFocusPainted(false);
        navPanel.add(homeButton);
        // Graph button
        JButton graphButton = new JButton("Graph Benchmarks");
        graphButton.setForeground(Color.WHITE);
        graphButton.setBackground(new Color(100, 100, 100));
        graphButton.setFont(new Font("Arial", Font.PLAIN, 14));
        graphButton.setFocusPainted(false);
        navPanel.add(graphButton);
        frame.add(navPanel, BorderLayout.NORTH);
        // Creating the "Post-Quantum" dropdown menu
        JMenu postqButton = new JMenu("Post-Quantum");
        postqButton.setForeground(Color.WHITE);
        postqButton.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.setBackground(new Color(100, 100, 100));
        postqButton.setPreferredSize(new Dimension(105, 25));
        // Creating the "Pre-Quantum" dropdown menu
        JMenu preqButton = new JMenu("Pre-Quantum");
        preqButton.setForeground(Color.WHITE);
        preqButton.setFont(new Font("Arial", Font.PLAIN, 14));
        preqButton.setBackground(new Color(100, 100, 100));
        preqButton.setPreferredSize(new Dimension(105, 25));
        // Adding Dilithium to the dropdown menu
        JMenuItem dilithium = new JMenuItem("CRYSTALS-Dilithium");
        dilithium.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.add(dilithium);
        // Adding Kyber to the dropdown menu
        JMenuItem kyber = new JMenuItem("CRYSTALS-Kyber");
        kyber.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.add(kyber);
        // Adding Falcon to the dropdown menu
        JMenuItem falcon = new JMenuItem("Falcon");
        falcon.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.add(falcon);
        // Adding Picnic to the dropdown menu
        JMenuItem picnic = new JMenuItem("Picnic");
        picnic.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.add(picnic);
        // Adding BIKE to the dropdown menu
        JMenuItem bike = new JMenuItem("BIKE");
        bike.setFont(new Font("Arial", Font.PLAIN, 14));
        postqButton.add(bike);
        // Adding SHA256 to the dropdown menu
        JMenuItem sha256 = new JMenuItem("SHA256");
        sha256.setFont(new Font("Arial", Font.PLAIN, 14));
        preqButton.add(sha256);
        // Adding RSA to the dropdown menu
        JMenuItem rsa = new JMenuItem("RSA");
        rsa.setFont(new Font("Arial", Font.PLAIN, 14));
        preqButton.add(rsa);
        // Adding RSA to the dropdown menu
        JMenuItem aesCTR = new JMenuItem("AES-CTR");
        aesCTR.setFont(new Font("Arial", Font.PLAIN, 14));
        preqButton.add(aesCTR);
        // Menubar
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(new Color(100, 100, 100));
        menuBar.add(postqButton);
        menuBar.add(preqButton);
        navPanel.add(menuBar, BorderLayout.WEST);
        // Creating card layouts
        JPanel cards = new JPanel(new CardLayout());
        frame.add(cards);
        // Adding pages to card layouts
        JPanel initialUI = createInitialUI();
        cards.add(initialUI, INITIAL_UI);
        JPanel pageOne = BenchmarkUI.createPageOne();
        cards.add(pageOne, PAGE_ONE);
        JPanel pageTwo = BenchmarkUI.createPageTwo();
        cards.add(pageTwo, PAGE_TWO);
        JPanel pageThree = Graph.createPageThree();
        cards.add(pageThree, PAGE_THREE);
        JPanel pageFour = BenchmarkUI.createPageFour();
        cards.add(pageFour, PAGE_FOUR);
        // Action listeners for buttons
        button1.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, PAGE_TWO);
        });

        button2.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, PAGE_ONE);
        });

        button2.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, PAGE_ONE);
        });

        button3.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, PAGE_FOUR);
        });

        homeButton.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, INITIAL_UI);
        });

        graphButton.addActionListener(e -> {
            CardLayout cl = (CardLayout) cards.getLayout();
            cl.show(cards, PAGE_THREE);
        });

        dilithium.addActionListener(e -> {
            // Redirect to website when "Benchmark Algorithm 1" is selected
            try {
                Desktop.getDesktop().browse(new URI("https://pq-crystals.org/dilithium/"));
            } catch (IOException | URISyntaxException ex) {
                ex.printStackTrace();
            }
        });

        kyber.addActionListener(e -> {
            // Redirect to website when "Benchmark Algorithm 1" is selected
            try {
                Desktop.getDesktop().browse(new URI("https://pq-crystals.org/kyber/"));
            } catch (IOException | URISyntaxException ex) {
                ex.printStackTrace();
            }
        });

        falcon.addActionListener(e -> {
            // Redirect to website when "Benchmark Algorithm 1" is selected
            try {
                Desktop.getDesktop().browse(new URI("https://falcon-sign.info/"));
            } catch (IOException | URISyntaxException ex) {
                ex.printStackTrace();
            }
        });

        picnic.addActionListener(e -> {
            // Redirect to website when "Benchmark Algorithm 1" is selected
            try {
                Desktop.getDesktop().browse(new URI("https://microsoft.github.io/Picnic/"));
            } catch (IOException | URISyntaxException ex) {
                ex.printStackTrace();
            }
        });
        frame.setVisible(true);
    }
}