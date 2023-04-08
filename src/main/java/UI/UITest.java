package UI;

import Testing.JMHPlotter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class UITest {

    private static final String INITIAL_UI = "initialUI";
    private static final String PAGE_ONE = "pageOne";
    private static final String PAGE_TWO = "pageTwo";

    private static JButton button1;
    private static JButton button2;

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

    private static JPanel createInitialUI() {
        setLookAndFeel();
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        panel.setBackground(new Color(60, 63, 65));

        JLabel label = new JLabel("Please select a benchmarking option:");
        label.setFont(new Font("Arial", Font.BOLD, 16));
        label.setForeground(Color.WHITE);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.insets = new Insets(20, 0, 20, 0);
        panel.add(label, gbc);

        button1 = new JButton("One Algorithm");
        button2 = new JButton("Two Algorithms");

        Font buttonFont = new Font("Arial", Font.PLAIN, 18);
        button1.setFont(buttonFont);
        button2.setFont(buttonFont);

        Dimension buttonSize = new Dimension(175, 50);
        button1.setPreferredSize(buttonSize);
        button2.setPreferredSize(buttonSize);

        Color buttonBgColor = new Color(100, 100, 100);
        Color buttonFgColor = Color.WHITE;
        button1.setBackground(buttonBgColor);
        button1.setForeground(buttonFgColor);
        button2.setBackground(buttonBgColor);
        button2.setForeground(buttonFgColor);

        gbc.gridwidth = 1;
        gbc.gridy = 1;

        gbc.gridx = 0;
        gbc.insets = new Insets(0, 0, 0, 5);
        panel.add(button1, gbc);

        gbc.gridx = 1;
        gbc.insets = new Insets(0, 5, 0, 0);
        panel.add(button2, gbc);

        return panel;
    }

    public static void main(String[] args) throws Exception {
        JFrame frame = new JFrame("Home Page");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 500);

        JPanel navPanel = new JPanel();
        navPanel.setBackground(new Color(50, 50, 50));
        navPanel.setLayout(new FlowLayout(FlowLayout.LEFT));;

        JButton homeButton = new JButton("Home");
        homeButton.setForeground(Color.WHITE);
        homeButton.setBackground(new Color(100, 100, 100));
        homeButton.setFont(new Font("Arial", Font.PLAIN, 14));
        homeButton.setFocusPainted(false);
        navPanel.add(homeButton);

        frame.add(navPanel, BorderLayout.NORTH);

        JPanel cards = new JPanel(new CardLayout());
        frame.add(cards);

        JPanel initialUI = createInitialUI();
        cards.add(initialUI, INITIAL_UI);

        JPanel pageOne = BenchmarkUI.createPageOne();
        cards.add(pageOne, PAGE_ONE);

        //JPanel pageTwo = JMHPlotter.createPageTwo();
        //cards.add(pageTwo, PAGE_TWO);

        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) cards.getLayout();
                cl.show(cards, PAGE_ONE);
            }
        });

        button2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) cards.getLayout();
                cl.show(cards, PAGE_TWO);
            }
        });

        homeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) cards.getLayout();
                cl.show(cards, INITIAL_UI);
            }
        });

        frame.setVisible(true);
    }
}