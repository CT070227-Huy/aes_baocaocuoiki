package ui;

import controller.SenderController;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;

public class SenderFrame extends JFrame implements SenderController.SenderView {
    private final JTextField inputFileField = new JTextField();
    private final JPasswordField secretKeyField = new JPasswordField();
    private final JTextArea statusArea = new JTextArea();
    private final JButton browseButton = new JButton("Browse");
    private final JButton encryptButton = new JButton("Encrypt");

    private final SenderController controller;
    private Path selectedInputFile;

    public SenderFrame() {
        controller = new SenderController(this);
        initializeFrame();
        initializeActions();
    }

    private void initializeFrame() {
        setTitle("Encrypt File");
        setSize(640, 420);
        setMinimumSize(new Dimension(640, 420));
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setContentPane(buildContentPanel());
        getRootPane().setDefaultButton(encryptButton);
    }

    private JPanel buildContentPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout(0, 16));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));
        contentPanel.setBackground(new Color(248, 249, 251));

        contentPanel.add(buildHeaderPanel(), BorderLayout.NORTH);
        contentPanel.add(buildFormPanel(), BorderLayout.CENTER);
        contentPanel.add(buildStatusPanel(), BorderLayout.SOUTH);

        return contentPanel;
    }

    private JPanel buildHeaderPanel() {
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("File Encryption");
        titleLabel.setAlignmentX(LEFT_ALIGNMENT);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 20));

        JLabel descriptionLabel = new JLabel("Choose a file, enter a 16-byte AES key, then encrypt.");
        descriptionLabel.setAlignmentX(LEFT_ALIGNMENT);
        descriptionLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));
        descriptionLabel.setForeground(new Color(85, 85, 85));

        headerPanel.add(titleLabel);
        headerPanel.add(Box.createVerticalStrut(6));
        headerPanel.add(descriptionLabel);
        return headerPanel;
    }

    private JPanel buildFormPanel() {
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setOpaque(false);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(6, 6, 6, 6);
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;

        inputFileField.setEditable(false);
        inputFileField.setBackground(Color.WHITE);
        inputFileField.setPreferredSize(new Dimension(0, 34));

        secretKeyField.setPreferredSize(new Dimension(0, 34));

        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 0;
        formPanel.add(new JLabel("Source File"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        formPanel.add(inputFileField, constraints);

        constraints.gridx = 2;
        constraints.weightx = 0;
        browseButton.setPreferredSize(new Dimension(110, 34));
        formPanel.add(browseButton, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weightx = 0;
        formPanel.add(new JLabel("Secret Key"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        constraints.gridwidth = 2;
        formPanel.add(secretKeyField, constraints);

        constraints.gridx = 1;
        constraints.gridy = 2;
        constraints.gridwidth = 2;
        constraints.weightx = 0;
        constraints.anchor = GridBagConstraints.EAST;
        encryptButton.setPreferredSize(new Dimension(140, 38));
        formPanel.add(encryptButton, constraints);

        return formPanel;
    }

    private JPanel buildStatusPanel() {
        JPanel statusPanel = new JPanel(new BorderLayout(0, 8));
        statusPanel.setOpaque(false);

        JLabel statusLabel = new JLabel("Status / Log");
        statusLabel.setFont(new Font("SansSerif", Font.BOLD, 13));

        statusArea.setEditable(false);
        statusArea.setLineWrap(true);
        statusArea.setWrapStyleWord(true);
        statusArea.setRows(8);
        statusArea.setBackground(Color.WHITE);
        statusArea.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JScrollPane scrollPane = new JScrollPane(statusArea);
        scrollPane.setPreferredSize(new Dimension(0, 170));

        statusPanel.add(statusLabel, BorderLayout.NORTH);
        statusPanel.add(scrollPane, BorderLayout.CENTER);
        return statusPanel;
    }

    private void initializeActions() {
        browseButton.addActionListener(event -> controller.handleChooseFile(this));
        encryptButton.addActionListener(event -> controller.handleEncrypt());
    }

    @Override
    public Path getSelectedInputFile() {
        return selectedInputFile;
    }

    @Override
    public Path getOutputFile() {
        return null;
    }

    @Override
    public String getSecretKey() {
        return new String(secretKeyField.getPassword());
    }

    @Override
    public void setSelectedInputFile(Path inputFile) {
        selectedInputFile = inputFile;
        inputFileField.setText(inputFile == null ? "" : inputFile.toString());
    }

    @Override
    public void showStatus(String message) {
        appendStatus(message);
    }

    @Override
    public void showSuccess(String message) {
        JOptionPane.showMessageDialog(this, message, "Encryption Success", JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Encryption Error", JOptionPane.ERROR_MESSAGE);
    }

    private void appendStatus(String message) {
        if (message == null || message.isBlank()) {
            return;
        }

        if (!statusArea.getText().isEmpty()) {
            statusArea.append(System.lineSeparator());
        }

        statusArea.append(message);
        statusArea.setCaretPosition(statusArea.getDocument().getLength());
    }
}
