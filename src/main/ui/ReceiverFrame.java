package ui;

import controller.ReceiverController;
import crypto.AESVariant;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Path;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;

public class ReceiverFrame extends JFrame implements ReceiverController.ReceiverView {
    private static final String[] ALGORITHM_OPTIONS = {"AES-128-CBC", "AES-192-CBC", "AES-256-CBC"};

    private final JTextField encryptedFileField = new JTextField();
    private final JTextField receiveDirectoryField = new JTextField();
    private final JTextField listenPortField = new JTextField("8000");
    private final JPasswordField secretKeyField = new JPasswordField();
    private final JComboBox<String> algorithmCombo = new JComboBox<>(ALGORITHM_OPTIONS);
    private final JLabel keyHintLabel = new JLabel();
    private final JTextArea statusArea = new JTextArea();
    private final JButton browseButton = new JButton("Duyệt");
    private final JButton browseReceiveDirectoryButton = new JButton("Chọn thư mục");
    private final JButton decryptButton = new JButton("Giải mã");
    private final JButton receiveButton = new JButton("Nhận tệp");

    private final ReceiverController controller;
    private Path selectedEncryptedFile;
    private Path selectedReceiveDirectory;

    public ReceiverFrame() {
        controller = new ReceiverController(this);
        initializeFrame();
        initializeActions();
    }

    private void initializeFrame() {
        setTitle("Giải mã tệp");
        setSize(700, 600);
        setMinimumSize(new Dimension(700, 600));
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setContentPane(buildContentPanel());
        getRootPane().setDefaultButton(decryptButton);
    }

    private JPanel buildContentPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout(0, 16));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));
        contentPanel.setBackground(new Color(248, 249, 251));

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setOpaque(false);
        topPanel.add(buildHeaderPanel());
        topPanel.add(Box.createVerticalStrut(16));
        topPanel.add(buildFormPanel());

        contentPanel.add(topPanel, BorderLayout.NORTH);
        contentPanel.add(buildStatusPanel(), BorderLayout.CENTER);

        return contentPanel;
    }

    private JPanel buildHeaderPanel() {
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("Giải mã tệp");
        titleLabel.setAlignmentX(LEFT_ALIGNMENT);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 20));

        JLabel descriptionLabel = new JLabel("Chọn tệp .enc, chọn AES-CBC, nhập khóa ở dạng hex rồi giải mã.");
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
        formPanel.setAlignmentX(LEFT_ALIGNMENT);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(6, 6, 6, 6);
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.gridy = 0;

        encryptedFileField.setEditable(false);
        encryptedFileField.setBackground(Color.WHITE);
        encryptedFileField.setPreferredSize(new Dimension(0, 34));

        receiveDirectoryField.setEditable(false);
        receiveDirectoryField.setBackground(Color.WHITE);
        receiveDirectoryField.setPreferredSize(new Dimension(0, 34));

        secretKeyField.setPreferredSize(new Dimension(0, 34));
        algorithmCombo.setPreferredSize(new Dimension(0, 34));
        listenPortField.setPreferredSize(new Dimension(0, 34));
        keyHintLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        keyHintLabel.setForeground(new Color(85, 85, 85));
        updateKeyHint();

        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 0;
        formPanel.add(new JLabel("Tệp đã mã hóa"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        formPanel.add(encryptedFileField, constraints);

        constraints.gridx = 2;
        constraints.weightx = 0;
        browseButton.setPreferredSize(new Dimension(110, 34));
        formPanel.add(browseButton, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weightx = 0;
        constraints.gridwidth = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(6, 6, 6, 6);
        formPanel.add(new JLabel("Thuật toán"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        constraints.gridwidth = 2;
        formPanel.add(algorithmCombo, constraints);

        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.weightx = 0;
        constraints.gridwidth = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        formPanel.add(new JLabel("Khóa bí mật"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        constraints.gridwidth = 2;
        formPanel.add(secretKeyField, constraints);

        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.gridwidth = 2;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(0, 6, 6, 6);
        formPanel.add(keyHintLabel, constraints);

        constraints.gridx = 1;
        constraints.gridy = 4;
        constraints.gridwidth = 2;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.NONE;
        constraints.anchor = GridBagConstraints.EAST;
        constraints.insets = new Insets(12, 6, 0, 6);
        decryptButton.setPreferredSize(new Dimension(140, 40));
        formPanel.add(decryptButton, constraints);

        receiveDirectoryField.setEditable(false);
        receiveDirectoryField.setBackground(Color.WHITE);
        receiveDirectoryField.setPreferredSize(new Dimension(0, 34));
        listenPortField.setPreferredSize(new Dimension(0, 34));
        listenPortField.setText("8000");

        constraints.gridy = 5;
        constraints.gridx = 0;
        constraints.gridwidth = 1;
        constraints.weightx = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(12, 6, 0, 6);
        formPanel.add(new JLabel("Thư mục nhận"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        formPanel.add(receiveDirectoryField, constraints);

        constraints.gridx = 2;
        constraints.weightx = 0;
        browseReceiveDirectoryButton.setPreferredSize(new Dimension(110, 34));
        formPanel.add(browseReceiveDirectoryButton, constraints);

        constraints.gridy = 6;
        constraints.gridx = 0;
        constraints.weightx = 0;
        formPanel.add(new JLabel("Cổng nghe"), constraints);

        constraints.gridx = 1;
        constraints.weightx = 1;
        formPanel.add(listenPortField, constraints);

        constraints.gridx = 2;
        constraints.weightx = 0;
        receiveButton.setPreferredSize(new Dimension(140, 40));
        formPanel.add(receiveButton, constraints);

        return formPanel;
    }

    private JPanel buildStatusPanel() {
        JPanel statusPanel = new JPanel(new BorderLayout(0, 8));
        statusPanel.setOpaque(false);

        JLabel statusLabel = new JLabel("Trạng thái / Nhật ký");
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
        browseReceiveDirectoryButton.addActionListener(event -> controller.handleChooseReceiveDirectory(this));
        decryptButton.addActionListener(event -> controller.handleDecrypt());
        receiveButton.addActionListener(event -> controller.handleStartReceive());
        algorithmCombo.addActionListener(event -> updateKeyHint());
    }

    @Override
    public Path getSelectedEncryptedFile() {
        return selectedEncryptedFile;
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
    public AESVariant getSelectedVariant() {
        return selectedVariant();
    }

    @Override
    public void setSelectedEncryptedFile(Path encryptedFile) {
        selectedEncryptedFile = encryptedFile;
        encryptedFileField.setText(encryptedFile == null ? "" : encryptedFile.toString());
    }

    @Override
    public Path getSelectedReceiveDirectory() {
        return selectedReceiveDirectory;
    }

    @Override
    public String getListenPort() {
        return listenPortField.getText();
    }

    @Override
    public void setSelectedReceiveDirectory(Path receiveDirectory) {
        selectedReceiveDirectory = receiveDirectory;
        receiveDirectoryField.setText(receiveDirectory == null ? "" : receiveDirectory.toString());
    }

    @Override
    public void showStatus(String message) {
        appendStatus(message);
    }

    @Override
    public void showSuccess(String message) {
        JOptionPane.showMessageDialog(this, message, "Giải mã thành công", JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Lỗi giải mã", JOptionPane.ERROR_MESSAGE);
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

    private void updateKeyHint() {
        AESVariant variant = selectedVariant();
        int hexLength = variant.getKeyLengthBytes() * 2;
        keyHintLabel.setText("Độ dài khóa: " + hexLength + " ký tự hex (" + variant.getKeyLengthBytes() + " byte)");
    }

    private AESVariant selectedVariant() {
        return switch (algorithmCombo.getSelectedIndex()) {
            case 1 -> AESVariant.AES_192;
            case 2 -> AESVariant.AES_256;
            default -> AESVariant.AES_128;
        };
    }
}
