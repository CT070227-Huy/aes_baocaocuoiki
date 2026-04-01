package ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Window;

public class MainFrame extends JFrame {
    private final JButton encryptButton = createActionButton("Mã hóa tệp");
    private final JButton decryptButton = createActionButton("Giải mã tệp");
    private final JButton exitButton = createActionButton("Thoát");

    public MainFrame() {
        initializeFrame();
        initializeActions();
    }

    private void initializeFrame() {
        setTitle("Demo Mã hóa Tệp AES");
        setSize(520, 340);
        setMinimumSize(new Dimension(520, 340));
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setContentPane(buildContentPanel());
    }

    private JPanel buildContentPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout(0, 20));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(24, 24, 24, 24));
        contentPanel.setBackground(new Color(245, 247, 250));

        contentPanel.add(buildHeaderPanel(), BorderLayout.NORTH);
        contentPanel.add(buildButtonPanel(), BorderLayout.CENTER);
        contentPanel.add(buildFooterLabel(), BorderLayout.SOUTH);

        return contentPanel;
    }

    private JPanel buildHeaderPanel() {
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel titleLabel = new JLabel("Demo Mã hóa và Giải mã Tệp AES");
        titleLabel.setAlignmentX(CENTER_ALIGNMENT);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 22));

        JLabel descriptionLabel = new JLabel("Chọn chức năng bên dưới để mã hóa hoặc giải mã tệp.");
        descriptionLabel.setAlignmentX(CENTER_ALIGNMENT);
        descriptionLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));
        descriptionLabel.setForeground(new Color(80, 80, 80));

        headerPanel.add(titleLabel);
        headerPanel.add(Box.createVerticalStrut(10));
        headerPanel.add(descriptionLabel);
        return headerPanel;
    }

    private JPanel buildButtonPanel() {
        JPanel buttonPanel = new JPanel(new GridLayout(3, 1, 0, 12));
        buttonPanel.setOpaque(false);
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(exitButton);
        return buttonPanel;
    }

    private JLabel buildFooterLabel() {
        JLabel footerLabel = new JLabel("Giao diện Java Swing cho mã hóa và giải mã tệp.", SwingConstants.CENTER);
        footerLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        footerLabel.setForeground(new Color(100, 100, 100));
        return footerLabel;
    }

    private void initializeActions() {
        encryptButton.addActionListener(event -> openChildWindow(SenderFrame.class, "Mã hóa tệp"));
        decryptButton.addActionListener(event -> openChildWindow(ReceiverFrame.class, "Giải mã tệp"));
        exitButton.addActionListener(event -> dispose());
    }

    private void openChildWindow(Class<?> windowClass, String fallbackTitle) {
        try {
            Object windowInstance = windowClass.getDeclaredConstructor().newInstance();

            if (windowInstance instanceof Window) {
                Window childWindow = (Window) windowInstance;
                childWindow.setLocationRelativeTo(this);
                childWindow.setVisible(true);
                return;
            }

            showPlaceholderWindow(fallbackTitle, windowClass.getSimpleName());
        } catch (ReflectiveOperationException exception) {
            JOptionPane.showMessageDialog(
                    this,
                    "Không thể mở " + windowClass.getSimpleName() + ".",
                    "Lỗi mở cửa sổ",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void showPlaceholderWindow(String title, String screenName) {
        JFrame placeholderFrame = new JFrame(title);
        placeholderFrame.setSize(420, 220);
        placeholderFrame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        placeholderFrame.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 18));

        JLabel messageLabel = new JLabel(
                "<html><div style='text-align:center;'>"
                        + screenName
                        + " chưa được triển khai thành cửa sổ Swing.<br>"
                        + "Khung tạm này giúp luồng demo từ màn hình chính vẫn hoạt động."
                        + "</div></html>",
                SwingConstants.CENTER
        );

        panel.add(titleLabel, BorderLayout.NORTH);
        panel.add(messageLabel, BorderLayout.CENTER);

        placeholderFrame.setContentPane(panel);
        placeholderFrame.setVisible(true);
    }

    private JButton createActionButton(String text) {
        JButton button = new JButton(text);
        button.setFocusPainted(false);
        button.setFont(new Font("SansSerif", Font.BOLD, 15));
        button.setPreferredSize(new Dimension(0, 52));
        return button;
    }
}
