package controller;

import crypto.AESVariant;
import exception.InvalidKeyException;
import file.FileDecryptService;
import java.awt.Component;
import java.nio.file.Path;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import model.DecryptionRequest;
import model.OperationResult;
import network.FileTransferServer;
import util.ValidationUtils;

public class ReceiverController {
    private final ReceiverView view;
    private final FileDecryptService fileDecryptService;
    private final FileTransferServer fileTransferServer;

    public ReceiverController(ReceiverView view) {
        this(view, new FileDecryptService(), new FileTransferServer());
    }

    public ReceiverController(ReceiverView view, FileDecryptService fileDecryptService, FileTransferServer fileTransferServer) {
        if (view == null) {
            throw new IllegalArgumentException("Giao diện nhận không được để trống.");
        }

        if (fileDecryptService == null) {
            throw new IllegalArgumentException("Dịch vụ giải mã tệp không được để trống.");
        }

        if (fileTransferServer == null) {
            throw new IllegalArgumentException("Dịch vụ nhận tệp không được để trống.");
        }

        this.view = view;
        this.fileDecryptService = fileDecryptService;
        this.fileTransferServer = fileTransferServer;
    }

    public void handleChooseFile(Component parentComponent) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setFileFilter(new FileNameExtensionFilter("Tệp mã hóa (*.enc)", "enc"));

        int selectionResult = fileChooser.showOpenDialog(parentComponent);
        if (selectionResult != JFileChooser.APPROVE_OPTION || fileChooser.getSelectedFile() == null) {
            return;
        }

        Path selectedFile = fileChooser.getSelectedFile().toPath().toAbsolutePath().normalize();
        view.setSelectedEncryptedFile(selectedFile);
        view.showStatus("Đã chọn tệp mã hóa: " + selectedFile.getFileName());
    }

    public void handleChooseReceiveDirectory(Component parentComponent) {
        JFileChooser directoryChooser = new JFileChooser();
        directoryChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int selectionResult = directoryChooser.showOpenDialog(parentComponent);
        if (selectionResult != JFileChooser.APPROVE_OPTION || directoryChooser.getSelectedFile() == null) {
            return;
        }

        Path selectedDirectory = directoryChooser.getSelectedFile().toPath().toAbsolutePath().normalize();
        view.setSelectedReceiveDirectory(selectedDirectory);
        view.showStatus("Đã chọn thư mục nhận: " + selectedDirectory);
    }

    public void handleStartReceive() {
        try {
            Path receiveDirectory = view.getSelectedReceiveDirectory();
            if (receiveDirectory == null) {
                throw new IllegalArgumentException("Vui lòng chọn thư mục nhận trước khi bắt đầu.");
            }

            int port = parsePort(view.getListenPort());
            if (port <= 0) {
                throw new IllegalArgumentException("Cổng phải là một số hợp lệ từ 1 đến 65535.");
            }

            view.showStatus("Đang chờ kết nối trên cổng " + port + "...");
            new Thread(() -> {
                OperationResult result = fileTransferServer.listenForSingleFile(port, receiveDirectory);
                SwingUtilities.invokeLater(() -> updateView(result));
            }, "receive-file-thread").start();
        } catch (IllegalArgumentException exception) {
            showValidationError(exception.getMessage());
        }
    }

    private int parsePort(String value) {
        if (value == null || value.isBlank()) {
            return -1;
        }

        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    public void handleDecrypt() {
        try {
            DecryptionRequest request = buildRequestFromView();
            view.showStatus("Đang giải mã tệp...");

            OperationResult result = fileDecryptService.decryptFile(request);
            updateView(result);
        } catch (InvalidKeyException | IllegalArgumentException exception) {
            showValidationError(exception.getMessage());
        }
    }

    private DecryptionRequest buildRequestFromView() throws InvalidKeyException {
        Path encryptedFile = view.getSelectedEncryptedFile();
        ValidationUtils.validateFileExists(encryptedFile);

        if (!encryptedFile.getFileName().toString().toLowerCase().endsWith(".enc")) {
            throw new IllegalArgumentException("Vui lòng chọn tệp .enc hợp lệ.");
        }

        AESVariant variant = view.getSelectedVariant();
        String secretKey = view.getSecretKey();
        ValidationUtils.validateAesKeyHex(secretKey, variant);

        Path outputFile = view.getOutputFile();
        if (outputFile != null && outputFile.equals(encryptedFile)) {
            throw new IllegalArgumentException("Tệp đầu ra phải khác tệp mã hóa đầu vào.");
        }

        return new DecryptionRequest(encryptedFile, outputFile, secretKey, variant);
    }

    private void updateView(OperationResult result) {
        if (result == null) {
            showValidationError("Giải mã không trả về kết quả.");
            return;
        }

        String message = buildDisplayMessage(result);
        view.showStatus(message);

        if (result.isSuccess()) {
            view.showSuccess(message);
        } else {
            view.showError(message);
        }
    }

    private String buildDisplayMessage(OperationResult result) {
        if (result.isSuccess() && result.getOutputPath() != null) {
            return result.getMessage() + " Tệp đầu ra: " + result.getOutputPath();
        }

        String exceptionMessage = result.getExceptionMessage();
        if (exceptionMessage != null
                && !exceptionMessage.isBlank()
                && !exceptionMessage.equals(result.getMessage())) {
            return result.getMessage() + " Chi tiết: " + exceptionMessage;
        }

        return result.getMessage();
    }

    private void showValidationError(String message) {
        view.showStatus(message);
        view.showError(message);
    }

    // ui.ReceiverFrame can implement this interface to connect Swing components to the controller.
    public interface ReceiverView {
        Path getSelectedEncryptedFile();

        Path getOutputFile();

        String getSecretKey();

        AESVariant getSelectedVariant();

        Path getSelectedReceiveDirectory();

        String getListenPort();

        void setSelectedEncryptedFile(Path encryptedFile);

        void setSelectedReceiveDirectory(Path receiveDirectory);

        void showStatus(String message);

        void showSuccess(String message);

        void showError(String message);
    }
}
