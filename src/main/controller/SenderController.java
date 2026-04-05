package controller;

import crypto.AESVariant;
import exception.InvalidKeyException;
import file.FileEncryptService;
import java.awt.Component;
import java.nio.file.Path;
import javax.swing.JFileChooser;
import model.EncryptionRequest;
import model.OperationResult;
import network.FileTransferClient;
import util.ValidationUtils;

public class SenderController {
    private final SenderView view;
    private final FileEncryptService fileEncryptService;
    private final FileTransferClient fileTransferClient;

    public SenderController(SenderView view) {
        this(view, new FileEncryptService(), new FileTransferClient());
    }

    public SenderController(SenderView view, FileEncryptService fileEncryptService, FileTransferClient fileTransferClient) {
        if (view == null) {
            throw new IllegalArgumentException("Giao diện gửi không được để trống.");
        }

        if (fileEncryptService == null) {
            throw new IllegalArgumentException("Dịch vụ mã hóa tệp không được để trống.");
        }

        if (fileTransferClient == null) {
            throw new IllegalArgumentException("Dịch vụ gửi tệp không được để trống.");
        }

        this.view = view;
        this.fileEncryptService = fileEncryptService;
        this.fileTransferClient = fileTransferClient;
    }

    public void handleChooseFile(Component parentComponent) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        int selectionResult = fileChooser.showOpenDialog(parentComponent);
        if (selectionResult != JFileChooser.APPROVE_OPTION || fileChooser.getSelectedFile() == null) {
            return;
        }

        Path selectedFile = fileChooser.getSelectedFile().toPath().toAbsolutePath().normalize();
        view.setSelectedInputFile(selectedFile);
        view.showStatus("Đã chọn tệp: " + selectedFile.getFileName());
    }

    public void handleChooseEncryptedFile(Component parentComponent) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Tệp mã hóa (*.enc)", "enc"));

        int selectionResult = fileChooser.showOpenDialog(parentComponent);
        if (selectionResult != JFileChooser.APPROVE_OPTION || fileChooser.getSelectedFile() == null) {
            return;
        }

        Path selectedFile = fileChooser.getSelectedFile().toPath().toAbsolutePath().normalize();
        view.setSelectedEncryptedFile(selectedFile);
        view.showStatus("Đã chọn tệp .enc gửi: " + selectedFile.getFileName());
    }

    public void handleSendEncryptedFile() {
        try {
            Path encryptedFile = view.getSelectedEncryptedFile();
            if (encryptedFile == null) {
                throw new IllegalArgumentException("Vui lòng chọn tệp .enc để gửi.");
            }

            String host = view.getTargetHost();
            int port = view.getTargetPort();
            if (port <= 0) {
                throw new IllegalArgumentException("Cổng phải là một số hợp lệ từ 1 đến 65535.");
            }

            view.showStatus("Đang gửi tệp đến " + host + ":" + port + "...");
            OperationResult result = fileTransferClient.sendFile(encryptedFile, host, port);
            updateView(result);
        } catch (IllegalArgumentException exception) {
            showValidationError(exception.getMessage());
        }
    }

    public void handleEncrypt() {
        try {
            EncryptionRequest request = buildRequestFromView();
            view.showStatus("Đang mã hóa tệp...");

            OperationResult result = fileEncryptService.encryptFile(request);
            updateView(result);
        } catch (InvalidKeyException | IllegalArgumentException exception) {
            showValidationError(exception.getMessage());
        }
    }

    private EncryptionRequest buildRequestFromView() throws InvalidKeyException {
        Path inputFile = view.getSelectedInputFile();
        ValidationUtils.validateFileExists(inputFile);

        AESVariant variant = view.getSelectedVariant();
        String secretKey = view.getSecretKey();
        ValidationUtils.validateAesKeyHex(secretKey, variant);

        Path outputFile = view.getOutputFile();
        if (outputFile != null && outputFile.equals(inputFile)) {
            throw new IllegalArgumentException("Tệp đầu ra phải khác tệp đầu vào.");
        }

        return new EncryptionRequest(inputFile, outputFile, secretKey, variant);
    }

    private void updateView(OperationResult result) {
        if (result == null) {
            showValidationError("Mã hóa không trả về kết quả.");
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

    // ui.SenderFrame can implement this interface to connect Swing components to the controller.
    public interface SenderView {
        Path getSelectedInputFile();

        Path getOutputFile();

        String getSecretKey();

        AESVariant getSelectedVariant();

        void setSelectedInputFile(Path inputFile);

        Path getSelectedEncryptedFile();

        String getTargetHost();

        int getTargetPort();

        void setSelectedEncryptedFile(Path encryptedFile);

        void showStatus(String message);

        void showSuccess(String message);

        void showError(String message);
    }
}
