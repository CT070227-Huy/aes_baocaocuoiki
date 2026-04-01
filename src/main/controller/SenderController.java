package controller;

import crypto.AESVariant;
import exception.InvalidKeyException;
import file.FileEncryptService;
import model.EncryptionRequest;
import model.OperationResult;
import util.ValidationUtils;

import javax.swing.JFileChooser;
import java.awt.Component;
import java.nio.file.Path;

public class SenderController {
    private final SenderView view;
    private final FileEncryptService fileEncryptService;

    public SenderController(SenderView view) {
        this(view, new FileEncryptService());
    }

    public SenderController(SenderView view, FileEncryptService fileEncryptService) {
        if (view == null) {
            throw new IllegalArgumentException("Giao diện gửi không được để trống.");
        }

        if (fileEncryptService == null) {
            throw new IllegalArgumentException("Dịch vụ mã hóa tệp không được để trống.");
        }

        this.view = view;
        this.fileEncryptService = fileEncryptService;
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

        void showStatus(String message);

        void showSuccess(String message);

        void showError(String message);
    }
}
