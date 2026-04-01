package controller;

import crypto.AESVariant;
import exception.InvalidKeyException;
import file.FileDecryptService;
import model.DecryptionRequest;
import model.OperationResult;
import util.ValidationUtils;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.nio.file.Path;

public class ReceiverController {
    private final ReceiverView view;
    private final FileDecryptService fileDecryptService;

    public ReceiverController(ReceiverView view) {
        this(view, new FileDecryptService());
    }

    public ReceiverController(ReceiverView view, FileDecryptService fileDecryptService) {
        if (view == null) {
            throw new IllegalArgumentException("Giao diện nhận không được để trống.");
        }

        if (fileDecryptService == null) {
            throw new IllegalArgumentException("Dịch vụ giải mã tệp không được để trống.");
        }

        this.view = view;
        this.fileDecryptService = fileDecryptService;
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

        void setSelectedEncryptedFile(Path encryptedFile);

        void showStatus(String message);

        void showSuccess(String message);

        void showError(String message);
    }
}
