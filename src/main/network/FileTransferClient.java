package network;

import model.OperationResult;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class FileTransferClient {
    public OperationResult sendFile(Path fileToSend, String host, int port) {
        if (fileToSend == null) {
            return OperationResult.failure("Vui lòng chọn tệp .enc để gửi.");
        }

        if (!Files.exists(fileToSend) || !Files.isRegularFile(fileToSend)) {
            return OperationResult.failure("Tệp gửi không tồn tại hoặc không phải tệp hợp lệ.");
        }

        if (host == null || host.isBlank()) {
            return OperationResult.failure("Vui lòng nhập địa chỉ máy nhận.");
        }

        if (port <= 0 || port > 65535) {
            return OperationResult.failure("Cổng phải là một số từ 1 đến 65535.");
        }

        try (Socket socket = new Socket(host.trim(), port);
             OutputStream socketOut = socket.getOutputStream();
             BufferedOutputStream bufferedOut = new BufferedOutputStream(socketOut);
             DataOutputStream dataOutput = new DataOutputStream(bufferedOut)) {

            String fileName = fileToSend.getFileName().toString();
            byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_8);
            long fileSize = Files.size(fileToSend);

            dataOutput.writeInt(fileNameBytes.length);
            dataOutput.write(fileNameBytes);
            dataOutput.writeLong(fileSize);

            Files.copy(fileToSend, bufferedOut);
            bufferedOut.flush();

            return OperationResult.success("Gửi tệp thành công đến " + host + ":" + port + ".", fileToSend);
        } catch (IOException exception) {
            return OperationResult.failure("Không thể gửi tệp đến máy nhận.", exception.getMessage());
        }
    }
}
