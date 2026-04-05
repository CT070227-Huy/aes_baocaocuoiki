package network;

import model.OperationResult;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class FileTransferServer {
    public OperationResult listenForSingleFile(int port, Path saveDirectory) {
        if (port <= 0 || port > 65535) {
            return OperationResult.failure("Cổng phải là một số từ 1 đến 65535.");
        }

        if (saveDirectory == null) {
            return OperationResult.failure("Vui lòng chọn thư mục lưu tệp nhận được.");
        }

        try {
            Files.createDirectories(saveDirectory);
        } catch (IOException exception) {
            return OperationResult.failure("Không thể tạo thư mục lưu tệp nhận được.", exception.getMessage());
        }

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            try (Socket clientSocket = serverSocket.accept();
                 InputStream socketIn = clientSocket.getInputStream();
                 BufferedInputStream bufferedIn = new BufferedInputStream(socketIn);
                 DataInputStream dataInput = new DataInputStream(bufferedIn)) {

                int fileNameLength = dataInput.readInt();
                if (fileNameLength <= 0 || fileNameLength > 0x1000) {
                    return OperationResult.failure("Tên tệp nhận được không hợp lệ.");
                }

                byte[] fileNameBytes = new byte[fileNameLength];
                dataInput.readFully(fileNameBytes);
                String fileName = new String(fileNameBytes, StandardCharsets.UTF_8);
                long fileSize = dataInput.readLong();

                if (fileSize < 0) {
                    return OperationResult.failure("Kích thước tệp nhận được không hợp lệ.");
                }

                Path targetFile = saveDirectory.resolve(Path.of(fileName).getFileName());
                Path normalizedTarget = targetFile.normalize();
                if (!normalizedTarget.startsWith(saveDirectory.normalize())) {
                    return OperationResult.failure("Tên tệp không hợp lệ.");
                }

                try (BufferedOutputStream fileOut = new BufferedOutputStream(Files.newOutputStream(normalizedTarget))) {
                    byte[] buffer = new byte[8192];
                    long remaining = fileSize;
                    while (remaining > 0) {
                        int bytesRead = dataInput.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                        if (bytesRead == -1) {
                            break;
                        }
                        fileOut.write(buffer, 0, bytesRead);
                        remaining -= bytesRead;
                    }
                    if (remaining != 0) {
                        return OperationResult.failure("Dữ liệu tệp bị thiếu khi nhận.");
                    }
                }

                return OperationResult.success("Đã nhận thành công tệp: " + normalizedTarget, normalizedTarget);
            }
        } catch (IOException exception) {
            return OperationResult.failure("Không thể lắng nghe kết nối hoặc nhận tệp.", exception.getMessage());
        }
    }
}
