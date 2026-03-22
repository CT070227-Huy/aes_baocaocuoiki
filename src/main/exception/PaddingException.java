package exception;

public class PaddingException extends CryptoException {
    public PaddingException(String message) {
        super(message);
    }

    public PaddingException(String message, Throwable cause) {
        super(message, cause);
    }
}
