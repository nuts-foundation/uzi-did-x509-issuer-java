package nl.nuts.credential.uzi;

public class InvalidCertificateException extends Exception {
    public InvalidCertificateException(String message) {
        super(message);
    }
    public InvalidCertificateException(Exception cause) {
        super(cause);
    }
}
