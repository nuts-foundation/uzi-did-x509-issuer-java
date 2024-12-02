package nl.nuts.credential.uzi;

public class CredentialCreationException extends Exception {
    public CredentialCreationException(String message) {
        super(message);
    }
    public CredentialCreationException(Exception cause) {
        super(cause);
    }
}
