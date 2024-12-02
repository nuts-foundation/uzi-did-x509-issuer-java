package nl.nuts.credential.uzi;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

import static nl.nuts.credential.uzi.JWTGenerator.loadPrivateKey;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class JWTGeneratorTest {

    @Test
    public void testGenerateVC() {

        Key privateKey = loadPrivateKey();

        assertDoesNotThrow(() -> {
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("example.com-chain.pem")) {
                List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
                Certificate certificate = new Certificate(certificates);
                JWTGenerator.generateVC(certificate, privateKey, "did:web:example.com:iam:groot");
            }
        });
    }
}