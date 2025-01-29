package nl.nuts.credential.uzi;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class JWTGeneratorTest {

    @Test
    public void testGenerateVC() {

        Key privateKey = loadPrivateKey();

        assertDoesNotThrow(() -> {
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("example.com-chain.pem")) {
                List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
                Certificate certificate = new Certificate(certificates);
                String jwt = JWTGenerator.generateVC(certificate, privateKey, "did:web:example.com:iam:groot");
                System.out.println(jwt);
            }
        });
    }

    static Key loadPrivateKey() {
        // load from class path: example.com.key
        // it's pem encoded
        String fileName = "example.com.key";
        try (InputStream inputStream = JWTGenerator.class.getClassLoader().getResourceAsStream(fileName)) {
            try (PemReader pemReader = new PemReader(new InputStreamReader(inputStream))) {
                PemObject pemObject = pemReader.readPemObject();
                byte[] content = pemObject.getContent();
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(keySpec);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}