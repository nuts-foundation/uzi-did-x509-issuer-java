package nl.nuts.credential.uzi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class JWTGeneratorTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateVCWithPem() {

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

    @Test
    public void testGenerateVCWithPkcs12() {

        KeyStore keyStore = loadPrivateKeyFromPkcs12();

        assertDoesNotThrow(() -> {
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("example.com-chain.pem")) {
                List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
                Certificate certificate = new Certificate(certificates);
                String jwt = JWTGenerator.generateVC(certificate, keyStore, "test", "did:web:example.com:iam:groot");
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

    static KeyStore loadPrivateKeyFromPkcs12() {
        String fileName = "example.com.p12";
        try (InputStream inputStream = JWTGenerator.class.getClassLoader().getResourceAsStream(fileName)) {
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(inputStream, "test".toCharArray());
            return keystore;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}