package nl.nuts.credential.uzi;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertificateTest {

    @Test
    public void testDIDX509() {
        assertDoesNotThrow(() -> {
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("example.com-chain.pem")) {
            //try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("uzi.pem")) {
                List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
                Certificate wrapper = new Certificate(certificates);
                assertEquals("did:x509:0:sha256:szqMaTpnD6GN0aRrT98eV4bhAoOgyItEZVyskYyL_Qc::san:otherName:2.16.528.1.1007.99.2110-1-1-S-2-00.000-3::subject:CN:example%2Ecom:L:world:O:ACME", wrapper.didX509());
            }
        });
    }
}
