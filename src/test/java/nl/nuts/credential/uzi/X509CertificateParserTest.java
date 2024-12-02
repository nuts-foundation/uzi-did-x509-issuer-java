package nl.nuts.credential.uzi;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

public class X509CertificateParserTest {
    @Test
    public void testParseX509Certificate() throws Exception {
        try (InputStream inputStream = X509CertificateParser.class.getClassLoader().getResourceAsStream("example.com-chain.pem")) {
            List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
            System.out.println(certificates.get(1).toString());
        }
    }
}
