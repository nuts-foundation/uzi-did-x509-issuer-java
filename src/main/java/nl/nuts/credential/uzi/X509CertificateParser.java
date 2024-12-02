package nl.nuts.credential.uzi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateParser {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static List<X509Certificate> parse(InputStream inputStream) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            try (PemReader pemReader = new PemReader(new InputStreamReader(inputStream))) {
                PemObject pemObject;
                while ((pemObject = pemReader.readPemObject()) != null) {
                    byte[] content = pemObject.getContent();
                    X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(content));
                    certificates.add(certificate);
                }
            }
        } catch (NoSuchProviderException | CertificateException e) {
            throw new RuntimeException(e);
        }

        return certificates;
    }
}
