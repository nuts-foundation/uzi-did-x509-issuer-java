package nl.nuts.credential.uzi;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

// Chain mirrors a PKIoverheid G4 UZI server certificate: RSA 4096, RSASSA-PSS/SHA-512, UZI otherName + permanentIdentifier SANs.
public class G4CertificateTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testG4Chain() throws Exception {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("g4-chain.pem")) {
            List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
            assertEquals(3, certificates.size());
            for (X509Certificate c : certificates) {
                assertEquals("SHA512withRSAandMGF1", c.getSigAlgName());
            }
            Certificate certificate = new Certificate(certificates);
            String did = certificate.didX509();
            System.out.println(did);
            assertTrue(did.startsWith("did:x509:0:sha256:U3UMqpGdAFLuQ_qakWR1zETEP1Ns85IG0s_fJKb8TUY::san:otherName:2.16.528.1.1003.1.3.5.5.5-1-900012345-S-90000380-00.000-00000000::subject:"), did);
            assertTrue(did.contains("O:Because%20We%20Care"), did);

            Key privateKey;
            try (InputStream keyStream = getClass().getClassLoader().getResourceAsStream("g4.key");
                 PemReader pemReader = new PemReader(new InputStreamReader(keyStream))) {
                PemObject pemObject = pemReader.readPemObject();
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pemObject.getContent()));
            }
            String jwt = JWTGenerator.generateVC(certificate, privateKey, "did:web:example.com:iam:holder");
            var parsed = Jwts.parser().verifyWith(certificates.get(2).getPublicKey()).build().parseSignedClaims(jwt);
            assertEquals("PS256", parsed.getHeader().getAlgorithm());
            assertEquals(did, parsed.getPayload().getIssuer());
        }
    }
}
