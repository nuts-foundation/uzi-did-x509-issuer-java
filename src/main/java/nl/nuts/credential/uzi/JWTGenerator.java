package nl.nuts.credential.uzi;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class JWTGenerator {
    /**
     * Generate a Verifiable Credential (VC) using the provided certificates and private key
     * @param certificate List of X509 certificates, the first certificate is the CA and the last is the leaf certificate
     * @param privateKey
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static void generateVC(Certificate certificate, Key privateKey, String subject) throws CredentialCreationException {
        try {
            String issuerDID = certificate.didX509();
            String kid = String.format("%s#0", issuerDID);
            Date expiration = certificate.getCertificate().getNotAfter();
            byte[] x5t = certificate.x5t();
            // copy and reverse
            List<X509Certificate> x5c = new ArrayList<>(certificate.getChain());
            Collections.reverse(x5c);

            // Generate the JWT
            String jwt = Jwts.builder()
                    .header()
                        .keyId(kid)
                        .x509Chain(x5c)
                        .x509Sha1Thumbprint(x5t)
                        .and()
                    .issuer(issuerDID)
                    .subject(subject)
                    .issuedAt(new Date())
                    .expiration(expiration)
                    .claims(certificate.toClaims())
                    .signWith(privateKey)
                    .compact();

            System.out.println("Generated JWT: " + jwt);
        } catch (InvalidCertificateException e) {
            throw new CredentialCreationException(e);
        }
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
