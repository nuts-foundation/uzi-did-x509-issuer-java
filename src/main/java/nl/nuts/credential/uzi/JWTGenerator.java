package nl.nuts.credential.uzi;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SecureDigestAlgorithm;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

public class JWTGenerator {
    private static String generateVCInternal(Certificate certificate, Key privateKey, String subject) throws CredentialCreationException {
        try {
            String issuerDID = certificate.didX509();
            String kid = String.format("%s#0", issuerDID);
            Date expiration = certificate.getCertificate().getNotAfter();
            byte[] x5t = certificate.x5t();
            // copy and reverse
            List<X509Certificate> x5c = new ArrayList<>(certificate.getChain());
            Collections.reverse(x5c);

            String jti = String.format("%s#%s", issuerDID, UUID.randomUUID());

            SecureDigestAlgorithm sigAlg = Jwts.SIG.get().forKey("PS256");

            // Generate the JWT
            String jwt = Jwts.builder()
                    .header()
                    .keyId(kid)
                    .type("JWT")
                    .x509Chain(x5c)
                    .x509Sha1Thumbprint(x5t)
                    .and()
                    .id(jti)
                    .issuer(issuerDID)
                    .subject(subject)
                    .notBefore(new Date())
                    .expiration(expiration)
                    .claims(certificate.toClaims())
                    .signWith(privateKey, sigAlg)
                    .compact();

            return jwt;
        } catch (InvalidCertificateException e) {
            throw new CredentialCreationException(e);
        }
    }

    /**
     * Generate a Verifiable Credential (VC) using the provided certificates and private key
     * @param certificate List of X509 certificates, the first certificate is the CA and the last is the leaf certificate
     * @param privateKey The private key used for signing the JWT
     * @param subject The subject of the JWT
     */
    public static String generateVC(Certificate certificate, Key privateKey, String subject) throws CredentialCreationException {
        return generateVCInternal(certificate, privateKey, subject);
    }

    /**
     * Generate a Verifiable Credential (VC) using the provided certificates and keyStore.
     * The first alias in the keyStore is used to retrieve the private key.
     * The certificate in the keyStore is not used.
     * @param certificate List of X509 certificates, the first certificate is the CA and the last is the leaf certificate
     * @param keyStore The KeyStore containing the private key used for signing the JWT
     * @param password The password for the KeyStore
     * @param subject The subject of the JWT
     */
    public static String generateVC(Certificate certificate, KeyStore keyStore, String password, String subject) throws CredentialCreationException {
        try {
            char[] pass = null;
            if (password != null) {
                pass = password.toCharArray();
            }
            // get first alias
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            // Retrieve the private key from the KeyStore
            Key privateKey = keyStore.getKey(alias, pass);
            return generateVCInternal(certificate, privateKey, subject);
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new CredentialCreationException(e);
        }
    }
}
