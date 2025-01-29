package nl.nuts.credential.uzi;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class Certificate {
    private List<X509Certificate> chain;
    private final MessageDigest digest;
    // encoded contains the DER encoded certificates
    private final List<byte[]> encoded;

    public Certificate(List<X509Certificate> chain) throws InvalidCertificateException {
        if (chain.isEmpty()) {
            throw new InvalidCertificateException("Certificate chain is empty");
        }

        this.chain = chain;
        this.encoded = new ArrayList<>();
        try {
            for (X509Certificate cert : this.chain) {
                this.encoded.add(cert.getEncoded());
            }
            this.digest = MessageDigest.getInstance("SHA-1");
        } catch (Exception e) {
            throw new InvalidCertificateException(e);
        }
    }

    // Generate the x5t claim (Base64 encoded sha1 thumbprint of the certificate)
    public byte[] x5t() {
        byte[] encoded = this.encoded.get(this.encoded.size()-1);
        return digest.digest(encoded);
//        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    // Generate the x5c claim (Base64 encoded certificate and full chain)
    public String x5c() {
        try {
            StringWriter s = new StringWriter();
            PemWriter pemWriter = new PemWriter(s);
            for (byte[] encoded : this.encoded) {
                pemWriter.writeObject(new PemObject("CERTIFICATE", encoded));
            }
            return s.toString();
        } catch (IOException e) {
            // we're writing to a StringWriter, this should never happen
            throw new RuntimeException(e);
        }
    }

    public String didX509() throws InvalidCertificateException{
        // we need the fingerprint of the second last certificate in the chain
        // or the last certificate if the chain only contains one certificate
        if (this.chain.isEmpty()) {
            throw new InvalidCertificateException("Certificate chain is too short");
        }
        try {
            // copy the chain, pop the last certificate, and get the sha512 of the last certificate
            List<X509Certificate> chain = new ArrayList<>(this.chain);
            if (chain.size() > 1) {
                chain.remove(chain.size() - 1);
            }
            byte[] encoded = chain.get(chain.size() - 1).getEncoded();
            MessageDigest digestSHA512 = MessageDigest.getInstance("SHA-256");
            byte[] hash = digestSHA512.digest(encoded);
            String policy = this.otherName();
            String withSan = String.format("did:x509:0:sha256:%s::san:otherName:%s", Base64.getUrlEncoder().withoutPadding().encodeToString(hash), policy);
            Map<String, String> subject = this.subjectValues();
            // join key/values with a colon, join pairs with a colon
            String subjectString = subject.entrySet().stream().map(e -> formatKeyValue(e.getKey(), e.getValue())).collect(Collectors.joining(":"));
            return withSan + "::" + "subject:" + subjectString;

        } catch (CertificateEncodingException e) {
            throw new InvalidCertificateException("CA is incorrect or malformed: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            // not to be expected for SHA-512
            throw new RuntimeException(e);
        }
    }

    private static String formatKeyValue(String key, String value) {
        try {
            return key + ":" + URLEncoder.encode(value, "UTF-8")
                    .replace("+", "%20")
                    .replace("_", "%5F")
                    .replace("~", "%7E")
                    .replace("-", "%2D")
                    .replace(".", "%2E");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Extract the subject from the certificate
     */
    private Map<String, String> subjectValues() {
        X509Certificate cert = getCertificate();
        X500Principal principal = cert.getSubjectX500Principal();
        String dn = principal.getName(X500Principal.RFC2253);
        Map<String, String> parsed = parseDN(dn);
        // filter on the keys we want to keep
        parsed.keySet().retainAll(Set.of("CN", "OU", "O", "C", "ST", "L"));
        return parsed;
    }

    /**
     * Extract the otherName for the policy string for the certificate
     * It returns something like 2.16.528.1.1007.[d+].[d+]-[d+]-[d+]-S-(d+)-00.000-[d+]
     * Where (d+) is the UZI number. This value is taken from the certificate san.otherName (2.5.29.17.2.5.5.5)
     * @return the policy string
     */
    private String otherName() throws InvalidCertificateException {
        // extract san.otherName from the certificate
        // and return the policy string
        X509Certificate cert = getCertificate();
        byte[] asn1EncodedPolicy = null;
        try {
            asn1EncodedPolicy = cert.getSubjectAlternativeNames().stream()
                    .filter(san -> san.get(0).equals(0)) // otherName
                    .map(san -> (byte[]) san.get(1))// get ASN1 encoded otherName
                    .filter(object -> hasIdentifier(object, "2.5.5.5"))
                    .findFirst()
                    .orElseThrow(() -> new InvalidCertificateException("No UZI number found in certificate"));
        } catch (CertificateParsingException e) {
            throw new InvalidCertificateException(e);
        }
        // parse the ASN1 encoded otherName to a string
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(asn1EncodedPolicy))) {
            ASN1Sequence sequence;
            ASN1Primitive object = asn1InputStream.readObject();
            if (object instanceof ASN1TaggedObject) {
                ASN1TaggedObject lvl1 = (ASN1TaggedObject) object;
                sequence = (ASN1Sequence) lvl1.getBaseObject();
            } else {
                sequence = (ASN1Sequence) object;
            }
            // the first object is the OID, the second is the value
            ASN1TaggedObject lvl2 = (ASN1TaggedObject) sequence.getObjectAt(1);
            return lvl2.getBaseObject().toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean hasIdentifier(byte[] raw, String s) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(raw))) {
            ASN1Sequence sequence;
            ASN1Primitive object = asn1InputStream.readObject();
            if (object instanceof ASN1TaggedObject) {
                ASN1TaggedObject lvl1 = (ASN1TaggedObject) object;
                sequence = (ASN1Sequence) lvl1.getBaseObject();
            } else {
                sequence = (ASN1Sequence) object;
            }
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
            return oid.getId().equals(s);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    X509Certificate getCertificate() {
        return this.chain.get(this.chain.size()-1);
    }

    List<X509Certificate> getChain() {
        return this.chain;
    }


    /**
     * Convert the certificate to a map of claims with "vc" as root
     * @return a map of claims
     */
    Map<String, ?> toClaims() throws InvalidCertificateException{
        Map<String, String> subject = this.subjectValues();

        return Map.of("vc", Map.of(
                "@context", "https://www.w3.org/2018/credentials/v1",
                "type", List.of("VerifiableCredential", "X509Credential"),
                "credentialSubject", Map.of(
                        "subject", subject,
                        "san", Map.of(
                            "otherName", this.otherName()
                        )
                )
        ));
    }

    private static Map<String, String> parseDN(String dn) {
        Map<String, String> attributes = new HashMap<>();
        String[] pairs = dn.split(",");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                attributes.put(keyValue[0], keyValue[1]);
            }
        }
        return attributes;
    }
}

