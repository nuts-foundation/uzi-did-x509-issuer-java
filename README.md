# Java library for generating X509 Verifiable credentials

## Usage

```Java
try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("full-chain-and-leaf.pem")) {
    List<X509Certificate> certificates = X509CertificateParser.parse(inputStream);
    Certificate certificate = new Certificate(certificates);
    String jwt = JWTGenerator.generateVC(certificate, privateKey, "did:web:example.com:iam:the_subject");
}
```

## Caveats

Use the BouncyCastle provider when parsing PKCS12 files and extracting certificates for it:

```Java
static {
    Security.addProvider(new BouncyCastleProvider());
}

KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
```