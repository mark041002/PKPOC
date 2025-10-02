package org.example.demopkzertifikat.service;

import org.example.demopkzertifikat.model.CertificateEntity;
import org.example.demopkzertifikat.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class PKIService {

    private final CertificateRepository certificateRepository;

    @Value("${pki.root.validity.days:3650}")
    private int rootValidityDays;

    @Value("${pki.intermediate.validity.days:1825}")
    private int intermediateValidityDays;

    @Value("${pki.endentity.validity.days:365}")
    private int endEntityValidityDays;

    @Value("${pki.key.size:2048}")
    private int keySize;

    /**
     * 1. Root CA erstellen (Ober-Zertifikat)
     */
    public CertificateEntity createRootCA(String commonName) throws Exception {
        log.info("Creating Root CA: {}", commonName);

        KeyPair keyPair = generateKeyPair();

        X500Name issuer = new X500Name("CN=" + commonName + ",O=Shooting Range,C=DE");
        BigInteger serial = generateSerial();

        Date notBefore = new Date();
        Date notAfter = Date.from(LocalDateTime.now()
                .plusDays(rootValidityDays)
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                issuer,
                keyPair.getPublic()
        );

        // CA Extensions
        certBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certHolder);

        return saveCertificate(cert, keyPair, CertificateEntity.CertificateType.ROOT_CA,
                commonName, null);
    }

    /**
     * 2. Intermediate CA erstellen (Schießstand-Zertifikat)
     */
    public CertificateEntity createIntermediateCA(String commonName,
                                                  String rootCASerial) throws Exception {
        log.info("Creating Intermediate CA: {} signed by Root CA: {}",
                commonName, rootCASerial);

        CertificateEntity rootCA = certificateRepository
                .findBySerialNumber(rootCASerial)
                .orElseThrow(() -> new RuntimeException("Root CA not found"));

        if (rootCA.getType() != CertificateEntity.CertificateType.ROOT_CA) {
            throw new RuntimeException("Issuer is not a Root CA");
        }

        KeyPair keyPair = generateKeyPair();
        X509Certificate issuerCert = pemToCertificate(rootCA.getCertificatePem());
        PrivateKey issuerKey = pemToPrivateKey(rootCA.getPrivateKeyPem());

        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + commonName +
                ",O=Shooting Range,OU=Range,C=DE");
        BigInteger serial = generateSerial();

        Date notBefore = new Date();
        Date notAfter = Date.from(LocalDateTime.now()
                .plusDays(intermediateValidityDays)
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        // Intermediate CA Extensions
        certBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(0)); // pathLen = 0
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(new BouncyCastleProvider())
                .build(issuerKey);

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certHolder);

        return saveCertificate(cert, keyPair,
                CertificateEntity.CertificateType.INTERMEDIATE_CA,
                commonName, rootCASerial);
    }

    /**
     * 3. End-Entity Zertifikat erstellen (Aufseher-Zertifikat)
     */
    public CertificateEntity createEndEntityCertificate(String commonName,
                                                        String intermediateCASerial) throws Exception {
        log.info("Creating End Entity Certificate: {} signed by Intermediate CA: {}",
                commonName, intermediateCASerial);

        CertificateEntity intermediateCA = certificateRepository
                .findBySerialNumber(intermediateCASerial)
                .orElseThrow(() -> new RuntimeException("Intermediate CA not found"));

        if (intermediateCA.getType() != CertificateEntity.CertificateType.INTERMEDIATE_CA) {
            throw new RuntimeException("Issuer is not an Intermediate CA");
        }

        KeyPair keyPair = generateKeyPair();
        X509Certificate issuerCert = pemToCertificate(intermediateCA.getCertificatePem());
        PrivateKey issuerKey = pemToPrivateKey(intermediateCA.getPrivateKeyPem());

        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + commonName +
                ",O=Shooting Range,OU=Supervisor,C=DE");
        BigInteger serial = generateSerial();

        Date notBefore = new Date();
        Date notAfter = Date.from(LocalDateTime.now()
                .plusDays(endEntityValidityDays)
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        // End Entity Extensions
        certBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(new BouncyCastleProvider())
                .build(issuerKey);

        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certHolder);

        return saveCertificate(cert, keyPair,
                CertificateEntity.CertificateType.END_ENTITY,
                commonName, intermediateCASerial);
    }

    /**
     * Zertifikat verifizieren
     */
    public boolean verifyCertificate(String certificateSerial) throws Exception {
        CertificateEntity certEntity = certificateRepository
                .findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        if (certEntity.isRevoked()) {
            log.warn("Certificate is revoked: {}", certificateSerial);
            return false;
        }

        // Ablaufdatum prüfen
        if (LocalDateTime.now().isAfter(certEntity.getValidTo())) {
            log.warn("Certificate is expired: {}", certificateSerial);
            return false;
        }

        // Root CA signiert sich selbst
        if (certEntity.getType() == CertificateEntity.CertificateType.ROOT_CA) {
            return true;
        }

        // Issuer laden
        CertificateEntity issuer = certificateRepository
                .findBySerialNumber(certEntity.getIssuerSerialNumber())
                .orElseThrow(() -> new RuntimeException("Issuer not found"));

        X509Certificate cert = pemToCertificate(certEntity.getCertificatePem());
        X509Certificate issuerCert = pemToCertificate(issuer.getCertificatePem());

        try {
            cert.verify(issuerCert.getPublicKey(), new BouncyCastleProvider());
            log.info("Certificate verified successfully: {}", certificateSerial);
            return true;
        } catch (Exception e) {
            log.error("Certificate verification failed: {}", certificateSerial, e);
            return false;
        }
    }

    /**
     * Digitale Signatur erstellen
     */
    public String signData(String data, String certificateSerial) throws Exception {
        CertificateEntity certEntity = certificateRepository
                .findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        if (certEntity.getType() != CertificateEntity.CertificateType.END_ENTITY) {
            throw new RuntimeException("Only end entity certificates can sign data");
        }

        PrivateKey privateKey = pemToPrivateKey(certEntity.getPrivateKeyPem());

        Signature signature = Signature.getInstance("SHA256withRSA",
                new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(data.getBytes());

        byte[] signatureBytes = signature.sign();
        return java.util.Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Digitale Signatur verifizieren
     */
    public boolean verifySignature(String data, String signatureBase64,
                                   String certificateSerial) throws Exception {
        CertificateEntity certEntity = certificateRepository
                .findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        X509Certificate cert = pemToCertificate(certEntity.getCertificatePem());

        Signature signature = Signature.getInstance("SHA256withRSA",
                new BouncyCastleProvider());
        signature.initVerify(cert.getPublicKey());
        signature.update(data.getBytes());

        byte[] signatureBytes = java.util.Base64.getDecoder().decode(signatureBase64);
        return signature.verify(signatureBytes);
    }

    /**
     * Zertifikat widerrufen
     */
    public void revokeCertificate(String certificateSerial) {
        CertificateEntity certEntity = certificateRepository
                .findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        certEntity.setRevoked(true);
        certEntity.setRevokedAt(LocalDateTime.now());
        certificateRepository.save(certEntity);

        log.info("Certificate revoked: {}", certificateSerial);
    }

    // ==================== Helper Methods ====================

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private BigInteger generateSerial() {
        return new BigInteger(160, new SecureRandom());
    }

    private CertificateEntity saveCertificate(X509Certificate cert, KeyPair keyPair,
                                              CertificateEntity.CertificateType type,
                                              String commonName, String issuerSerial) throws Exception {
        CertificateEntity entity = new CertificateEntity();
        entity.setSerialNumber(cert.getSerialNumber().toString(16));
        entity.setCommonName(commonName);
        entity.setType(type);
        entity.setCertificatePem(certificateToPem(cert));
        entity.setPrivateKeyPem(privateKeyToPem(keyPair.getPrivate()));
        entity.setPublicKeyPem(publicKeyToPem(keyPair.getPublic()));
        entity.setIssuerSerialNumber(issuerSerial);
        entity.setValidFrom(LocalDateTime.ofInstant(cert.getNotBefore().toInstant(),
                ZoneId.systemDefault()));
        entity.setValidTo(LocalDateTime.ofInstant(cert.getNotAfter().toInstant(),
                ZoneId.systemDefault()));
        entity.setCreatedAt(LocalDateTime.now());

        return certificateRepository.save(entity);
    }

    private String certificateToPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }

    private String privateKeyToPem(PrivateKey key) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
        }
        return sw.toString();
    }

    private String publicKeyToPem(PublicKey key) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(new PemObject("PUBLIC KEY", key.getEncoded()));
        }
        return sw.toString();
    }

    private X509Certificate pemToCertificate(String pem) throws Exception {
        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(pem.getBytes()));
    }

    private PrivateKey pemToPrivateKey(String pem) throws Exception {
        String privateKeyPEM = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = java.util.Base64.getDecoder().decode(privateKeyPEM);
        java.security.spec.PKCS8EncodedKeySpec spec =
                new java.security.spec.PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public List<CertificateEntity> getAllCertificates() {
        return certificateRepository.findAll();
    }

    public CertificateEntity getCertificateBySerial(String serial) {
        return certificateRepository.findBySerialNumber(serial)
                .orElseThrow(() -> new RuntimeException("Certificate not found"));
    }
}