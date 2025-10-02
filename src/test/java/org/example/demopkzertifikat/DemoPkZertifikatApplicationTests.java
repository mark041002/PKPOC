package org.example.demopkzertifikat;

import org.example.demopkzertifikat.model.CertificateEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.demopkzertifikat.service.PKIService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DemoPkZertifikatApplicationTests implements CommandLineRunner {

    private final PKIService pkiService;

    @Override
    public void run(String... args) throws Exception {
        if (args.length > 0 && args[0].equals("--test-pki")) {
            log.info("=== Starting PKI Test ===");

            // 1. Root CA erstellen
            log.info("1. Creating Root CA...");
            CertificateEntity rootCA = pkiService.createRootCA(
                    "German Shooting Federation Root CA");
            log.info("Root CA Serial: {}", rootCA.getSerialNumber());

            // 2. Schießstand-Zertifikat erstellen
            log.info("2. Creating Shooting Range Certificate...");
            CertificateEntity range1 = pkiService.createShootingRangeCertificate(
                    "Schützenverein München",
                    rootCA.getSerialNumber()
            );
            log.info("Range Certificate Serial: {}", range1.getSerialNumber());

            // 3. Aufseher-Zertifikate erstellen
            log.info("3. Creating Supervisor Certificates...");
            CertificateEntity supervisor1 = pkiService.createSupervisorCertificate(
                    "Max Mustermann",
                    "max.mustermann@schuetzenverein-muenchen.de",
                    range1.getSerialNumber()
            );
            log.info("Supervisor 1 Serial: {}", supervisor1.getSerialNumber());

            CertificateEntity supervisor2 = pkiService.createSupervisorCertificate(
                    "Erika Musterfrau",
                    "erika.musterfrau@schuetzenverein-muenchen.de",
                    range1.getSerialNumber()
            );
            log.info("Supervisor 2 Serial: {}", supervisor2.getSerialNumber());

            // 4. Zertifikate verifizieren
            log.info("4. Verifying Certificates...");
            log.info("Root CA valid: {}",
                    pkiService.verifyCertificate(rootCA.getSerialNumber()));
            log.info("Range valid: {}",
                    pkiService.verifyCertificate(range1.getSerialNumber()));
            log.info("Supervisor 1 valid: {}",
                    pkiService.verifyCertificate(supervisor1.getSerialNumber()));
            log.info("Supervisor 2 valid: {}",
                    pkiService.verifyCertificate(supervisor2.getSerialNumber()));

            log.info("=== PKI Test Completed Successfully ===");
        }
    }
}