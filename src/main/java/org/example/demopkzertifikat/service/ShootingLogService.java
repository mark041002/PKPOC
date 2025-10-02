package org.example.demopkzertifikat.service;

import org.example.demopkzertifikat.model.CertificateEntity;
import org.example.demopkzertifikat.model.ShootingLogEntry;
import org.example.demopkzertifikat.repository.ShootingLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class ShootingLogService {

    private final ShootingLogRepository shootingLogRepository;
    private final PKIService pkiService;

    /**
     * Schießbuch-Eintrag erstellen und signieren
     */
    public ShootingLogEntry createLogEntry(String shooterName, String weaponType,
                                           int shotsCount, String supervisorCertSerial,
                                           String notes) throws Exception {
        // Zertifikat verifizieren
        if (!pkiService.verifyCertificate(supervisorCertSerial)) {
            throw new RuntimeException("Invalid or revoked supervisor certificate");
        }

        CertificateEntity supervisorCert = pkiService.getCertificateBySerial(supervisorCertSerial);

        ShootingLogEntry entry = new ShootingLogEntry();
        entry.setShooterName(shooterName);
        entry.setWeaponType(weaponType);
        entry.setShotsCount(shotsCount);
        entry.setTimestamp(LocalDateTime.now());
        entry.setSupervisorCertificateSerial(supervisorCertSerial);
        entry.setSupervisorCommonName(supervisorCert.getCommonName());
        entry.setNotes(notes);
        entry.setCreatedAt(LocalDateTime.now());

        // Daten für Signatur erstellen
        String dataToSign = String.format("%s|%s|%d|%s",
                shooterName, weaponType, shotsCount, entry.getTimestamp());

        // Digital signieren
        String signature = pkiService.signData(dataToSign, supervisorCertSerial);
        entry.setDigitalSignature(signature);

        log.info("Created shooting log entry signed by: {}",
                supervisorCert.getCommonName());

        return shootingLogRepository.save(entry);
    }

    /**
     * Eintrag verifizieren
     */
    public boolean verifyLogEntry(Long entryId) throws Exception {
        ShootingLogEntry entry = shootingLogRepository.findById(entryId)
                .orElseThrow(() -> new RuntimeException("Log entry not found"));

        String dataToSign = String.format("%s|%s|%d|%s",
                entry.getShooterName(), entry.getWeaponType(),
                entry.getShotsCount(), entry.getTimestamp());

        return pkiService.verifySignature(dataToSign, entry.getDigitalSignature(),
                entry.getSupervisorCertificateSerial());
    }

    public List<ShootingLogEntry> getAllLogEntries() {
        return shootingLogRepository.findAll();
    }

    public List<ShootingLogEntry> getLogEntriesBySupervisor(String certificateSerial) {
        return shootingLogRepository.findBySupervisorCertificateSerial(certificateSerial);
    }
}