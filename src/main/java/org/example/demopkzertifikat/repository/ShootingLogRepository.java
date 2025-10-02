package org.example.demopkzertifikat.repository;

import org.example.demopkzertifikat.model.ShootingLogEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ShootingLogRepository extends JpaRepository<ShootingLogEntry, Long> {

    List<ShootingLogEntry> findBySupervisorCertificateSerial(String certificateSerial);

    List<ShootingLogEntry> findAllByOrderByTimestampDesc();

    List<ShootingLogEntry> findByTimestampBetween(LocalDateTime start, LocalDateTime end);
}