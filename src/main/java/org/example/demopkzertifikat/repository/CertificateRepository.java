package org.example.demopkzertifikat.repository;

import org.example.demopkzertifikat.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    Optional<CertificateEntity> findBySerialNumber(String serialNumber);

    List<CertificateEntity> findByType(CertificateEntity.CertificateType type);

    Optional<CertificateEntity> findByCommonName(String commonName);

    List<CertificateEntity> findByIssuerSerialNumber(String issuerSerialNumber);
}