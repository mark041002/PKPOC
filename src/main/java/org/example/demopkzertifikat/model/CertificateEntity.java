package org.example.demopkzertifikat.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String serialNumber;

    @Column(nullable = false)
    private String commonName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    @Column(length = 10000)
    private String certificatePem;

    @Column(length = 10000)
    private String privateKeyPem;

    @Column(length = 10000)
    private String publicKeyPem;

    private String issuerSerialNumber;

    @Column(nullable = false)
    private LocalDateTime validFrom;

    @Column(nullable = false)
    private LocalDateTime validTo;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private boolean revoked = false;

    private LocalDateTime revokedAt;

    public enum CertificateType {
        ROOT_CA,
        INTERMEDIATE_CA,
        END_ENTITY
    }
}