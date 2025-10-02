package org.example.demopkzertifikat.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "shooting_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ShootingLogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String shooterName;

    @Column(nullable = false)
    private String weaponType;

    @Column(nullable = false)
    private Integer shotsCount;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    // Signatur-Informationen
    @Column(nullable = false)
    private String supervisorCertificateSerial;

    @Column(length = 2000)
    private String digitalSignature;

    @Column(nullable = false)
    private String supervisorCommonName;

    private String notes;

    @Column(nullable = false)
    private LocalDateTime createdAt;
}