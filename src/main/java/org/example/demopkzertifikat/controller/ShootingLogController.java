package org.example.demopkzertifikat.controller;

import org.example.demopkzertifikat.model.ShootingLogEntry;
import org.example.demopkzertifikat.service.ShootingLogService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/shooting-logs")
@RequiredArgsConstructor
public class ShootingLogController {

    private final ShootingLogService shootingLogService;

    @PostMapping
    public ResponseEntity<ShootingLogEntry> createLogEntry(
            @RequestBody CreateLogEntryRequest request) {
        try {
            ShootingLogEntry entry = shootingLogService.createLogEntry(
                    request.getShooterName(),
                    request.getWeaponType(),
                    request.getShotsCount(),
                    request.getSupervisorCertSerial(),
                    request.getNotes()
            );
            return ResponseEntity.ok(entry);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping
    public ResponseEntity<List<ShootingLogEntry>> getAllLogEntries() {
        return ResponseEntity.ok(shootingLogService.getAllLogEntries());
    }

    @GetMapping("/supervisor/{certSerial}")
    public ResponseEntity<List<ShootingLogEntry>> getLogEntriesBySupervisor(
            @PathVariable String certSerial) {
        return ResponseEntity.ok(shootingLogService.getLogEntriesBySupervisor(certSerial));
    }

    @PostMapping("/{entryId}/verify")
    public ResponseEntity<VerificationResponse> verifyLogEntry(@PathVariable Long entryId) {
        try {
            boolean valid = shootingLogService.verifyLogEntry(entryId);
            return ResponseEntity.ok(new VerificationResponse(valid));
        } catch (Exception e) {
            return ResponseEntity.ok(new VerificationResponse(false));
        }
    }

    // DTOs
    @Data
    public static class CreateLogEntryRequest {
        private String shooterName;
        private String weaponType;
        private Integer shotsCount;
        private String supervisorCertSerial;
        private String notes;
    }

    @Data
    public static class VerificationResponse {
        private boolean valid;

        public VerificationResponse(boolean valid) {
            this.valid = valid;
        }
    }
}