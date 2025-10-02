package org.example.demopkzertifikat.controller;

import org.example.demopkzertifikat.model.CertificateEntity;
import org.example.demopkzertifikat.service.PKIService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final PKIService pkiService;

    @PostMapping("/root-ca")
    public ResponseEntity<CertificateEntity> createRootCA(@RequestBody CreateRootCARequest request) {
        try {
            CertificateEntity cert = pkiService.createRootCA(request.getCommonName());
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/intermediate-ca")
    public ResponseEntity<CertificateEntity> createIntermediateCA(
            @RequestBody CreateIntermediateCARequest request) {
        try {
            CertificateEntity cert = pkiService.createIntermediateCA(
                    request.getCommonName(), request.getRootCASerial());
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/end-entity")
    public ResponseEntity<CertificateEntity> createEndEntity(
            @RequestBody CreateEndEntityRequest request) {
        try {
            CertificateEntity cert = pkiService.createEndEntityCertificate(
                    request.getCommonName(), request.getIntermediateCASerial());
            return ResponseEntity.ok(cert);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping
    public ResponseEntity<List<CertificateEntity>> getAllCertificates() {
        return ResponseEntity.ok(pkiService.getAllCertificates());
    }

    @GetMapping("/{serial}")
    public ResponseEntity<CertificateEntity> getCertificate(@PathVariable String serial) {
        try {
            return ResponseEntity.ok(pkiService.getCertificateBySerial(serial));
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/{serial}/verify")
    public ResponseEntity<VerificationResponse> verifyCertificate(@PathVariable String serial) {
        try {
            boolean valid = pkiService.verifyCertificate(serial);
            return ResponseEntity.ok(new VerificationResponse(valid));
        } catch (Exception e) {
            return ResponseEntity.ok(new VerificationResponse(false));
        }
    }

    @PostMapping("/{serial}/revoke")
    public ResponseEntity<Void> revokeCertificate(@PathVariable String serial) {
        try {
            pkiService.revokeCertificate(serial);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // DTOs
    @Data
    public static class CreateRootCARequest {
        private String commonName;
    }

    @Data
    public static class CreateIntermediateCARequest {
        private String commonName;
        private String rootCASerial;
    }

    @Data
    public static class CreateEndEntityRequest {
        private String commonName;
        private String intermediateCASerial;
    }

    @Data
    public static class VerificationResponse {
        private boolean valid;

        public VerificationResponse(boolean valid) {
            this.valid = valid;
        }
    }
}