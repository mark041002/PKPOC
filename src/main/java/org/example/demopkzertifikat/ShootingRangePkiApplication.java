package org.example.demopkzertifikat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

@SpringBootApplication
public class ShootingRangePkiApplication {

    static {
        // Bouncy Castle Provider registrieren
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(ShootingRangePkiApplication.class, args);
    }
}