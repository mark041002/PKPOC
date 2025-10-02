9. Postman Collection - API Aufrufe
   
9.1 Root CA erstellen
POST http://localhost:8080/api/certificates/root-ca
{
"commonName": "Schießstand Root CA"
}

9.2 Intermediate CA erstellen (Schießstand)
POST http://localhost:8080/api/certificates/intermediate-ca
{
"commonName": "Schießstand München",
"rootCASerial": "SERIAL_VON_ROOT_CA"
}

9.3 Aufseher-Zertifikat erstellen
POST http://localhost:8080/api/certificates/end-entity
{
"commonName": "Max Mustermann - Aufseher",
"intermediateCASerial": "SERIAL_VON_INTERMEDIATE_CA"
}

9.4 Alle Zertifikate anzeigen
GET http://localhost:8080/api/certificates

9.5 Zertifikat verifizieren
POST http://localhost:8080/api/certificates/{serial}/verify

9.6 Schießbuch-Eintrag erstellen
POST http://localhost:8080/api/shooting-logs
{
"shooterName": "Hans Schmidt",
"weaponType": "Pistole 9mm",
"shotsCount": 50,
"supervisorCertSerial": "SERIAL_VON_AUFSEHER",
"notes": "Training absolviert"
}

9.7 Alle Einträge anzeigen
GET http://localhost:8080/api/shooting-logs

9.8 Eintrag verifizieren
POST http://localhost:8080/api/shooting-logs/{entryId}/verify

9.9 Zertifikat widerrufen
POST http://localhost:8080/api/certificates/{serial}/revoke

test