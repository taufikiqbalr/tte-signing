package id.taufikiqbal.tte.pki;

import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class CertificateRepository {

    public record CertificateRecord(
            String serialHex,
            String subjectDn,
            byte[] certificateDer,
            Instant notBefore,
            Instant notAfter,
            String status,
            Instant revocationTime,
            Integer revocationReason) {

        public X509Certificate certificate() {
            try {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(certificateDer));
            } catch (Exception e) {
                throw new IllegalStateException("Stored certificate is not valid X.509", e);
            }
        }

        public BigInteger serialNumber() {
            return new BigInteger(serialHex, 16);
        }
    }

    private final JdbcTemplate jdbcTemplate;

    public CertificateRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void save(X509Certificate certificate) {
        try {
            jdbcTemplate.update("""
                    INSERT INTO issued_certificate
                        (serial_hex, subject_dn, certificate_der, not_before, not_after, status)
                    VALUES (?, ?, ?, ?, ?, 'GOOD')
                    """,
                    certificate.getSerialNumber().toString(16).toUpperCase(),
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getEncoded(),
                    Timestamp.from(certificate.getNotBefore().toInstant()),
                    Timestamp.from(certificate.getNotAfter().toInstant()));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to persist issued certificate", e);
        }
    }

    public void saveIfAbsent(X509Certificate certificate) {
        try {
            jdbcTemplate.update("""
                    INSERT INTO issued_certificate
                        (serial_hex, subject_dn, certificate_der, not_before, not_after, status)
                    VALUES (?, ?, ?, ?, ?, 'GOOD')
                    ON CONFLICT (serial_hex) DO NOTHING
                    """,
                    certificate.getSerialNumber().toString(16).toUpperCase(),
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getEncoded(),
                    Timestamp.from(certificate.getNotBefore().toInstant()),
                    Timestamp.from(certificate.getNotAfter().toInstant()));
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to register PKI service certificate", e);
        }
    }

    public Optional<CertificateRecord> findBySerial(BigInteger serial) {
        List<CertificateRecord> records = jdbcTemplate.query("""
                        SELECT serial_hex, subject_dn, certificate_der, not_before, not_after,
                               status, revocation_time, revocation_reason
                        FROM issued_certificate
                        WHERE UPPER(serial_hex) = UPPER(?)
                        """,
                (rs, rowNum) -> new CertificateRecord(
                        rs.getString("serial_hex"),
                        rs.getString("subject_dn"),
                        rs.getBytes("certificate_der"),
                        rs.getTimestamp("not_before").toInstant(),
                        rs.getTimestamp("not_after").toInstant(),
                        rs.getString("status"),
                        rs.getTimestamp("revocation_time") == null
                                ? null : rs.getTimestamp("revocation_time").toInstant(),
                        (Integer) rs.getObject("revocation_reason")),
                serial.toString(16));
        return records.stream().findFirst();
    }

    public Optional<CertificateRecord> findBySerialHex(String serialHex) {
        try {
            return findBySerial(new BigInteger(serialHex, 16));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    public void revoke(String serialHex, int reason) {
        int updated = jdbcTemplate.update("""
                UPDATE issued_certificate
                SET status = 'REVOKED',
                    revocation_time = CURRENT_TIMESTAMP,
                    revocation_reason = ?
                WHERE UPPER(serial_hex) = UPPER(?)
                  AND status = 'GOOD'
                """, reason, serialHex);

        if (updated == 0 && findBySerialHex(serialHex).isEmpty()) {
            throw new IllegalArgumentException("Certificate serial not found");
        }
    }

    public List<CertificateRecord> findRevoked() {
        return jdbcTemplate.query("""
                        SELECT serial_hex, subject_dn, certificate_der, not_before, not_after,
                               status, revocation_time, revocation_reason
                        FROM issued_certificate
                        WHERE status = 'REVOKED'
                        ORDER BY revocation_time
                        """,
                (rs, rowNum) -> new CertificateRecord(
                        rs.getString("serial_hex"),
                        rs.getString("subject_dn"),
                        rs.getBytes("certificate_der"),
                        rs.getTimestamp("not_before").toInstant(),
                        rs.getTimestamp("not_after").toInstant(),
                        rs.getString("status"),
                        rs.getTimestamp("revocation_time").toInstant(),
                        (Integer) rs.getObject("revocation_reason")));
    }

    public BigInteger nextTsaSerial() {
        Long value = jdbcTemplate.queryForObject(
                "SELECT nextval('tsa_serial_seq')", Long.class);
        if (value == null) {
            throw new IllegalStateException("Unable to allocate TSA serial");
        }
        return BigInteger.valueOf(value);
    }
}
